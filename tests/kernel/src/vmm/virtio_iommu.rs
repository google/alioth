// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Minimal `#![no_std]`, integer-only Ring-0 OASIS VirtIO v1.2 `virtio-iommu`
//! driver (`0x1af4:0x1057`).
//!
//! Initializes prior to PID-2 userspace startup:
//! - Hides its own PCI BDF from Ring-3 `sys-io`.
//! - Enforces default-deny (`bypass = 0`).
//! - Isolates every `pci_passthrough=` BDF in an empty `BLOCKING_DOMAIN`.
//! - Maps L1's PVH RAM segments into `L1_SYSTEM_DOMAIN` for L1-owned devices so
//!   unmodified stock `sys-io` runs behind segment-wide `virtio-iommu` in both
//!   `wasm-vmm` (`iommu = true`) and `cloud-hypervisor-static` (`iommu=virtio`).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{fence, AtomicU32, Ordering};

use vmm_core::host::{HvError, HvResult, MemProt};

use crate::mm::mmio::{mmio_map_region, MmioMapping};
use crate::mm::phys::{phys_allocate_frameless, raw_ram_segments};
use crate::mm::{align_down, align_up, AllocationClass, PageType, PAGE_SIZE_SMALL, PAGING_DIRECT_MAP_OFFSET};
use crate::util::SpinLock;

use super::iommu::{register_system_iommu, IommuProvider};
use super::pci_cfg::{
    hide_bdf_from_userspace, is_bdf_passthrough, pci_cfg_read16, pci_cfg_read32, pci_cfg_read8,
    pci_cfg_write16, probe_mmio_bar,
};

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_IOMMU_PCI_DEV_ID: u16 = 0x1057; // 0x1040 + 23

const PCI_CAP_VENDOR: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_IOMMU_F_INPUT_RANGE: u64 = 1 << 0;
const VIRTIO_IOMMU_F_DOMAIN_RANGE: u64 = 1 << 1;
const VIRTIO_IOMMU_F_MAP_UNMAP: u64 = 1 << 2;
const VIRTIO_IOMMU_F_BYPASS_CONFIG: u64 = 1 << 6;

const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
const VIRTIO_IOMMU_T_DETACH: u8 = 2;
const VIRTIO_IOMMU_T_MAP: u8 = 3;
const VIRTIO_IOMMU_T_UNMAP: u8 = 4;

const VIRTIO_IOMMU_S_OK: u8 = 0;
const VIRTIO_IOMMU_S_NOENT: u8 = 6;

const VIRTIO_IOMMU_MAP_F_READ: u32 = 1 << 0;
const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 1 << 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

// VirtIO CommonCfg register offsets
const COMMON_DFSELECT: usize = 0x00;
const COMMON_DF: usize = 0x04;
const COMMON_GFSELECT: usize = 0x08;
const COMMON_GF: usize = 0x0c;
const COMMON_MSIX_CFG: usize = 0x10;
const COMMON_NUMQ: usize = 0x12;
const COMMON_STATUS: usize = 0x14;
const COMMON_Q_SELECT: usize = 0x16;
const COMMON_Q_SIZE: usize = 0x18;
const COMMON_Q_MSIX: usize = 0x1a;
const COMMON_Q_ENABLE: usize = 0x1c;
const COMMON_Q_NOTIFY_OFF: usize = 0x1e;
const COMMON_Q_DESCLO: usize = 0x20;
const COMMON_Q_DESCHI: usize = 0x24;
const COMMON_Q_AVAILLO: usize = 0x28;
const COMMON_Q_AVAILHI: usize = 0x2c;
const COMMON_Q_USEDLO: usize = 0x30;
const COMMON_Q_USEDHI: usize = 0x34;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ReqAttachDetach {
    type_: u8,
    reserved0: [u8; 3],
    domain: u32,
    endpoint: u32,
    reserved1: [u8; 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ReqMap {
    type_: u8,
    reserved0: [u8; 3],
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    phys_start: u64,
    flags: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ReqUnmap {
    type_: u8,
    reserved0: [u8; 3],
    domain: u32,
    virt_start: u64,
    virt_end: u64,
}

#[derive(Clone, Copy)]
struct CapRegion {
    bar: u8,
    offset: u32,
    length: u32,
    notify_multiplier: u32,
}

struct RequestQueueState {
    notify_va: usize,
    q_size: u16,
    ring_va: usize,
    req_pa: u64,
    req_va: usize,
    avail_idx: u16,
    last_used_idx: u16,
    endpoint_domains: BTreeMap<u16, u32>,
    free_domains: Vec<u32>,
    _bar_mappings: Vec<(u8, MmioMapping)>,
}

pub struct VirtioIommuDriver {
    bdf: u16,
    blocking_domain: u32,
    domain_range_end: u32,
    next_domain: AtomicU32,
    state: SpinLock<RequestQueueState>,
}

const AVAIL_OFFSET: usize = 0x200;
const USED_OFFSET: usize = 0x800;
const TAIL_OFFSET: usize = 0x100;

#[inline]
unsafe fn mmio_r8(va: usize) -> u8 {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    let v = unsafe { core::ptr::read_volatile(va as *const u8) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn mmio_w8(va: usize, val: u8) {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(va as *mut u8, val) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[inline]
unsafe fn mmio_r16(va: usize) -> u16 {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    let v = unsafe { core::ptr::read_volatile(va as *const u16) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn mmio_w16(va: usize, val: u16) {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(va as *mut u16, val) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[inline]
unsafe fn mmio_r32(va: usize) -> u32 {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    let v = unsafe { core::ptr::read_volatile(va as *const u32) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn mmio_w32(va: usize, val: u32) {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(va as *mut u32, val) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

impl RequestQueueState {
    fn submit_sync(&mut self, req_bytes: &[u8]) -> Result<u8, HvError> {
        debug_assert!(req_bytes.len() <= TAIL_OFFSET);
        let desc0_ptr = self.ring_va as *mut VirtqDesc;
        let desc1_ptr = unsafe { desc0_ptr.add(1) };

        unsafe {
            core::ptr::copy_nonoverlapping(
                req_bytes.as_ptr(),
                self.req_va as *mut u8,
                req_bytes.len(),
            );
            core::ptr::write_bytes((self.req_va + TAIL_OFFSET) as *mut u8, 0xff, 4);

            core::ptr::write_volatile(
                desc0_ptr,
                VirtqDesc {
                    addr: self.req_pa,
                    len: req_bytes.len() as u32,
                    flags: VIRTQ_DESC_F_NEXT,
                    next: 1,
                },
            );
            core::ptr::write_volatile(
                desc1_ptr,
                VirtqDesc {
                    addr: self.req_pa + (TAIL_OFFSET as u64),
                    len: 4,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                },
            );

            let ring_slot = (self.avail_idx & (self.q_size - 1)) as usize;
            let avail_ring_entry = (self.ring_va + AVAIL_OFFSET + 4 + ring_slot * 2) as *mut u16;
            core::ptr::write_volatile(avail_ring_entry, 0u16);
            fence(Ordering::SeqCst);

            self.avail_idx = self.avail_idx.wrapping_add(1);
            let avail_idx_ptr = (self.ring_va + AVAIL_OFFSET + 2) as *mut u16;
            core::ptr::write_volatile(avail_idx_ptr, self.avail_idx);
            fence(Ordering::SeqCst);

            // Ring doorbell for queue 0 (`writew(0, notify_va)`).
            mmio_w16(self.notify_va, 0);

            let used_idx_ptr = (self.ring_va + USED_OFFSET + 2) as *const u16;
            let target_used = self.last_used_idx.wrapping_add(1);
            let mut spins: u64 = 0;
            while core::ptr::read_volatile(used_idx_ptr) != target_used {
                spins += 1;
                if spins > 50_000_000 {
                    log::error!("virtio-iommu: requestq timed out waiting for completion");
                    return Err(HvError::HardwareFault);
                }
                core::hint::spin_loop();
            }
            fence(Ordering::SeqCst);
            self.last_used_idx = target_used;
            let status = core::ptr::read_volatile((self.req_va + TAIL_OFFSET) as *const u8);
            Ok(status)
        }
    }

    fn cmd_attach(&mut self, domain: u32, endpoint: u16) -> Result<u8, HvError> {
        let req = ReqAttachDetach {
            type_: VIRTIO_IOMMU_T_ATTACH,
            reserved0: [0; 3],
            domain,
            endpoint: endpoint as u32,
            reserved1: [0; 8],
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &req as *const ReqAttachDetach as *const u8,
                size_of::<ReqAttachDetach>(),
            )
        };
        self.submit_sync(bytes)
    }

    fn cmd_detach(&mut self, domain: u32, endpoint: u16) -> Result<u8, HvError> {
        let req = ReqAttachDetach {
            type_: VIRTIO_IOMMU_T_DETACH,
            reserved0: [0; 3],
            domain,
            endpoint: endpoint as u32,
            reserved1: [0; 8],
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &req as *const ReqAttachDetach as *const u8,
                size_of::<ReqAttachDetach>(),
            )
        };
        self.submit_sync(bytes)
    }

    fn cmd_map(
        &mut self,
        domain: u32,
        virt_start: u64,
        virt_end: u64,
        phys_start: u64,
        flags: u32,
    ) -> Result<u8, HvError> {
        let req = ReqMap {
            type_: VIRTIO_IOMMU_T_MAP,
            reserved0: [0; 3],
            domain,
            virt_start,
            virt_end,
            phys_start,
            flags,
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(&req as *const ReqMap as *const u8, size_of::<ReqMap>())
        };
        self.submit_sync(bytes)
    }

    fn cmd_unmap(&mut self, domain: u32, virt_start: u64, virt_end: u64) -> Result<u8, HvError> {
        let req = ReqUnmap {
            type_: VIRTIO_IOMMU_T_UNMAP,
            reserved0: [0; 3],
            domain,
            virt_start,
            virt_end,
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(&req as *const ReqUnmap as *const u8, size_of::<ReqUnmap>())
        };
        self.submit_sync(bytes)
    }
}

impl IommuProvider for VirtioIommuDriver {
    fn alloc_domain(&self) -> HvResult<u32> {
        {
            let mut st = self.state.lock(line!());
            if let Some(reused) = st.free_domains.pop() {
                return Ok(reused);
            }
        }
        let id = self.next_domain.fetch_add(1, Ordering::Relaxed);
        if id > self.domain_range_end {
            return Err(HvError::NoMemory);
        }
        Ok(id)
    }

    fn free_domain(&self, domain: u32) {
        if domain > self.blocking_domain + 1 {
            let mut st = self.state.lock(line!());
            st.free_domains.push(domain);
        }
    }

    fn attach_endpoint(&self, domain: u32, bdf: u16) -> HvResult<()> {
        let mut st = self.state.lock(line!());
        if let Some(&prev_dom) = st.endpoint_domains.get(&bdf) {
            if prev_dom == domain {
                return Ok(());
            }
            let detach_rc = st.cmd_detach(prev_dom, bdf)?;
            if detach_rc != VIRTIO_IOMMU_S_OK && detach_rc != VIRTIO_IOMMU_S_NOENT {
                log::error!(
                    "virtio-iommu: DETACH({prev_dom}, {bdf:#06x}) failed with status {detach_rc}"
                );
                return Err(HvError::HardwareFault);
            }
            st.endpoint_domains.remove(&bdf);
        }
        let rc = st.cmd_attach(domain, bdf)?;
        if rc != VIRTIO_IOMMU_S_OK {
            log::error!(
                "virtio-iommu: ATTACH({domain}, {bdf:#06x}) rejected with status {rc}"
            );
            return Err(HvError::Unsupported);
        }
        st.endpoint_domains.insert(bdf, domain);
        Ok(())
    }

    fn detach_to_blocked(&self, bdf: u16) -> HvResult<()> {
        self.attach_endpoint(self.blocking_domain, bdf)
    }

    fn map_dma(
        &self,
        domain: u32,
        iova: u64,
        hpa: u64,
        size: u64,
        prot: MemProt,
    ) -> HvResult<()> {
        if size == 0 || (iova & 0xfff) != 0 || (hpa & 0xfff) != 0 || (size & 0xfff) != 0 {
            return Err(HvError::InvalidParam);
        }
        let virt_end = iova.checked_add(size - 1).ok_or(HvError::InvalidParam)?;
        let mut flags = 0u32;
        if prot.contains(MemProt::READ) {
            flags |= VIRTIO_IOMMU_MAP_F_READ;
        }
        if prot.contains(MemProt::WRITE) {
            flags |= VIRTIO_IOMMU_MAP_F_WRITE;
        }
        if flags == 0 {
            return Ok(());
        }
        let mut st = self.state.lock(line!());
        let rc = st.cmd_map(domain, iova, virt_end, hpa, flags)?;
        if rc != VIRTIO_IOMMU_S_OK {
            log::error!(
                "virtio-iommu: MAP(dom={domain}, iova={iova:#x}..={virt_end:#x}, hpa={hpa:#x}) failed: {rc}"
            );
            return Err(HvError::HardwareFault);
        }
        Ok(())
    }

    fn unmap_dma(&self, domain: u32, iova: u64, size: u64) -> HvResult<()> {
        if size == 0 || (iova & 0xfff) != 0 || (size & 0xfff) != 0 {
            return Err(HvError::InvalidParam);
        }
        let virt_end = iova.checked_add(size - 1).ok_or(HvError::InvalidParam)?;
        let mut st = self.state.lock(line!());
        let rc = st.cmd_unmap(domain, iova, virt_end)?;
        if rc != VIRTIO_IOMMU_S_OK && rc != VIRTIO_IOMMU_S_NOENT {
            log::error!(
                "virtio-iommu: UNMAP(dom={domain}, iova={iova:#x}..={virt_end:#x}) failed: {rc}"
            );
            return Err(HvError::HardwareFault);
        }
        Ok(())
    }
}

fn scan_bus0_endpoints() -> Vec<(u16, u16, u16)> {
    let mut found = Vec::new();
    for slot in 0u16..32 {
        let bdf0 = slot << 3;
        let vd0 = pci_cfg_read32(bdf0, 0x00);
        let vendor0 = (vd0 & 0xffff) as u16;
        if vendor0 == 0xffff || vendor0 == 0 {
            continue;
        }
        let device0 = (vd0 >> 16) as u16;
        found.push((bdf0, vendor0, device0));

        let hdr_type = pci_cfg_read8(bdf0, 0x0e);
        if (hdr_type & 0x80) != 0 {
            for func in 1u16..8 {
                let bdf = (slot << 3) | func;
                let vd = pci_cfg_read32(bdf, 0x00);
                let vendor = (vd & 0xffff) as u16;
                if vendor != 0xffff && vendor != 0 {
                    found.push((bdf, vendor, (vd >> 16) as u16));
                }
            }
        }
    }
    found
}

fn parse_virtio_caps(bdf: u16) -> Option<(CapRegion, CapRegion, CapRegion)> {
    let status = pci_cfg_read16(bdf, 0x06);
    if (status & 0x0010) == 0 {
        return None;
    }
    let mut common = None;
    let mut notify = None;
    let mut device = None;

    let mut pos = pci_cfg_read8(bdf, 0x34) & !0x3;
    for _ in 0..48 {
        if pos < 0x40 {
            break;
        }
        let hdr = pci_cfg_read32(bdf, pos);
        let cap_id = (hdr & 0xff) as u8;
        let next = ((hdr >> 8) & 0xff) as u8 & !0x3;
        let cap_len = ((hdr >> 16) & 0xff) as u8;
        let cfg_type = ((hdr >> 24) & 0xff) as u8;

        if cap_id == PCI_CAP_VENDOR && cap_len >= 16 {
            let bar = pci_cfg_read8(bdf, pos + 4);
            let offset = pci_cfg_read32(bdf, pos + 8);
            let length = pci_cfg_read32(bdf, pos + 12);
            if bar < 6 {
                match cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => {
                        common = Some(CapRegion {
                            bar,
                            offset,
                            length,
                            notify_multiplier: 0,
                        });
                    }
                    VIRTIO_PCI_CAP_NOTIFY_CFG if cap_len >= 20 => {
                        let mult = pci_cfg_read32(bdf, pos + 16);
                        notify = Some(CapRegion {
                            bar,
                            offset,
                            length,
                            notify_multiplier: mult,
                        });
                    }
                    VIRTIO_PCI_CAP_DEVICE_CFG => {
                        device = Some(CapRegion {
                            bar,
                            offset,
                            length,
                            notify_multiplier: 0,
                        });
                    }
                    _ => {}
                }
            }
        }
        pos = next;
    }
    Some((common?, notify?, device?))
}

fn coalesced_l1_ram_ranges() -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = raw_ram_segments()
        .iter()
        .filter(|s| s.size > 0)
        .map(|s| {
            let start = align_down(s.start, PAGE_SIZE_SMALL);
            let end = align_up(s.end(), PAGE_SIZE_SMALL);
            (start, end)
        })
        .filter(|(s, e)| e > s)
        .collect();
    ranges.sort_by_key(|r| r.0);

    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

pub fn init_early() {
    let endpoints = scan_bus0_endpoints();
    let Some(&(iommu_bdf, _, _)) = endpoints
        .iter()
        .find(|&&(_, v, d)| v == VIRTIO_VENDOR_ID && d == VIRTIO_IOMMU_PCI_DEV_ID)
    else {
        log::info!("vmm::virtio_iommu: no virtio-iommu device present on PCI bus 0");
        return;
    };

    hide_bdf_from_userspace(iommu_bdf);

    let Some((common_cap, notify_cap, dev_cap)) = parse_virtio_caps(iommu_bdf) else {
        panic!("virtio-iommu at {iommu_bdf:#06x} missing required VirtIO PCI capabilities");
    };

    // Enable MEM + BUS_MASTER + INTX_DISABLE on the virtio-iommu PCI function.
    let cmd = pci_cfg_read16(iommu_bdf, 0x04);
    pci_cfg_write16(iommu_bdf, 0x04, (cmd | 0x0002 | 0x0004 | 0x0400) & !0x0001);

    let mut bar_mappings: Vec<(u8, MmioMapping)> = Vec::new();
    let mut map_bar = |bar_idx: u8| -> usize {
        if let Some((_, m)) = bar_mappings.iter().find(|(b, _)| *b == bar_idx) {
            return m.virt_addr as usize;
        }
        let (phys, size, _, _) =
            probe_mmio_bar(iommu_bdf, bar_idx).expect("failed to probe virtio-iommu BAR");
        let mapping = mmio_map_region(phys, size).expect("failed to MMIO-map virtio-iommu BAR");
        let va = mapping.virt_addr as usize;
        bar_mappings.push((bar_idx, mapping));
        va
    };

    let common_va = map_bar(common_cap.bar) + (common_cap.offset as usize);
    let notify_base_va = map_bar(notify_cap.bar) + (notify_cap.offset as usize);
    let dev_cfg_va = map_bar(dev_cap.bar) + (dev_cap.offset as usize);

    let ring_pa = phys_allocate_frameless(PageType::SmallPage, AllocationClass::Kernel)
        .expect("failed to allocate virtio-iommu ring page");
    let event_ring_pa = phys_allocate_frameless(PageType::SmallPage, AllocationClass::Kernel)
        .expect("failed to allocate virtio-iommu eventq ring page");
    let req_pa = phys_allocate_frameless(PageType::SmallPage, AllocationClass::Kernel)
        .expect("failed to allocate virtio-iommu scratch page");
    let ring_va = (PAGING_DIRECT_MAP_OFFSET + ring_pa) as usize;
    let event_ring_va = (PAGING_DIRECT_MAP_OFFSET + event_ring_pa) as usize;
    let req_va = (PAGING_DIRECT_MAP_OFFSET + req_pa) as usize;

    let (q_size, notify_va, domain_start, domain_end) = unsafe {
        core::ptr::write_bytes(ring_va as *mut u8, 0, PAGE_SIZE_SMALL as usize);
        core::ptr::write_bytes(event_ring_va as *mut u8, 0, PAGE_SIZE_SMALL as usize);
        core::ptr::write_bytes(req_va as *mut u8, 0, PAGE_SIZE_SMALL as usize);

        // 1. Reset device and poll until `device_status == 0`.
        mmio_w8(common_va + COMMON_STATUS, 0);
        while mmio_r8(common_va + COMMON_STATUS) != 0 {
            core::hint::spin_loop();
        }

        // 2. ACKNOWLEDGE | DRIVER
        mmio_w8(common_va + COMMON_STATUS, STATUS_ACKNOWLEDGE);
        mmio_w8(
            common_va + COMMON_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );

        // 3. Negotiate features
        mmio_w32(common_va + COMMON_DFSELECT, 0);
        let feat_lo = mmio_r32(common_va + COMMON_DF) as u64;
        mmio_w32(common_va + COMMON_DFSELECT, 1);
        let feat_hi = mmio_r32(common_va + COMMON_DF) as u64;
        let offered = (feat_hi << 32) | feat_lo;

        let required = VIRTIO_F_VERSION_1 | VIRTIO_IOMMU_F_MAP_UNMAP;
        assert_eq!(
            offered & required,
            required,
            "virtio-iommu missing VERSION_1 or MAP_UNMAP (offered={offered:#x})"
        );
        let wanted = required
            | (offered
                & (VIRTIO_IOMMU_F_INPUT_RANGE
                    | VIRTIO_IOMMU_F_DOMAIN_RANGE
                    | VIRTIO_IOMMU_F_BYPASS_CONFIG));

        mmio_w32(common_va + COMMON_GFSELECT, 0);
        mmio_w32(common_va + COMMON_GF, wanted as u32);
        mmio_w32(common_va + COMMON_GFSELECT, 1);
        mmio_w32(common_va + COMMON_GF, (wanted >> 32) as u32);

        mmio_w8(
            common_va + COMMON_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        let st = mmio_r8(common_va + COMMON_STATUS);
        assert_ne!(
            st & STATUS_FEATURES_OK,
            0,
            "virtio-iommu rejected negotiated features"
        );

        // Disable config MSI-X vector (polled mode).
        mmio_w16(common_va + COMMON_MSIX_CFG, 0xffff);

        // 4. Configure queue 0 (`requestq`) in polled mode (`queue_msix_vector = 0xffff`).
        mmio_w16(common_va + COMMON_Q_SELECT, 0);
        let max_q = mmio_r16(common_va + COMMON_Q_SIZE);
        assert!(max_q >= 2, "virtio-iommu requestq too small ({max_q})");
        let q_sz = max_q.min(16);
        mmio_w16(common_va + COMMON_Q_SIZE, q_sz);
        mmio_w16(common_va + COMMON_Q_MSIX, 0xffff);

        let desc_pa = ring_pa;
        let avail_pa = ring_pa + (AVAIL_OFFSET as u64);
        let used_pa = ring_pa + (USED_OFFSET as u64);

        mmio_w32(common_va + COMMON_Q_DESCLO, desc_pa as u32);
        mmio_w32(common_va + COMMON_Q_DESCHI, (desc_pa >> 32) as u32);
        mmio_w32(common_va + COMMON_Q_AVAILLO, avail_pa as u32);
        mmio_w32(common_va + COMMON_Q_AVAILHI, (avail_pa >> 32) as u32);
        mmio_w32(common_va + COMMON_Q_USEDLO, used_pa as u32);
        mmio_w32(common_va + COMMON_Q_USEDHI, (used_pa >> 32) as u32);

        // Suppress device interrupts via VIRTQ_AVAIL_F_NO_INTERRUPT (`flags = 1`).
        core::ptr::write_volatile((ring_va + AVAIL_OFFSET) as *mut u16, 1u16);

        let q_notify_off = mmio_r16(common_va + COMMON_Q_NOTIFY_OFF) as usize;
        let n_va = notify_base_va + q_notify_off * (notify_cap.notify_multiplier as usize);

        mmio_w16(common_va + COMMON_Q_ENABLE, 1);

        // Also configure and enable queue 1 (`eventq`) when present (required by VirtIO v1.2
        // §5.12.2 and enforced by Cloud Hypervisor's `min_queues == 2` check on activation).
        let num_queues = mmio_r16(common_va + COMMON_NUMQ);
        if num_queues >= 2 {
            mmio_w16(common_va + COMMON_Q_SELECT, 1);
            let max_eq = mmio_r16(common_va + COMMON_Q_SIZE);
            if max_eq >= 2 {
                let eq_sz = max_eq.min(16);
                mmio_w16(common_va + COMMON_Q_SIZE, eq_sz);
                mmio_w16(common_va + COMMON_Q_MSIX, 0xffff);

                let edesc_pa = event_ring_pa;
                let eavail_pa = event_ring_pa + (AVAIL_OFFSET as u64);
                let eused_pa = event_ring_pa + (USED_OFFSET as u64);

                mmio_w32(common_va + COMMON_Q_DESCLO, edesc_pa as u32);
                mmio_w32(common_va + COMMON_Q_DESCHI, (edesc_pa >> 32) as u32);
                mmio_w32(common_va + COMMON_Q_AVAILLO, eavail_pa as u32);
                mmio_w32(common_va + COMMON_Q_AVAILHI, (eavail_pa >> 32) as u32);
                mmio_w32(common_va + COMMON_Q_USEDLO, eused_pa as u32);
                mmio_w32(common_va + COMMON_Q_USEDHI, (eused_pa >> 32) as u32);

                core::ptr::write_volatile((event_ring_va + AVAIL_OFFSET) as *mut u16, 1u16);
                mmio_w16(common_va + COMMON_Q_ENABLE, 1);
            }
        }

        // 5. DRIVER_OK
        mmio_w8(
            common_va + COMMON_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );

        // Enforce default-deny (`bypass = 0`) if `F_BYPASS_CONFIG` was negotiated.
        if (wanted & VIRTIO_IOMMU_F_BYPASS_CONFIG) != 0 && dev_cap.length >= 37 {
            mmio_w8(dev_cfg_va + 36, 0);
        }

        let (dom_start, dom_end) =
            if (wanted & VIRTIO_IOMMU_F_DOMAIN_RANGE) != 0 && dev_cap.length >= 32 {
                let s = mmio_r32(dev_cfg_va + 24);
                let e = mmio_r32(dev_cfg_va + 28);
                (s.max(1), e)
            } else {
                (1u32, u32::MAX)
            };
        assert!(dom_end >= dom_start.saturating_add(4));

        (q_sz, n_va, dom_start, dom_end)
    };

    let blocking_domain = domain_start;
    let l1_system_domain = domain_start + 1;
    let first_vm_domain = domain_start + 2;

    let mut rq = RequestQueueState {
        notify_va,
        q_size,
        ring_va,
        req_pa,
        req_va,
        avail_idx: 0,
        last_used_idx: 0,
        endpoint_domains: BTreeMap::new(),
        free_domains: Vec::new(),
        _bar_mappings: bar_mappings,
    };

    let l1_ram = coalesced_l1_ram_ranges();
    let mut l1_system_mapped = false;

    for &(bdf, _vendor, _device) in &endpoints {
        if bdf == 0x0000 || bdf == iommu_bdf {
            continue;
        }
        if is_bdf_passthrough(bdf) {
            let rc = rq
                .cmd_attach(blocking_domain, bdf)
                .expect("virtio-iommu ATTACH(blocking_domain) transport error");
            assert_eq!(
                rc, VIRTIO_IOMMU_S_OK,
                "passthrough BDF {bdf:#06x} is not managed by virtio-iommu (status={rc})"
            );
            rq.endpoint_domains.insert(bdf, blocking_domain);
        } else {
            let rc = rq
                .cmd_attach(l1_system_domain, bdf)
                .expect("virtio-iommu ATTACH(l1_system_domain) transport error");
            if rc == VIRTIO_IOMMU_S_OK {
                rq.endpoint_domains.insert(bdf, l1_system_domain);
                if !l1_system_mapped {
                    for &(start, end) in &l1_ram {
                        let mrc = rq
                            .cmd_map(
                                l1_system_domain,
                                start,
                                end - 1,
                                start,
                                VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE,
                            )
                            .expect("virtio-iommu MAP(l1_system_domain) transport error");
                        assert_eq!(
                            mrc, VIRTIO_IOMMU_S_OK,
                            "virtio-iommu MAP(l1_system_domain, {start:#x}..{end:#x}) failed: {mrc}"
                        );
                    }
                    l1_system_mapped = true;
                }
            } else if rc != VIRTIO_IOMMU_S_NOENT {
                panic!(
                    "virtio-iommu ATTACH(l1_system_domain, {bdf:#06x}) failed with unexpected status {rc}"
                );
            }
        }
    }

    let driver = Box::leak(Box::new(VirtioIommuDriver {
        bdf: iommu_bdf,
        blocking_domain,
        domain_range_end: domain_end,
        next_domain: AtomicU32::new(first_vm_domain),
        state: SpinLock::new(rq),
    }));
    register_system_iommu(driver);

    log::info!(
        "vmm::virtio_iommu: active at {:02x}:{:02x}.{} (l1_dom={}, block_dom={}, vm_doms={}..={})",
        driver.bdf >> 8,
        (driver.bdf >> 3) & 0x1f,
        driver.bdf & 0x7,
        l1_system_domain,
        blocking_domain,
        first_vm_domain,
        domain_end
    );
}
