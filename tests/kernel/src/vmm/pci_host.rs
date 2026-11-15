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

//! Ring-0 physical PCI passthrough backend (`PciHostManager`) and zero-hop
//! physical MSI-X -> guest vLAPIC interrupt routing (`IDT 80..=111`).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use vmm_core::host::abi::MAX_PASSTHROUGH_DEVS;
use vmm_core::host::{HvError, HvResult, MemObjId, PciBarInfo, PciBarKind, PciDevId};

use crate::arch::irq::{IRQ_VMM_END, IRQ_VMM_START};
use crate::mm::mmio::{mmio_map_region, MmioMapping};
use crate::util::SpinLock;

use super::host_impl::MotorHvCore;
use super::pci_cfg::{
    host_pio_read, host_pio_write, is_bdf_passthrough, pci_cfg_read16, pci_cfg_read32,
    pci_cfg_read8, pci_cfg_write16, pci_cfg_write32, pci_cfg_write8, probe_mmio_bar, probe_pio_bar,
};
use super::stage2::Stage2Mmu;

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_IOMMU_PCI_DEV_ID: u16 = 0x1057;

const PCI_CAP_ID_VENDOR: u8 = 0x09;
const PCI_CAP_ID_EXP: u8 = 0x10;
const PCI_CAP_ID_MSIX: u8 = 0x11;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const COMMON_STATUS_OFFSET: usize = 0x14;

const HOST_CMD_SAFE_IDLE: u16 = 0x0001 | 0x0002 | 0x0400; // IO | MEM | INTX_DISABLE (BUS_MASTER = 0)

const NUM_VMM_IRQS: usize = (IRQ_VMM_END - IRQ_VMM_START + 1) as usize;

/// Global Bus-0 claim bitmap preventing concurrent VMs from attaching the same BDF.
static CLAIMED_BUS0_BITMAP: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn try_claim_bdf(bdf: u16) -> bool {
    if (bdf >> 8) != 0 {
        return false;
    }
    let idx = ((bdf as usize) >> 6) & 3;
    let bit = 1u64 << (bdf & 63);
    let prev = CLAIMED_BUS0_BITMAP[idx].fetch_or(bit, Ordering::AcqRel);
    (prev & bit) == 0
}

fn unclaim_bdf(bdf: u16) {
    if (bdf >> 8) == 0 {
        let idx = ((bdf as usize) >> 6) & 3;
        let bit = 1u64 << (bdf & 63);
        CLAIMED_BUS0_BITMAP[idx].fetch_and(!bit, Ordering::AcqRel);
    }
}

struct VmmIrqRouteSlot {
    lock: AtomicU32,
    hv_ptr: AtomicUsize,
    guest_addr: AtomicU64,
    guest_data: AtomicU32,
}

impl VmmIrqRouteSlot {
    const fn new() -> Self {
        Self {
            lock: AtomicU32::new(0),
            hv_ptr: AtomicUsize::new(0),
            guest_addr: AtomicU64::new(0),
            guest_data: AtomicU32::new(0),
        }
    }

    #[inline]
    fn lock_cli_already_disabled(&self) {
        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }
}

static VMM_IRQ_ALLOC_MASK: AtomicU32 = AtomicU32::new(0);
static VMM_IRQ_ROUTES: [VmmIrqRouteSlot; NUM_VMM_IRQS] =
    [const { VmmIrqRouteSlot::new() }; NUM_VMM_IRQS];

fn alloc_vmm_host_vec() -> Option<u8> {
    loop {
        let cur = VMM_IRQ_ALLOC_MASK.load(Ordering::Acquire);
        if cur == u32::MAX {
            return None;
        }
        let bit_idx = (!cur).trailing_zeros();
        if bit_idx >= NUM_VMM_IRQS as u32 {
            return None;
        }
        let next = cur | (1u32 << bit_idx);
        if VMM_IRQ_ALLOC_MASK
            .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Some(IRQ_VMM_START + (bit_idx as u8));
        }
    }
}

fn update_vmm_irq_route(host_vec: u8, hv_ptr: usize, guest_addr: u64, guest_data: u32) {
    if !(IRQ_VMM_START..=IRQ_VMM_END).contains(&host_vec) {
        return;
    }
    let idx = (host_vec - IRQ_VMM_START) as usize;
    let slot = &VMM_IRQ_ROUTES[idx];
    x86_64::instructions::interrupts::without_interrupts(|| {
        slot.lock_cli_already_disabled();
        slot.guest_addr.store(guest_addr, Ordering::Relaxed);
        slot.guest_data.store(guest_data, Ordering::Relaxed);
        slot.hv_ptr.store(hv_ptr, Ordering::Release);
        slot.unlock();
    });
}

fn free_vmm_host_vec(host_vec: u8) {
    if !(IRQ_VMM_START..=IRQ_VMM_END).contains(&host_vec) {
        return;
    }
    let idx = (host_vec - IRQ_VMM_START) as usize;
    let slot = &VMM_IRQ_ROUTES[idx];
    x86_64::instructions::interrupts::without_interrupts(|| {
        slot.lock_cli_already_disabled();
        slot.hv_ptr.store(0, Ordering::Release);
        slot.guest_addr.store(0, Ordering::Relaxed);
        slot.guest_data.store(0, Ordering::Relaxed);
        slot.unlock();
    });
    VMM_IRQ_ALLOC_MASK.fetch_and(!(1u32 << idx), Ordering::AcqRel);
}

/// Invoked directly from `irq_handler_inner` (`IF == 0`) for vectors `80..=111`.
/// Strictly lock-free on `MotorHvCore` and allocation-free.
pub fn handle_host_msix_irq(host_vec: u8) -> bool {
    if !(IRQ_VMM_START..=IRQ_VMM_END).contains(&host_vec) {
        return false;
    }
    let idx = (host_vec - IRQ_VMM_START) as usize;
    let slot = &VMM_IRQ_ROUTES[idx];
    slot.lock_cli_already_disabled();
    let hv_ptr = slot.hv_ptr.load(Ordering::Acquire);
    let woke = if hv_ptr != 0 {
        let addr = slot.guest_addr.load(Ordering::Relaxed);
        let data = slot.guest_data.load(Ordering::Relaxed);
        unsafe { (&*(hv_ptr as *const MotorHvCore)).inject_msi_from_irq(addr, data) }
    } else {
        false
    };
    slot.unlock();
    woke
}

enum HostBarDesc {
    Empty,
    Io {
        port: u16,
        size: u64,
    },
    Mmio {
        size: u64,
        is_64: bool,
        prefetchable: bool,
        mem_obj: Option<MemObjId>,
        kmap: MmioMapping,
    },
}

struct AttachedHostPciDev {
    host_bdf: u16,
    vendor: u16,
    bars: Box<[HostBarDesc; 6]>,
    msix_cap_pos: Option<u8>,
    msix_table_bar: u8,
    msix_table_offset: usize,
    msix_entries: u16,
    msix_host_vecs: Vec<Option<u8>>,
    pcie_cap_pos: Option<u8>,
    pcie_has_flr: bool,
    virtio_common_bar_off: Option<(u8, usize)>,
}

impl AttachedHostPciDev {
    fn bar_va(&self, bar_idx: u8, offset: usize, len: usize) -> Option<usize> {
        let HostBarDesc::Mmio { size, kmap, .. } = self.bars.get(bar_idx as usize)? else {
            return None;
        };
        let end = offset.checked_add(len)?;
        if (end as u64) > *size {
            return None;
        }
        Some((kmap.virt_addr as usize) + offset)
    }

    fn mask_and_release_all_msix(&mut self) {
        if let Some(cap_pos) = self.msix_cap_pos {
            let ctrl = pci_cfg_read16(self.host_bdf, cap_pos + 2);
            // Clear Enable (bit 15) and Function Mask (bit 14).
            pci_cfg_write16(self.host_bdf, cap_pos + 2, ctrl & 0x3fff);

            for idx in 0..(self.msix_entries as usize) {
                let entry_off = self.msix_table_offset + idx * 16;
                if let Some(va) = self.bar_va(self.msix_table_bar, entry_off, 16) {
                    unsafe {
                        core::ptr::write_volatile((va + 12) as *mut u32, 1u32);
                    }
                }
            }
        }
        for slot in self.msix_host_vecs.iter_mut() {
            if let Some(vec) = slot.take() {
                free_vmm_host_vec(vec);
            }
        }
    }

    fn reset_hardware(&mut self) {
        // 1. Immediately disable physical BUS_MASTER while keeping INTX_DISABLE set.
        let cur_cmd = pci_cfg_read16(self.host_bdf, 0x04);
        pci_cfg_write16(self.host_bdf, 0x04, (cur_cmd & !0x0004) | 0x0400);

        // 2. Mask all physical MSI-X vectors and release L1 IDT routes.
        self.mask_and_release_all_msix();

        // 3. Issue PCIe Function-Level Reset (FLR) when advertised.
        if self.pcie_has_flr {
            if let Some(exp_pos) = self.pcie_cap_pos {
                let devctl = pci_cfg_read16(self.host_bdf, exp_pos + 0x08);
                pci_cfg_write16(self.host_bdf, exp_pos + 0x08, devctl | (1 << 15));
                for _ in 0..100_000 {
                    let devsts = pci_cfg_read16(self.host_bdf, exp_pos + 0x0a);
                    if (devsts & (1 << 5)) == 0 {
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
        }

        // 4. Restore MEM | IO | INTX_DISABLE (with BUS_MASTER = 0) so MMIO BARs decode.
        pci_cfg_write16(self.host_bdf, 0x04, HOST_CMD_SAFE_IDLE);

        // 5. For VirtIO PCI endpoints, explicitly write `device_status = 0` and poll until `0`
        //    so L0 (`wasm-vmm` or `cloud-hypervisor-static`) resets all virtqueues cleanly.
        if self.vendor == VIRTIO_VENDOR_ID {
            if let Some((c_bar, c_off)) = self.virtio_common_bar_off {
                if let Some(status_va) = self.bar_va(c_bar, c_off + COMMON_STATUS_OFFSET, 1) {
                    unsafe {
                        core::ptr::write_volatile(status_va as *mut u8, 0u8);
                        for _ in 0..100_000 {
                            if core::ptr::read_volatile(status_va as *const u8) == 0 {
                                break;
                            }
                            core::hint::spin_loop();
                        }
                    }
                }
            }
        }
    }
}

pub struct PciHostManager {
    self_hv: AtomicUsize,
    devs: SpinLock<Vec<Option<AttachedHostPciDev>>>,
}

impl Default for PciHostManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PciHostManager {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(MAX_PASSTHROUGH_DEVS);
        slots.resize_with(MAX_PASSTHROUGH_DEVS, || None);
        Self {
            self_hv: AtomicUsize::new(0),
            devs: SpinLock::new(slots),
        }
    }

    pub fn set_self_hv(&self, hv: &MotorHvCore) {
        self.self_hv
            .store(hv as *const MotorHvCore as usize, Ordering::Release);
    }

    pub fn attach(&self, stage2: &Stage2Mmu, host_bdf: u16) -> HvResult<PciDevId> {
        if (host_bdf >> 8) != 0 || host_bdf == 0 || !is_bdf_passthrough(host_bdf) {
            log::error!(
                "vmm::pci_host: rejected attach of unauthorized BDF {host_bdf:#06x} (missing from pci_passthrough=)"
            );
            return Err(HvError::InvalidParam);
        }

        let id_dword = pci_cfg_read32(host_bdf, 0x00);
        let vendor = (id_dword & 0xffff) as u16;
        let device = (id_dword >> 16) as u16;
        if vendor == 0 || vendor == 0xffff {
            return Err(HvError::InvalidParam);
        }
        if vendor == VIRTIO_VENDOR_ID && device == VIRTIO_IOMMU_PCI_DEV_ID {
            return Err(HvError::InvalidParam);
        }

        if !try_claim_bdf(host_bdf) {
            log::error!("vmm::pci_host: BDF {host_bdf:#06x} is already claimed by an active VM");
            return Err(HvError::InvalidParam);
        }

        // Fail closed if no active IOMMU is available to isolate DMA.
        if let Err(e) = stage2.attach_iommu_endpoint(host_bdf) {
            unclaim_bdf(host_bdf);
            return Err(e);
        }

        let res = self.attach_inner(stage2, host_bdf, vendor, device);
        if res.is_err() {
            stage2.detach_iommu_endpoint(host_bdf);
            unclaim_bdf(host_bdf);
        }
        res
    }

    fn attach_inner(
        &self,
        stage2: &Stage2Mmu,
        host_bdf: u16,
        vendor: u16,
        device: u16,
    ) -> HvResult<PciDevId> {
        let mut bars: Box<[HostBarDesc; 6]> = Box::new([const { HostBarDesc::Empty }; 6]);
        let mut bar_idx = 0u8;
        while bar_idx < 6 {
            if let Some((phys_addr, size, is_64, prefetchable)) = probe_mmio_bar(host_bdf, bar_idx)
            {
                let kmap = match mmio_map_region(phys_addr, size) {
                    Ok(m) => m,
                    Err(_) => {
                        Self::cleanup_bar_objs(stage2, &bars);
                        return Err(HvError::NoMemory);
                    }
                };
                let mem_obj = if (phys_addr & 0xfff) == 0 && (size & 0xfff) == 0 && size >= 4096 {
                    match stage2.register_pci_bar_obj(phys_addr, size) {
                        Ok(id) => Some(id),
                        Err(e) => {
                            Self::cleanup_bar_objs(stage2, &bars);
                            return Err(e);
                        }
                    }
                } else {
                    None
                };
                bars[bar_idx as usize] = HostBarDesc::Mmio {
                    size,
                    is_64,
                    prefetchable,
                    mem_obj,
                    kmap,
                };
                bar_idx += if is_64 { 2 } else { 1 };
            } else if let Some((port, size)) = probe_pio_bar(host_bdf, bar_idx) {
                bars[bar_idx as usize] = HostBarDesc::Io { port, size };
                bar_idx += 1;
            } else {
                bar_idx += 1;
            }
        }

        let mut msix_cap_pos = None;
        let mut msix_table_bar = 0u8;
        let mut msix_table_offset = 0usize;
        let mut msix_entries = 0u16;
        let mut pcie_cap_pos = None;
        let mut pcie_has_flr = false;
        let mut virtio_common_bar_off = None;

        let status = pci_cfg_read16(host_bdf, 0x06);
        if (status & 0x0010) != 0 {
            let mut pos = pci_cfg_read8(host_bdf, 0x34) & !0x3;
            let mut visited = 0u64;
            for _ in 0..48 {
                if pos < 0x40 {
                    break;
                }
                let bit = ((pos - 0x40) >> 2) as u32;
                if bit < 64 {
                    if (visited & (1u64 << bit)) != 0 {
                        break;
                    }
                    visited |= 1u64 << bit;
                }
                let hdr = pci_cfg_read16(host_bdf, pos);
                let cap_id = (hdr & 0xff) as u8;
                let next = ((hdr >> 8) as u8) & !0x3;

                if cap_id == PCI_CAP_ID_MSIX && msix_cap_pos.is_none() {
                    let ctrl = pci_cfg_read16(host_bdf, pos + 2);
                    let tbl = pci_cfg_read32(host_bdf, pos + 4);
                    msix_cap_pos = Some(pos);
                    msix_entries = (ctrl & 0x07ff) + 1;
                    msix_table_bar = (tbl & 0x7) as u8;
                    msix_table_offset = (tbl & !0x7) as usize;
                } else if cap_id == PCI_CAP_ID_EXP && pcie_cap_pos.is_none() {
                    let devcap = pci_cfg_read32(host_bdf, pos + 4);
                    pcie_cap_pos = Some(pos);
                    pcie_has_flr = (devcap & (1 << 28)) != 0;
                } else if cap_id == PCI_CAP_ID_VENDOR
                    && vendor == VIRTIO_VENDOR_ID
                    && virtio_common_bar_off.is_none()
                {
                    let cap_len = pci_cfg_read8(host_bdf, pos + 2);
                    let cfg_type = pci_cfg_read8(host_bdf, pos + 3);
                    if cfg_type == VIRTIO_PCI_CAP_COMMON_CFG && cap_len >= 16 {
                        let c_bar = pci_cfg_read8(host_bdf, pos + 4);
                        let c_off = pci_cfg_read32(host_bdf, pos + 8) as usize;
                        virtio_common_bar_off = Some((c_bar, c_off));
                    }
                }

                pos = next;
            }
        }

        let mut attached = AttachedHostPciDev {
            host_bdf,
            vendor,
            bars,
            msix_cap_pos,
            msix_table_bar,
            msix_table_offset,
            msix_entries,
            msix_host_vecs: vec![None; msix_entries as usize],
            pcie_cap_pos,
            pcie_has_flr,
            virtio_common_bar_off,
        };

        attached.reset_hardware();

        let mut devs = self.devs.lock(line!());
        let Some(slot_id) = devs.iter().position(Option::is_none) else {
            attached.mask_and_release_all_msix();
            Self::cleanup_bar_objs(stage2, &attached.bars);
            return Err(HvError::NoMemory);
        };
        devs[slot_id] = Some(attached);
        log::info!(
            "vmm::pci_host: attached {:02x}:{:02x}.{} ({vendor:#06x}:{device:#06x}) -> PciDevId({slot_id}), msix_vecs={msix_entries}",
            host_bdf >> 8,
            (host_bdf >> 3) & 0x1f,
            host_bdf & 0x7
        );
        Ok(slot_id as PciDevId)
    }

    fn cleanup_bar_objs(stage2: &Stage2Mmu, bars: &[HostBarDesc; 6]) {
        for b in bars {
            if let HostBarDesc::Mmio {
                mem_obj: Some(obj), ..
            } = b
            {
                stage2.unregister_pci_bar_obj(*obj);
            }
        }
    }

    fn finalize_detached(stage2: &Stage2Mmu, mut dev: AttachedHostPciDev) {
        dev.reset_hardware();
        Self::cleanup_bar_objs(stage2, &dev.bars);
        stage2.detach_iommu_endpoint(dev.host_bdf);
        let bdf = dev.host_bdf;
        drop(dev);
        unclaim_bdf(bdf);
    }

    pub fn detach(&self, stage2: &Stage2Mmu, dev_id: PciDevId) -> HvResult<()> {
        let idx = dev_id as usize;
        if idx >= MAX_PASSTHROUGH_DEVS {
            return Err(HvError::InvalidParam);
        }
        let dev = {
            let mut devs = self.devs.lock(line!());
            devs[idx].take().ok_or(HvError::InvalidParam)?
        };
        Self::finalize_detached(stage2, dev);
        Ok(())
    }

    pub fn teardown_all(&self, stage2: &Stage2Mmu) {
        let mut taken = Vec::with_capacity(MAX_PASSTHROUGH_DEVS);
        {
            let mut devs = self.devs.lock(line!());
            for slot in devs.iter_mut() {
                if let Some(d) = slot.take() {
                    taken.push(d);
                }
            }
        }
        for dev in taken {
            Self::finalize_detached(stage2, dev);
        }
    }

    pub fn reset(&self, dev_id: PciDevId) -> HvResult<()> {
        let idx = dev_id as usize;
        let mut devs = self.devs.lock(line!());
        let dev = devs
            .get_mut(idx)
            .and_then(Option::as_mut)
            .ok_or(HvError::InvalidParam)?;
        dev.reset_hardware();
        Ok(())
    }

    pub fn read_config(&self, dev_id: PciDevId, offset: u16, size: u8) -> HvResult<u32> {
        if offset >= 256 || (offset as u32 + size as u32) > 256 {
            return Err(HvError::InvalidParam);
        }
        let host_bdf = {
            let devs = self.devs.lock(line!());
            devs.get(dev_id as usize)
                .and_then(Option::as_ref)
                .ok_or(HvError::InvalidParam)?
                .host_bdf
        };
        let off = offset as u8;
        match size {
            1 => Ok(pci_cfg_read8(host_bdf, off) as u32),
            2 if (off & 1) == 0 => Ok(pci_cfg_read16(host_bdf, off) as u32),
            4 if (off & 3) == 0 => Ok(pci_cfg_read32(host_bdf, off)),
            _ => Err(HvError::InvalidParam),
        }
    }

    pub fn write_config(&self, dev_id: PciDevId, offset: u16, size: u8, val: u32) -> HvResult<()> {
        if offset >= 256 || (offset as u32 + size as u32) > 256 {
            return Err(HvError::InvalidParam);
        }
        let host_bdf = {
            let devs = self.devs.lock(line!());
            devs.get(dev_id as usize)
                .and_then(Option::as_ref)
                .ok_or(HvError::InvalidParam)?
                .host_bdf
        };
        let off = offset as u8;
        // Never allow writes to relocate physical BARs (0x10..=0x27) or clear INTX_DISABLE/MEM/IO.
        if (0x10..=0x27).contains(&off) {
            return Err(HvError::InvalidParam);
        }
        match size {
            1 => pci_cfg_write8(host_bdf, off, val as u8),
            2 if (off & 1) == 0 => {
                let v = if off == 0x04 {
                    ((val as u16) & 0x0004) | HOST_CMD_SAFE_IDLE
                } else {
                    val as u16
                };
                pci_cfg_write16(host_bdf, off, v);
            }
            4 if (off & 3) == 0 => pci_cfg_write32(host_bdf, off, val),
            _ => return Err(HvError::InvalidParam),
        }
        Ok(())
    }

    pub fn bar_info(&self, dev_id: PciDevId, bar_idx: u8) -> HvResult<PciBarInfo> {
        if bar_idx >= 6 {
            return Err(HvError::InvalidParam);
        }
        let devs = self.devs.lock(line!());
        let dev = devs
            .get(dev_id as usize)
            .and_then(Option::as_ref)
            .ok_or(HvError::InvalidParam)?;
        let info = match &dev.bars[bar_idx as usize] {
            HostBarDesc::Empty => PciBarInfo::default(),
            HostBarDesc::Io { size, .. } => PciBarInfo {
                kind: PciBarKind::Io,
                prefetchable: false,
                size: *size,
                mem_obj: None,
            },
            HostBarDesc::Mmio {
                size,
                is_64,
                prefetchable,
                mem_obj,
                ..
            } => PciBarInfo {
                kind: if *is_64 {
                    PciBarKind::Mem64
                } else {
                    PciBarKind::Mem32
                },
                prefetchable: *prefetchable,
                size: *size,
                mem_obj: *mem_obj,
            },
        };
        Ok(info)
    }

    pub fn bar_io(
        &self,
        dev_id: PciDevId,
        bar_idx: u8,
        offset: u64,
        size: u8,
        write: Option<u64>,
    ) -> HvResult<u64> {
        if bar_idx >= 6 {
            return Err(HvError::InvalidParam);
        }
        let devs = self.devs.lock(line!());
        let dev = devs
            .get(dev_id as usize)
            .and_then(Option::as_ref)
            .ok_or(HvError::InvalidParam)?;
        match &dev.bars[bar_idx as usize] {
            HostBarDesc::Empty => Err(HvError::InvalidParam),
            HostBarDesc::Io { port, size: bsize } => {
                let end = offset.checked_add(size as u64).ok_or(HvError::InvalidParam)?;
                if end > *bsize {
                    return Err(HvError::InvalidParam);
                }
                let p = port.checked_add(offset as u16).ok_or(HvError::InvalidParam)?;
                if let Some(val) = write {
                    if !host_pio_write(p, size, val) {
                        return Err(HvError::InvalidParam);
                    }
                    Ok(0)
                } else {
                    host_pio_read(p, size).ok_or(HvError::InvalidParam)
                }
            }
            HostBarDesc::Mmio { .. } => {
                let va = dev
                    .bar_va(bar_idx, offset as usize, size as usize)
                    .ok_or(HvError::InvalidParam)?;
                unsafe {
                    if let Some(val) = write {
                        match size {
                            1 => core::ptr::write_volatile(va as *mut u8, val as u8),
                            2 => core::ptr::write_volatile(va as *mut u16, val as u16),
                            4 => core::ptr::write_volatile(va as *mut u32, val as u32),
                            8 => core::ptr::write_volatile(va as *mut u64, val),
                            _ => return Err(HvError::InvalidParam),
                        }
                        Ok(0)
                    } else {
                        let out = match size {
                            1 => core::ptr::read_volatile(va as *const u8) as u64,
                            2 => core::ptr::read_volatile(va as *const u16) as u64,
                            4 => core::ptr::read_volatile(va as *const u32) as u64,
                            8 => core::ptr::read_volatile(va as *const u64),
                            _ => return Err(HvError::InvalidParam),
                        };
                        Ok(out)
                    }
                }
            }
        }
    }

    pub fn configure_msix(
        &self,
        dev_id: PciDevId,
        entry_idx: u16,
        guest_msi: Option<(u64, u32)>,
    ) -> HvResult<()> {
        let hv_ptr = self.self_hv.load(Ordering::Acquire);
        if hv_ptr == 0 {
            return Err(HvError::InvalidParam);
        }
        let mut devs = self.devs.lock(line!());
        let dev = devs
            .get_mut(dev_id as usize)
            .and_then(Option::as_mut)
            .ok_or(HvError::InvalidParam)?;
        let Some(cap_pos) = dev.msix_cap_pos else {
            return Err(HvError::Unsupported);
        };
        let idx = entry_idx as usize;
        if idx >= (dev.msix_entries as usize) {
            return Err(HvError::InvalidParam);
        }
        let entry_off = dev.msix_table_offset + idx * 16;
        let entry_va = dev
            .bar_va(dev.msix_table_bar, entry_off, 16)
            .ok_or(HvError::HardwareFault)?;

        match guest_msi {
            Some((guest_addr, guest_data)) => {
                let host_vec = match dev.msix_host_vecs[idx] {
                    Some(v) => v,
                    None => {
                        let v = alloc_vmm_host_vec().ok_or(HvError::NoMemory)?;
                        dev.msix_host_vecs[idx] = Some(v);
                        v
                    }
                };
                update_vmm_irq_route(host_vec, hv_ptr, guest_addr, guest_data);

                let bsp_apic_id = (crate::arch::bsp() as u32) & 0xff;
                let phys_msi_addr_lo = 0xfee0_0000u32 | (bsp_apic_id << 12);
                let phys_msi_data = host_vec as u32;

                unsafe {
                    // Mask entry before modifying address/data, then unmask.
                    core::ptr::write_volatile((entry_va + 12) as *mut u32, 1u32);
                    core::ptr::write_volatile(entry_va as *mut u32, phys_msi_addr_lo);
                    core::ptr::write_volatile((entry_va + 4) as *mut u32, 0u32);
                    core::ptr::write_volatile((entry_va + 8) as *mut u32, phys_msi_data);
                    core::ptr::write_volatile((entry_va + 12) as *mut u32, 0u32);
                }

                // Ensure physical MsixMsgCtrl has Enable = 1 (bit 15) and FunctionMask = 0 (bit 14).
                let ctrl = pci_cfg_read16(dev.host_bdf, cap_pos + 2);
                if (ctrl & 0xc000) != 0x8000 {
                    pci_cfg_write16(dev.host_bdf, cap_pos + 2, (ctrl & !0x4000) | 0x8000);
                }
            }
            None => {
                unsafe {
                    core::ptr::write_volatile((entry_va + 12) as *mut u32, 1u32);
                }
                if let Some(host_vec) = dev.msix_host_vecs[idx].take() {
                    free_vmm_host_vec(host_vec);
                }
                if dev.msix_host_vecs.iter().all(Option::is_none) {
                    let ctrl = pci_cfg_read16(dev.host_bdf, cap_pos + 2);
                    if (ctrl & 0x8000) != 0 {
                        pci_cfg_write16(dev.host_bdf, cap_pos + 2, ctrl & !0xc000);
                    }
                }
            }
        }
        Ok(())
    }
}
