// SPDX-License-Identifier: GPL-2.0
// Ring-0 PCI device passthrough, Linux IOMMU domain isolation (`virtio-iommu` / AMD-Vi),
// Stage-2 UC BAR MMIO registration, and direct hardirq MSI-X -> guest vLAPIC injection.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

use vmm_core::host::abi::MAX_PASSTHROUGH_DEVS;
use vmm_core::host::{HvError, HvResult, MemProt, PciBarInfo, PciBarKind, PciDevId};

use crate::host_impl::LinuxHvCore;
use crate::kapi::{
    airlock_kapi_iommu_alloc_for_bdf, airlock_kapi_iommu_free, airlock_kapi_iommu_map,
    airlock_kapi_iommu_unmap, airlock_kapi_pci_bar_io, airlock_kapi_pci_close,
    airlock_kapi_pci_configure_msix, airlock_kapi_pci_open, airlock_kapi_pci_read_config,
    airlock_kapi_pci_reset, airlock_kapi_pci_write_config, AirlockIommuCtx, AirlockKapiBarDesc,
    AirlockPciDev, SpinLock,
};
use crate::stage2::{Stage2IommuOps, Stage2Mmu};

fn errno_to_hv(rc: i32) -> HvError {
    match rc {
        -12 | -28 => HvError::NoMemory,     // -ENOMEM, -ENOSPC
        -95 | -38 => HvError::Unsupported,  // -EOPNOTSUPP, -ENOSYS
        -5 => HvError::HardwareFault,       // -EIO
        _ => HvError::InvalidParam,
    }
}

struct LinuxIommuDomain {
    raw: *mut AirlockIommuCtx,
}

unsafe impl Send for LinuxIommuDomain {}
unsafe impl Sync for LinuxIommuDomain {}

impl LinuxIommuDomain {
    fn alloc_for_bdf(bdf: u16) -> HvResult<Arc<Self>> {
        let mut raw = null_mut();
        let rc = unsafe { airlock_kapi_iommu_alloc_for_bdf(bdf, &mut raw) };
        if rc < 0 || raw.is_null() {
            return Err(errno_to_hv(rc));
        }
        Ok(Arc::new(Self { raw }))
    }
}

impl Stage2IommuOps for LinuxIommuDomain {
    fn map_dma(&self, gpa: u64, hpa: u64, size: u64, prot: MemProt) -> HvResult<()> {
        let readable = prot.contains(MemProt::READ);
        let writable = prot.contains(MemProt::WRITE);
        let rc = unsafe { airlock_kapi_iommu_map(self.raw, gpa, hpa, size, readable, writable) };
        if rc < 0 {
            Err(errno_to_hv(rc))
        } else {
            Ok(())
        }
    }

    fn unmap_dma(&self, gpa: u64, size: u64) {
        unsafe { airlock_kapi_iommu_unmap(self.raw, gpa, size) };
    }
}

impl Drop for LinuxIommuDomain {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { airlock_kapi_iommu_free(self.raw) };
            self.raw = null_mut();
        }
    }
}

struct RawPciDevHandle {
    raw: *mut AirlockPciDev,
    // Kept alive until after `airlock_kapi_pci_close` detaches the group from `domain`.
    _iommu: Arc<LinuxIommuDomain>,
}

unsafe impl Send for RawPciDevHandle {}
unsafe impl Sync for RawPciDevHandle {}

impl Drop for RawPciDevHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { airlock_kapi_pci_close(self.raw) };
            self.raw = null_mut();
        }
    }
}

struct AttachedPciEntry {
    handle: Arc<RawPciDevHandle>,
    bars: [PciBarInfo; 6],
}

pub struct PciHostManager {
    self_hv: AtomicUsize,
    iommu: SpinLock<Option<Arc<LinuxIommuDomain>>>,
    devs: SpinLock<Vec<Option<AttachedPciEntry>>>,
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
            iommu: SpinLock::new(None),
            devs: SpinLock::new(slots),
        }
    }

    pub fn set_self_hv(&self, hv: &LinuxHvCore) {
        self.self_hv
            .store(hv as *const LinuxHvCore as usize, Ordering::Release);
    }

    fn ensure_iommu_domain(&self, stage2: &Stage2Mmu, bdf: u16) -> HvResult<Arc<LinuxIommuDomain>> {
        if let Some(existing) = self.iommu.lock().clone() {
            return Ok(existing);
        }
        let dom = LinuxIommuDomain::alloc_for_bdf(bdf)?;
        let ops: Arc<dyn Stage2IommuOps> = dom.clone();
        stage2.bind_iommu_and_replay(ops)?;
        let mut guard = self.iommu.lock();
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.clone());
        }
        *guard = Some(dom.clone());
        Ok(dom)
    }

    pub fn attach(&self, stage2: &Stage2Mmu, host_bdf: u16) -> HvResult<PciDevId> {
        let hv_ptr = self.self_hv.load(Ordering::Acquire);
        if hv_ptr == 0 || host_bdf == 0 {
            return Err(HvError::InvalidParam);
        }

        let iommu_dom = self.ensure_iommu_domain(stage2, host_bdf)?;

        let mut raw_bars = [AirlockKapiBarDesc::default(); 6];
        let mut raw_dev = null_mut();
        let rc = unsafe {
            airlock_kapi_pci_open(
                host_bdf,
                iommu_dom.raw,
                hv_ptr,
                raw_bars.as_mut_ptr(),
                &mut raw_dev,
            )
        };
        if rc < 0 || raw_dev.is_null() {
            return Err(errno_to_hv(rc));
        }

        let handle = Arc::new(RawPciDevHandle {
            raw: raw_dev,
            _iommu: iommu_dom,
        });

        let mut bars = [PciBarInfo::default(); 6];
        for i in 0..6 {
            let b = &raw_bars[i];
            match b.kind {
                1 => {
                    bars[i] = PciBarInfo {
                        kind: PciBarKind::Io,
                        prefetchable: false,
                        size: b.size,
                        mem_obj: None,
                    };
                }
                2 | 3 => {
                    let mem_obj = if (b.phys_start & 0xfff) == 0
                        && (b.size & 0xfff) == 0
                        && b.size >= 4096
                    {
                        match stage2.register_pci_bar_obj(b.phys_start, b.size) {
                            Ok(id) => Some(id),
                            Err(e) => {
                                Self::cleanup_bar_objs(stage2, &bars);
                                return Err(e);
                            }
                        }
                    } else {
                        None
                    };
                    bars[i] = PciBarInfo {
                        kind: if b.kind == 3 {
                            PciBarKind::Mem64
                        } else {
                            PciBarKind::Mem32
                        },
                        prefetchable: b.prefetchable != 0,
                        size: b.size,
                        mem_obj,
                    };
                }
                _ => {}
            }
        }

        let mut devs = self.devs.lock();
        let Some(slot_id) = devs.iter().position(Option::is_none) else {
            drop(devs);
            Self::cleanup_bar_objs(stage2, &bars);
            return Err(HvError::NoMemory);
        };
        devs[slot_id] = Some(AttachedPciEntry { handle, bars });
        Ok(slot_id as PciDevId)
    }

    fn cleanup_bar_objs(stage2: &Stage2Mmu, bars: &[PciBarInfo; 6]) {
        for b in bars {
            if let Some(obj) = b.mem_obj {
                stage2.unregister_pci_bar_obj(obj);
            }
        }
    }

    fn get_handle(&self, dev_id: PciDevId) -> HvResult<Arc<RawPciDevHandle>> {
        let devs = self.devs.lock();
        devs.get(dev_id as usize)
            .and_then(Option::as_ref)
            .map(|e| e.handle.clone())
            .ok_or(HvError::InvalidParam)
    }

    pub fn detach(&self, stage2: &Stage2Mmu, dev_id: PciDevId) -> HvResult<()> {
        let idx = dev_id as usize;
        if idx >= MAX_PASSTHROUGH_DEVS {
            return Err(HvError::InvalidParam);
        }
        let entry = {
            let mut devs = self.devs.lock();
            devs[idx].take().ok_or(HvError::InvalidParam)?
        };
        Self::cleanup_bar_objs(stage2, &entry.bars);
        drop(entry);
        Ok(())
    }

    pub fn teardown_all(&self, stage2: &Stage2Mmu) {
        let mut taken = Vec::with_capacity(MAX_PASSTHROUGH_DEVS);
        {
            let mut devs = self.devs.lock();
            for slot in devs.iter_mut() {
                if let Some(e) = slot.take() {
                    taken.push(e);
                }
            }
        }
        stage2.clear_iommu_ops();
        let cached_dom = self.iommu.lock().take();
        for entry in taken {
            Self::cleanup_bar_objs(stage2, &entry.bars);
            drop(entry);
        }
        drop(cached_dom);
    }

    pub fn reset(&self, dev_id: PciDevId) -> HvResult<()> {
        let handle = self.get_handle(dev_id)?;
        let rc = unsafe { airlock_kapi_pci_reset(handle.raw) };
        if rc < 0 {
            Err(errno_to_hv(rc))
        } else {
            Ok(())
        }
    }

    pub fn read_config(&self, dev_id: PciDevId, offset: u16, size: u8) -> HvResult<u32> {
        let handle = self.get_handle(dev_id)?;
        let mut val = 0u32;
        let rc = unsafe { airlock_kapi_pci_read_config(handle.raw, offset, size, &mut val) };
        if rc < 0 {
            Err(errno_to_hv(rc))
        } else {
            Ok(val)
        }
    }

    pub fn write_config(&self, dev_id: PciDevId, offset: u16, size: u8, val: u32) -> HvResult<()> {
        let handle = self.get_handle(dev_id)?;
        let rc = unsafe { airlock_kapi_pci_write_config(handle.raw, offset, size, val) };
        if rc < 0 {
            Err(errno_to_hv(rc))
        } else {
            Ok(())
        }
    }

    pub fn bar_info(&self, dev_id: PciDevId, bar_idx: u8) -> HvResult<PciBarInfo> {
        if bar_idx >= 6 {
            return Err(HvError::InvalidParam);
        }
        let devs = self.devs.lock();
        let entry = devs
            .get(dev_id as usize)
            .and_then(Option::as_ref)
            .ok_or(HvError::InvalidParam)?;
        Ok(entry.bars[bar_idx as usize])
    }

    pub fn bar_io(
        &self,
        dev_id: PciDevId,
        bar_idx: u8,
        offset: u64,
        size: u8,
        write: Option<u64>,
    ) -> HvResult<u64> {
        let handle = self.get_handle(dev_id)?;
        let mut out = 0u64;
        let (is_write, val) = match write {
            Some(v) => (true, v),
            None => (false, 0),
        };
        let rc = unsafe {
            airlock_kapi_pci_bar_io(handle.raw, bar_idx, offset, size, is_write, val, &mut out)
        };
        if rc < 0 {
            Err(errno_to_hv(rc))
        } else {
            Ok(out)
        }
    }

    pub fn configure_msix(
        &self,
        dev_id: PciDevId,
        entry_idx: u16,
        guest_msi: Option<(u64, u32)>,
    ) -> HvResult<()> {
        let handle = self.get_handle(dev_id)?;
        let (enabled, addr, data) = match guest_msi {
            Some((a, d)) => (true, a, d),
            None => (false, 0, 0),
        };
        let rc = unsafe {
            airlock_kapi_pci_configure_msix(handle.raw, entry_idx, enabled, addr, data)
        };
        if rc < 0 {
            Err(errno_to_hv(rc))
        } else {
            Ok(())
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_on_msix_irq(
    hv_ptr: usize,
    guest_addr: u64,
    guest_data: u32,
) {
    if hv_ptr != 0 {
        let hv = unsafe { &*(hv_ptr as *const LinuxHvCore) };
        let _ = hv.inject_msi_from_irq(guest_addr, guest_data);
    }
}
