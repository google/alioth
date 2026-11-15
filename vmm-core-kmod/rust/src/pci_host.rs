// SPDX-License-Identifier: GPL-2.0
// Ring-0 PCI device passthrough & Linux IOMMU manager (implemented in sub-step `(l.5)`).

use vmm_core::host::{HvError, HvResult, PciBarInfo, PciDevId};

use crate::stage2::Stage2Mmu;

pub struct PciHostManager;

impl Default for PciHostManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PciHostManager {
    pub const fn new() -> Self {
        Self
    }

    pub fn attach(&self, _stage2: &Stage2Mmu, _host_bdf: u16) -> HvResult<PciDevId> {
        Err(HvError::Unsupported)
    }

    pub fn detach(&self, _stage2: &Stage2Mmu, _dev: PciDevId) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn reset(&self, _dev: PciDevId) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn read_config(&self, _dev: PciDevId, _offset: u16, _size: u8) -> HvResult<u32> {
        Err(HvError::Unsupported)
    }

    pub fn write_config(
        &self,
        _dev: PciDevId,
        _offset: u16,
        _size: u8,
        _val: u32,
    ) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn bar_info(&self, _dev: PciDevId, _bar_idx: u8) -> HvResult<PciBarInfo> {
        Err(HvError::Unsupported)
    }

    pub fn bar_io(
        &self,
        _dev: PciDevId,
        _bar_idx: u8,
        _offset: u64,
        _size: u8,
        _write: Option<u64>,
    ) -> HvResult<u64> {
        Err(HvError::Unsupported)
    }

    pub fn configure_msix(
        &self,
        _dev: PciDevId,
        _entry_idx: u16,
        _guest_msi: Option<(u64, u32)>,
    ) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn teardown_all(&self, _stage2: &Stage2Mmu) {}
}
