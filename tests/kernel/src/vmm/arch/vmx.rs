// Intel VT-x (VMX) stub implementing the vendor-neutral arch interface.

use vmm_core::host::abi::{RawCpuid, VcpuCommPage};
use vmm_core::host::{HvError, HvResult, RegId, RegVal};

use crate::uspace::process::Thread;

use super::FastExit;
use crate::vmm::lapic::VcpuLapic;
use crate::vmm::stage2::Stage2Mmu;

pub fn is_supported() -> bool {
    false
}

pub struct VmxSharedTables;

impl VmxSharedTables {
    pub fn new() -> HvResult<Self> {
        Err(HvError::Unsupported)
    }
}

pub struct VmxVcpu;

impl VmxVcpu {
    pub fn new(_shared: &VmxSharedTables, _npt_root_pa: u64) -> HvResult<Self> {
        Err(HvError::Unsupported)
    }

    pub fn guest_xcr0(&self) -> u64 {
        1
    }

    pub fn configure_cpuids(&mut self, _cpuids: &[RawCpuid]) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn get_regs(
        &self,
        _lapic: &VcpuLapic,
        _ids: &[RegId],
        _out: &mut [RegVal],
    ) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn set_regs(&mut self, _lapic: &VcpuLapic, _regs: &[(RegId, RegVal)]) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    pub fn apply_sipi(&mut self, _start_page: u8, _npt_root_pa: u64) {}

    pub fn advance_rip(&mut self, _bytes: u8) {}

    pub fn complete_rdmsr(&mut self, _val: u64, _insn_len: u8) {}

    pub fn inject_gp0(&mut self) {}

    pub fn sync_to_comm(&self, _comm: &mut VcpuCommPage) {}

    pub fn enter_guest(
        &mut self,
        _thread: &Thread,
        _lapic: &VcpuLapic,
        _stage2: &Stage2Mmu,
        _comm: &mut VcpuCommPage,
    ) -> HvResult<FastExit> {
        Err(HvError::Unsupported)
    }
}
