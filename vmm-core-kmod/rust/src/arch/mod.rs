// SPDX-License-Identifier: GPL-2.0
// Vendor-neutral Ring-0 hardware virtualization facade (AMD SVM primary, Intel VMX stub).

pub mod svm;
pub mod vmx;

use vmm_core::host::abi::{RawCpuid, VcpuCommPage};
use vmm_core::host::{HvError, HvResult, RegId, RegVal};

use crate::lapic::VcpuLapic;
use crate::stage2::Stage2Mmu;

/// Decoded outcome of a single guest entry (`VMRUN` / `VMLAUNCH`).
pub enum FastExit {
    /// Physical host interrupt / timer preemption arrived (`VMEXIT_INTR` / `NMI` / pre-entry abort).
    HostIntr,
    /// Guest executed `HLT` (`RIP` already advanced past `HLT`).
    Hlt,
    /// Guest executed `CPUID` (already answered in-place from per-vCPU `cpuids`).
    Cpuid,
    /// Guest executed scalar `IN` or `OUT` (`comm` already populated with `VmExit::Io`).
    Pio {
        port: u16,
        write: Option<u32>,
        size: u8,
        insn_len: u8,
    },
    /// Guest triggered a Stage-2 Nested Page Fault (`comm` populated with `VmExit::MmioFault`).
    MmioFault { gpa: u64, is_write: bool },
    /// Guest executed `RDMSR` on a non-EFER/PAT MSR (`RIP` not yet advanced).
    MsrRead { msr: u32, insn_len: u8 },
    /// Guest executed `WRMSR` on a non-EFER/PAT MSR (`RIP` not yet advanced).
    MsrWrite { msr: u32, val: u64, insn_len: u8 },
    /// Guest triple-faulted (`VMEXIT_SHUTDOWN`).
    Shutdown,
    /// Handled completely inside the arch backend (`EFER`, `PAT`, `XSETBV`, `VINTR`, `#UD`).
    EmulateHandled,
}

pub enum ArchSharedTables {
    Svm(svm::SvmSharedTables),
    Vmx(vmx::VmxSharedTables),
}

impl ArchSharedTables {
    pub fn new() -> HvResult<Self> {
        if svm::is_supported() {
            Ok(Self::Svm(svm::SvmSharedTables::new()?))
        } else if vmx::is_supported() {
            Ok(Self::Vmx(vmx::VmxSharedTables::new()?))
        } else {
            Err(HvError::Unsupported)
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum ArchVcpu {
    Svm(svm::SvmVcpu),
    Vmx(vmx::VmxVcpu),
}

impl ArchVcpu {
    pub fn new(shared: &ArchSharedTables, npt_root_pa: u64) -> HvResult<Self> {
        match shared {
            ArchSharedTables::Svm(t) => Ok(Self::Svm(svm::SvmVcpu::new(t, npt_root_pa)?)),
            ArchSharedTables::Vmx(t) => Ok(Self::Vmx(vmx::VmxVcpu::new(t, npt_root_pa)?)),
        }
    }

    pub fn configure_cpuids(&mut self, cpuids: &[RawCpuid]) -> HvResult<()> {
        match self {
            Self::Svm(v) => v.configure_cpuids(cpuids),
            Self::Vmx(v) => v.configure_cpuids(cpuids),
        }
    }

    pub fn get_regs(&self, lapic: &VcpuLapic, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        match self {
            Self::Svm(v) => v.get_regs(lapic, ids, out),
            Self::Vmx(v) => v.get_regs(lapic, ids, out),
        }
    }

    pub fn set_regs(&mut self, lapic: &VcpuLapic, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        match self {
            Self::Svm(v) => v.set_regs(lapic, regs),
            Self::Vmx(v) => v.set_regs(lapic, regs),
        }
    }

    pub fn apply_sipi(&mut self, start_page: u8, npt_root_pa: u64) {
        match self {
            Self::Svm(v) => v.apply_sipi(start_page, npt_root_pa),
            Self::Vmx(v) => v.apply_sipi(start_page, npt_root_pa),
        }
    }

    pub fn advance_rip(&mut self, bytes: u8) {
        match self {
            Self::Svm(v) => v.advance_rip(bytes),
            Self::Vmx(v) => v.advance_rip(bytes),
        }
    }

    pub fn complete_rdmsr(&mut self, val: u64, insn_len: u8) {
        match self {
            Self::Svm(v) => v.complete_rdmsr(val, insn_len),
            Self::Vmx(v) => v.complete_rdmsr(val, insn_len),
        }
    }

    #[allow(dead_code)]
    pub fn inject_gp0(&mut self) {
        match self {
            Self::Svm(v) => v.inject_gp0(),
            Self::Vmx(v) => v.inject_gp0(),
        }
    }

    pub fn sync_to_comm(&self, comm: &mut VcpuCommPage) {
        match self {
            Self::Svm(v) => v.sync_to_comm(comm),
            Self::Vmx(v) => v.sync_to_comm(comm),
        }
    }

    pub fn enter_guest(
        &mut self,
        lapic: &VcpuLapic,
        stage2: &Stage2Mmu,
        comm: &mut VcpuCommPage,
    ) -> HvResult<FastExit> {
        match self {
            Self::Svm(v) => v.enter_guest(lapic, stage2, comm),
            Self::Vmx(v) => v.enter_guest(lapic, stage2, comm),
        }
    }
}
