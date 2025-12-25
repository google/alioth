// Copyright 2024 Google LLC
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

#[cfg(target_os = "macos")]
#[path = "hvf/hvf.rs"]
mod hvf;
#[cfg(target_os = "linux")]
#[path = "kvm/kvm.rs"]
mod kvm;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;
#[cfg(target_arch = "x86_64")]
use std::collections::HashMap;
use std::fmt::Debug;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread::JoinHandle;

use serde::Deserialize;
use serde_aco::Help;
use snafu::Snafu;

#[cfg(target_arch = "x86_64")]
use crate::arch::cpuid::CpuidIn;
#[cfg(target_arch = "x86_64")]
use crate::arch::reg::{DtReg, DtRegVal, SegReg, SegRegVal};
use crate::arch::reg::{Reg, SReg};
#[cfg(target_arch = "x86_64")]
use crate::arch::sev::{SevPolicy, SnpPageType, SnpPolicy};
use crate::errors::{DebugTrace, trace_error};

#[cfg(target_os = "macos")]
pub use self::hvf::Hvf;
#[cfg(target_os = "linux")]
pub use self::kvm::{Kvm, KvmConfig, KvmError};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to map hva {hva:#x} to gpa {gpa:#x}, size {size:#x}"))]
    GuestMap {
        hva: usize,
        gpa: u64,
        size: u64,
        error: std::io::Error,
    },
    #[snafu(display("Failed to unmap gpa {gpa:#x}, size {size:#x}"))]
    GuestUnmap {
        gpa: u64,
        size: u64,
        error: std::io::Error,
    },
    #[snafu(display("Hypervisor is missing capability: {cap}"))]
    Capability { cap: &'static str },
    #[snafu(display("Failed to setup signal handlers"))]
    SetupSignal { error: std::io::Error },
    #[snafu(display("Failed to create a VM"))]
    CreateVm { error: std::io::Error },
    #[snafu(display("Failed to create a VCPU"))]
    CreateVcpu { error: std::io::Error },
    #[snafu(display("Failed to create a device"))]
    CreateDevice { error: std::io::Error },
    #[snafu(display("Failed to configure VM parameters"))]
    SetVmParam { error: std::io::Error },
    #[snafu(display("Failed to configure VCPU registers"))]
    VcpuReg { error: std::io::Error },
    #[snafu(display("Failed to configure the guest CPUID"))]
    GuestCpuid { error: std::io::Error },
    #[cfg(target_arch = "x86_64")]
    #[snafu(display("Failed to configure guest MSRs"))]
    GuestMsr { error: std::io::Error },
    #[snafu(display("Failed to configure an encrypted region"))]
    EncryptedRegion { error: std::io::Error },
    #[snafu(display("Cannot create multiple VM memories"))]
    MemoryCreated,
    #[snafu(display("Failed to configure an IrqFd"))]
    IrqFd { error: std::io::Error },
    #[snafu(display("Failed to configure an IoeventFd"))]
    IoeventFd { error: std::io::Error },
    #[snafu(display("Failed to create an IrqSender for pin {pin}"))]
    CreateIrq { pin: u8, error: std::io::Error },
    #[snafu(display("Failed to send an interrupt"))]
    SendInterrupt { error: std::io::Error },
    #[snafu(display("Failed to run a VCPU"))]
    RunVcpu { error: std::io::Error },
    #[snafu(display("Failed to stop a VCPU"))]
    StopVcpu { error: std::io::Error },
    #[snafu(display("Failed to handle VM exit: {msg}"))]
    VmExit { msg: String },
    #[cfg(target_os = "linux")]
    #[snafu(display("KVM internal error"), context(false))]
    KvmErr { source: Box<KvmError> },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Deserialize, Clone, Help)]
#[cfg_attr(target_os = "macos", derive(Default))]
pub enum HvConfig {
    /// KVM backed by the Linux kernel.
    #[cfg(target_os = "linux")]
    #[serde(alias = "kvm")]
    Kvm(KvmConfig),
    /// macOS Hypervisor Framework.
    #[cfg(target_os = "macos")]
    #[default]
    #[serde(alias = "hvf")]
    Hvf,
}

#[cfg(target_os = "linux")]
impl Default for HvConfig {
    fn default() -> Self {
        HvConfig::Kvm(KvmConfig::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemMapOption {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub log_dirty: bool,
}

impl Default for MemMapOption {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            exec: true,
            log_dirty: false,
        }
    }
}

pub trait Vcpu {
    #[cfg(target_arch = "aarch64")]
    fn reset(&mut self, is_bsp: bool) -> Result<()>;

    fn get_reg(&self, reg: Reg) -> Result<u64, Error>;
    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error>;

    fn get_sreg(&self, reg: SReg) -> Result<u64, Error>;

    #[cfg(target_arch = "x86_64")]
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error>;

    #[cfg(target_arch = "aarch64")]
    fn set_sregs(&mut self, sregs: &[(SReg, u64)]) -> Result<(), Error>;

    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error>;

    #[cfg(target_arch = "x86_64")]
    fn set_cpuids(&mut self, cpuids: HashMap<CpuidIn, CpuidResult>) -> Result<(), Error>;

    #[cfg(target_arch = "x86_64")]
    fn set_msrs(&mut self, msrs: &[(u32, u64)]) -> Result<()>;

    fn dump(&self) -> Result<(), Error>;

    #[cfg(target_arch = "aarch64")]
    fn advance_pc(&mut self) -> Result<()> {
        let pc = self.get_reg(Reg::Pc)?;
        self.set_regs(&[(Reg::Pc, pc + 4)])
    }
}

pub trait IrqSender: Debug + Send + Sync + 'static {
    fn send(&self) -> Result<(), Error>;
}

impl<T> IrqSender for Arc<T>
where
    T: IrqSender,
{
    fn send(&self) -> Result<(), Error> {
        IrqSender::send(self.as_ref())
    }
}

pub trait MsiSender: Debug + Send + Sync + 'static {
    type IrqFd: IrqFd;
    fn send(&self, addr: u64, data: u32) -> Result<()>;
    fn create_irqfd(&self) -> Result<Self::IrqFd>;
}

pub trait VmMemory: Debug + Send + Sync + 'static {
    fn mem_map(&self, gpa: u64, size: u64, hva: usize, option: MemMapOption) -> Result<(), Error>;

    fn unmap(&self, gpa: u64, size: u64) -> Result<(), Error>;

    fn reset(&self) -> Result<()>;

    fn register_encrypted_range(&self, _range: &[u8]) -> Result<()> {
        unimplemented!()
    }
    fn deregister_encrypted_range(&self, _range: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn mark_private_memory(&self, gpa: u64, size: u64, private: bool) -> Result<()>;
}

pub trait IoeventFd: Debug + Send + Sync + AsFd + 'static {}

pub trait IoeventFdRegistry: Debug + Send + Sync + 'static {
    type IoeventFd: IoeventFd;
    fn create(&self) -> Result<Self::IoeventFd>;
    fn register(&self, fd: &Self::IoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    fn register_port(
        &self,
        fd: &Self::IoeventFd,
        port: u16,
        len: u8,
        data: Option<u64>,
    ) -> Result<()>;
    fn deregister(&self, fd: &Self::IoeventFd) -> Result<()>;
}

pub trait IrqFd: Debug + Send + Sync + AsFd + 'static {
    fn set_addr_lo(&self, val: u32) -> Result<()>;
    fn get_addr_lo(&self) -> u32;
    fn set_addr_hi(&self, val: u32) -> Result<()>;
    fn get_addr_hi(&self) -> u32;
    fn set_data(&self, val: u32) -> Result<()>;
    fn get_data(&self) -> u32;
    fn set_masked(&self, val: bool) -> Result<bool>;
    fn get_masked(&self) -> bool;
}

#[cfg(target_arch = "aarch64")]
pub trait GicV2: Debug + Send + Sync + 'static {
    fn init(&self) -> Result<()>;
    fn get_dist_reg(&self, cpu_index: u32, offset: u16) -> Result<u32>;
    fn set_dist_reg(&self, cpu_index: u32, offset: u16, val: u32) -> Result<()>;
    fn get_cpu_reg(&self, cpu_index: u32, offset: u16) -> Result<u32>;
    fn set_cpu_reg(&self, cpu_index: u32, offset: u16, val: u32) -> Result<()>;
    fn get_num_irqs(&self) -> Result<u32>;
    fn set_num_irqs(&self, val: u32) -> Result<()>;
}

#[cfg(target_arch = "aarch64")]
pub trait GicV2m: Debug + Send + Sync + 'static {
    fn init(&self) -> Result<()>;
}

#[cfg(target_arch = "aarch64")]
pub trait GicV3: Debug + Send + Sync + 'static {
    fn init(&self) -> Result<()>;
}

#[cfg(target_arch = "aarch64")]
pub trait Its: Debug + Send + Sync + 'static {
    fn init(&self) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub enum Coco {
    /// Enable AMD SEV or SEV-ES.
    #[cfg(target_arch = "x86_64")]
    #[serde(alias = "sev")]
    AmdSev {
        /// SEV policy, 0x1 for SEV, 0x5 for SEV-ES.
        /// SEV API Ver 0.24, Rev 3.24, Ch.2, Table 2.
        policy: SevPolicy,
    },
    /// Enable AMD SEV-SNP.
    #[cfg(target_arch = "x86_64")]
    #[serde(alias = "snp", alias = "sev-snp")]
    AmdSnp {
        /// SEV-SNP policy, e.g. 0x30000.
        /// SNP Firmware ABI Spec, Rev 1.55, Sec.4.3, Table 9.
        policy: SnpPolicy,
    },
}

#[derive(Debug)]
pub struct VmConfig {
    pub coco: Option<Coco>,
}

pub trait Vm {
    type Vcpu: Vcpu;
    type Memory: VmMemory;
    type IrqSender: IrqSender + Send + Sync;
    type MsiSender: MsiSender;
    type IoeventFdRegistry: IoeventFdRegistry;
    fn create_vcpu(&self, index: u16, identity: u64) -> Result<Self::Vcpu, Error>;
    fn create_irq_sender(&self, pin: u8) -> Result<Self::IrqSender, Error>;
    fn create_msi_sender(
        &self,
        #[cfg(target_arch = "aarch64")] devid: u32,
    ) -> Result<Self::MsiSender>;
    fn create_vm_memory(&mut self) -> Result<Self::Memory, Error>;
    fn create_ioeventfd_registry(&self) -> Result<Self::IoeventFdRegistry>;
    fn stop_vcpu<T>(&self, identity: u64, handle: &JoinHandle<T>) -> Result<(), Error>;

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_start(&self, policy: SevPolicy) -> Result<()>;

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_update_vmsa(&self) -> Result<()>;

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_update_data(&self, range: &mut [u8]) -> Result<()>;

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_measure(&self) -> Result<Vec<u8>>;

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_finish(&self) -> Result<()>;

    #[cfg(target_arch = "x86_64")]
    fn snp_launch_start(&self, policy: SnpPolicy) -> Result<()>;

    #[cfg(target_arch = "x86_64")]
    fn snp_launch_update(&self, range: &mut [u8], gpa: u64, type_: SnpPageType) -> Result<()>;

    #[cfg(target_arch = "x86_64")]
    fn snp_launch_finish(&self) -> Result<()>;

    #[cfg(target_arch = "aarch64")]
    type GicV2: GicV2;
    #[cfg(target_arch = "aarch64")]
    fn create_gic_v2(&self, distributor_base: u64, cpu_interface_base: u64) -> Result<Self::GicV2>;

    #[cfg(target_arch = "aarch64")]
    type GicV3: GicV3;
    #[cfg(target_arch = "aarch64")]
    fn create_gic_v3(
        &self,
        distributor_base: u64,
        redistributor_base: u64,
        redistributor_count: u16,
    ) -> Result<Self::GicV3>;

    #[cfg(target_arch = "aarch64")]
    type GicV2m: GicV2m;
    #[cfg(target_arch = "aarch64")]
    fn create_gic_v2m(&self, base: u64) -> Result<Self::GicV2m>;

    #[cfg(target_arch = "aarch64")]
    type Its: Its;
    #[cfg(target_arch = "aarch64")]
    fn create_its(&self, base: u64) -> Result<Self::Its>;
}

pub trait Hypervisor {
    type Vm: Vm + Sync + Send + 'static;

    fn create_vm(&self, config: &VmConfig) -> Result<Self::Vm, Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_supported_cpuids(&self) -> Result<HashMap<CpuidIn, CpuidResult>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    #[cfg(target_arch = "x86_64")]
    Io {
        port: u16,
        write: Option<u32>,
        size: u8,
    },
    Mmio {
        addr: u64,
        write: Option<u64>,
        size: u8,
    },
    ConvertMemory {
        gpa: u64,
        size: u64,
        private: bool,
    },
    Shutdown,
    Reboot,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmEntry {
    None,
    Shutdown,
    Reboot,
    #[cfg(target_arch = "x86_64")]
    Io {
        data: Option<u32>,
    },
    Mmio {
        data: u64,
    },
}

#[cfg(test)]
#[path = "hv_test.rs"]
pub(crate) mod tests;
