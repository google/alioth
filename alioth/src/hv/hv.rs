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

#[cfg(target_os = "linux")]
#[path = "kvm/kvm.rs"]
mod kvm;
#[cfg(test)]
pub(crate) mod test;
#[cfg(target_os = "linux")]
pub use kvm::{Kvm, KvmConfig, KvmError};
use macros::trace_error;
use serde::Deserialize;
use snafu::Snafu;

use std::fmt::Debug;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread::JoinHandle;

#[cfg(target_arch = "x86_64")]
use crate::arch::cpuid::Cpuid;
use crate::arch::reg::Reg;
#[cfg(target_arch = "x86_64")]
use crate::arch::reg::{DtReg, DtRegVal, SReg, SegReg, SegRegVal};

use crate::arch::sev::{SevPolicy, SnpPageType, SnpPolicy};

#[trace_error]
#[derive(Snafu)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to map hva {hva:#x} to gpa {gpa:#x}, size {size:#x}"))]
    GuestMap {
        hva: usize,
        gpa: u64,
        size: usize,
        error: std::io::Error,
    },
    #[snafu(display("Failed to unmap gpa {gpa:#x}, size {size:#x}"))]
    GuestUnmap {
        gpa: u64,
        size: usize,
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
    #[snafu(display("Failed to configure an encrypted region"))]
    EncryptedRegion { error: std::io::Error },
    #[snafu(display("Cannot create multiple VM memories"))]
    MemoryCreated,
    #[snafu(display("Failed to configure an IrqFd"))]
    IrqFd { error: std::io::Error },
    #[snafu(display("Failed to configure an IoeventFd"))]
    IoeventFd { error: std::io::Error },
    #[snafu(display("Failed to create an IntxSender for pin {pin}"))]
    CreateIntx { pin: u8, error: std::io::Error },
    #[snafu(display("Failed to send an interrupt"))]
    SendInterrupt { error: std::io::Error },
    #[snafu(display("Failed to run a VCPU"))]
    RunVcpu { error: std::io::Error },
    #[snafu(display("Failed to stop a VCPU"))]
    StopVcpu { error: std::io::Error },
    #[snafu(display("KVM internal error"), context(false))]
    KvmErr { source: Box<KvmError> },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

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
    fn get_reg(&self, reg: Reg) -> Result<u64, Error>;
    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_sreg(&self, reg: SReg) -> Result<u64, Error>;

    #[cfg(target_arch = "x86_64")]
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error>;

    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error>;

    #[cfg(target_arch = "x86_64")]
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error>;

    fn dump(&self) -> Result<(), Error>;
}

pub trait IntxSender: Debug + Send + Sync + 'static {
    fn send(&self) -> Result<(), Error>;
}

impl<T> IntxSender for Arc<T>
where
    T: IntxSender,
{
    fn send(&self) -> Result<(), Error> {
        IntxSender::send(self.as_ref())
    }
}

pub trait MsiSender: Debug + Send + Sync + 'static {
    type IrqFd: IrqFd;
    fn send(&self, addr: u64, data: u32) -> Result<()>;
    fn create_irqfd(&self) -> Result<Self::IrqFd>;
}

pub trait VmMemory: Debug + Send + Sync + 'static {
    fn mem_map(
        &self,
        slot: u32,
        gpa: usize,
        size: usize,
        hva: usize,
        option: MemMapOption,
    ) -> Result<(), Error>;

    fn unmap(&self, slot: u32, gpa: usize, size: usize) -> Result<(), Error>;

    fn max_mem_slots(&self) -> Result<u32, Error>;

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
    fn register(&self, fd: &Self::IoeventFd, gpa: usize, len: u8, data: Option<u64>) -> Result<()>;
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
    fn set_masked(&self, val: bool) -> Result<()>;
    fn get_masked(&self) -> bool;
}

#[derive(Debug, Clone, Deserialize)]
pub enum Coco {
    #[serde(alias = "sev")]
    AmdSev { policy: SevPolicy },
    #[serde(alias = "snp", alias = "sev-snp")]
    AmdSnp { policy: SnpPolicy },
}

#[derive(Debug)]
pub struct VmConfig {
    pub coco: Option<Coco>,
}

pub trait Vm {
    type Vcpu: Vcpu;
    type Memory: VmMemory;
    type IntxSender: IntxSender + Send + Sync;
    type MsiSender: MsiSender;
    type IoeventFdRegistry: IoeventFdRegistry;
    fn create_vcpu(&self, id: u32) -> Result<Self::Vcpu, Error>;
    fn create_intx_sender(&self, pin: u8) -> Result<Self::IntxSender, Error>;
    fn create_msi_sender(&self) -> Result<Self::MsiSender>;
    fn create_vm_memory(&mut self) -> Result<Self::Memory, Error>;
    fn create_ioeventfd_registry(&self) -> Result<Self::IoeventFdRegistry>;
    fn stop_vcpu<T>(id: u32, handle: &JoinHandle<T>) -> Result<(), Error>;

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_start(&self, policy: u32) -> Result<()>;

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
}

pub trait Hypervisor {
    type Vm: Vm + Sync + Send + 'static;

    fn create_vm(&self, config: &VmConfig) -> Result<Self::Vm, Error>;

    #[cfg(target_arch = "x86_64")]
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    Io {
        port: u16,
        write: Option<u32>,
        size: u8,
    },
    Mmio {
        addr: usize,
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
    Unknown(String),
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmEntry {
    None,
    Shutdown,
    Reboot,
    Io { data: u32 },
    Mmio { data: u64 },
}
