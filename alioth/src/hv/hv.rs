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

#[path = "arch/arch.rs"]
pub mod arch;

#[cfg(target_os = "linux")]
#[path = "kvm/kvm.rs"]
mod kvm;
#[cfg(test)]
pub(crate) mod test;
#[cfg(target_os = "linux")]
pub use kvm::{Kvm, KvmConfig};
use serde::Deserialize;

use std::fmt::Debug;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread::JoinHandle;

use arch::Reg;
#[cfg(target_arch = "x86_64")]
use arch::{Cpuid, DtReg, DtRegVal, SReg, SegReg, SegRegVal};
use thiserror::Error;

use crate::arch::sev::Policy;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid memory map option for {hypervisor}: {option:?}")]
    MemMapOption {
        option: MemMapOption,
        hypervisor: &'static str,
    },
    #[error("IO error: {source}")]
    StdIo {
        #[from]
        source: std::io::Error,
    },
    #[error("{msg}")]
    Unexpected { msg: String },
    #[error("lack capability: {cap}")]
    LackCap { cap: String },
    #[error("creating multipe memory")]
    CreatingMultipleMemory,
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
    fn send(&self, addr: u64, data: u32) -> Result<()>;
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

#[derive(Debug, Clone, Deserialize)]
pub enum Coco {
    #[serde(alias = "sev")]
    AmdSev { policy: Policy },
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

    fn sev_launch_start(&self, _policy: u32) -> Result<(), Error> {
        unimplemented!()
    }
    fn sev_launch_update_vmsa(&self) -> Result<(), Error> {
        unimplemented!()
    }
    fn sev_launch_update_data(&self, _range: &mut [u8]) -> Result<(), Error> {
        unimplemented!()
    }
    fn sev_launch_measure(&self) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }
    fn sev_launch_finish(&self) -> Result<(), Error> {
        unimplemented!()
    }
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
