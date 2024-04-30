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
pub use kvm::Kvm;

use std::fmt::Debug;
use std::sync::Arc;
use std::thread::JoinHandle;

use arch::Reg;
#[cfg(target_arch = "x86_64")]
use arch::{Cpuid, DtReg, DtRegVal, SReg, SegReg, SegRegVal};
use thiserror::Error;

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
}

pub trait Vm {
    type Vcpu: Vcpu;
    type Memory: VmMemory;
    type IntxSender: IntxSender + Send + Sync;
    fn create_vcpu(&self, id: u32) -> Result<Self::Vcpu, Error>;
    fn create_intx_sender(&self, pin: u8) -> Result<Self::IntxSender, Error>;
    fn create_vm_memory(&mut self) -> Result<Self::Memory, Error>;
    fn stop_vcpu<T>(id: u32, handle: &JoinHandle<T>) -> Result<(), Error>;
}

pub trait Hypervisor {
    type Vm: Vm + Sync + Send + 'static;

    fn create_vm(&self) -> Result<Self::Vm, Error>;

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
    Unknown(String),
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmEntry {
    None,
    Shutdown,
    Io { data: u32 },
    Mmio { data: u64 },
}
