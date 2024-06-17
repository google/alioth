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

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::io::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::os::fd::{OwnedFd, RawFd};
use std::ptr::null_mut;

use libc::{mmap, munmap, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use snafu::ResultExt;

#[cfg(target_arch = "x86_64")]
use crate::arch::cpuid::Cpuid;
use crate::arch::reg::Reg;
#[cfg(target_arch = "x86_64")]
use crate::arch::reg::{DtReg, DtRegVal, SReg, SegReg, SegRegVal};
use crate::ffi;
use crate::hv::kvm::bindings::{KvmExit, KvmRun};
use crate::hv::kvm::ioctls::kvm_run;
use crate::hv::kvm::{kvm_error, KvmError};
use crate::hv::{error, Error, Vcpu, VmEntry, VmExit};

pub(super) struct KvmRunBlock {
    addr: usize,
    size: usize,
}

impl KvmRunBlock {
    pub unsafe fn new(fd: RawFd, mmap_size: usize) -> Result<KvmRunBlock, KvmError> {
        let prot = PROT_READ | PROT_WRITE;
        let addr = ffi!(
            unsafe { mmap(null_mut(), mmap_size, prot, MAP_SHARED, fd, 0,) },
            MAP_FAILED
        )
        .context(kvm_error::MmapVcpuFd)?;
        Ok(KvmRunBlock {
            addr: addr as usize,
            size: mmap_size,
        })
    }

    pub(super) unsafe fn data_slice<T>(&self, offset: usize, count: usize) -> &[T] {
        std::slice::from_raw_parts((self.addr + offset) as *const T, count)
    }

    pub(super) unsafe fn data_slice_mut<T>(&mut self, offset: usize, count: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut((self.addr + offset) as *mut T, count)
    }
}

impl Deref for KvmRunBlock {
    type Target = KvmRun;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.addr as *const Self::Target) }
    }
}

impl DerefMut for KvmRunBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.addr as *mut Self::Target) }
    }
}

impl Drop for KvmRunBlock {
    fn drop(&mut self) {
        if let Err(e) = ffi!(unsafe { munmap(self.addr as _, self.size) }) {
            log::error!("unmap kvm_run: {}", e)
        }
    }
}

pub struct KvmVcpu {
    pub(super) kvm_run: KvmRunBlock,
    pub(super) fd: OwnedFd,
}

impl Vcpu for KvmVcpu {
    fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        self.kvm_get_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        self.kvm_get_dt_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        self.kvm_get_seg_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        self.kvm_get_sreg(reg)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        self.kvm_set_regs(vals)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        self.kvm_set_sregs(sregs, seg_regs, dt_regs)
    }

    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
        match entry {
            VmEntry::None => {}
            VmEntry::Io { data } => self.entry_io(data),
            VmEntry::Mmio { data } => self.entry_mmio(data),
            VmEntry::Shutdown | VmEntry::Reboot => self.set_immediate_exit(true),
        };
        let ret = unsafe { kvm_run(&self.fd) };
        match ret {
            Err(e) => match (e.kind(), entry) {
                (ErrorKind::WouldBlock, _) => Ok(VmExit::Interrupted),
                (ErrorKind::Interrupted, VmEntry::Shutdown) => {
                    self.set_immediate_exit(false);
                    Ok(VmExit::Shutdown)
                }
                (ErrorKind::Interrupted, VmEntry::Reboot) => {
                    self.set_immediate_exit(false);
                    Ok(VmExit::Reboot)
                }
                (ErrorKind::Interrupted, _) => Ok(VmExit::Interrupted),
                _ => Err(e).context(error::RunVcpu),
            },
            Ok(_) => match self.kvm_run.exit_reason {
                KvmExit::IO => self.handle_io(),
                KvmExit::HYPERCALL => self.handle_hypercall(),
                KvmExit::MMIO => self.handle_mmio(),
                KvmExit::SHUTDOWN => Ok(VmExit::Shutdown),
                reason => Ok(VmExit::Unknown(format!("unkown kvm exit: {:#x?}", reason))),
            },
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        self.kvm_set_cpuids(cpuids)
    }

    fn dump(&self) -> Result<(), Error> {
        Ok(())
    }
}
