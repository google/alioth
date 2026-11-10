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

#[path = "x86_64.rs"]
mod x86_64;

use std::io::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::os::fd::{OwnedFd, RawFd};
use std::ptr::null_mut;

use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, mmap, munmap};

use crate::ffi;
use crate::hv::arch::Reg;
use crate::hv::arch::{Cpuid, DtReg, DtRegVal, SReg, SegReg, SegRegVal};
use crate::hv::{Error, VmEntry, VmExit};

use super::bindings::{
    KVM_EXIT_IO, KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT, KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN, KvmRun,
    KVM_EXIT_FAIL_ENTRY, KVM_EXIT_INTERNAL_ERROR,
};
use super::ioctls::kvm_run;

pub(super) struct KvmRunBlock {
    addr: usize,
    size: usize,
}

impl KvmRunBlock {
    pub unsafe fn new(fd: RawFd, mmap_size: usize) -> Result<KvmRunBlock, Error> {
        let prot = PROT_READ | PROT_WRITE;
        let addr = ffi!(
            unsafe { mmap(null_mut(), mmap_size, prot, MAP_SHARED, fd, 0,) },
            MAP_FAILED
        )?;
        Ok(KvmRunBlock {
            addr: addr as usize,
            size: mmap_size,
        })
    }

    pub(super) unsafe fn data_slice<T>(&self, offset: usize, count: usize) -> &[T] {
        unsafe { std::slice::from_raw_parts((self.addr + offset) as *const T, count) }
    }

    pub(super) unsafe fn data_slice_mut<T>(&mut self, offset: usize, count: usize) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut((self.addr + offset) as *mut T, count) }
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
            log::error!("unmap kvm_run: {e}")
        }
    }
}

pub struct Vcpu {
    pub(super) kvm_run: KvmRunBlock,
    pub(super) fd: OwnedFd,
}

impl Vcpu {
    pub fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        self.kvm_get_reg(reg)
    }

    pub fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        self.kvm_get_dt_reg(reg)
    }

    pub fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        self.kvm_get_seg_reg(reg)
    }

    pub fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        self.kvm_get_sreg(reg)
    }

    pub fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        self.kvm_set_regs(vals)
    }

    pub fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        self.kvm_set_sregs(sregs, seg_regs, dt_regs)
    }

    pub fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
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
                _ => Err(e.into()),
            },
            Ok(_) => match self.kvm_run.exit_reason {
                KVM_EXIT_IO => self.handle_io(),
                KVM_EXIT_MMIO => self.handle_mmio(),
                KVM_EXIT_SHUTDOWN => Ok(VmExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => {
                    let fail_entry = unsafe { self.kvm_run.exit.fail_entry };
                    Ok(VmExit::Unknown(format!(
                        "KVM VM-entry failed: hardware_entry_failure_reason = {:#x}, cpu = {}",
                        fail_entry.hardware_entry_failure_reason,
                        fail_entry.cpu
                    )))
                }
                KVM_EXIT_INTERNAL_ERROR => {
                    let internal = unsafe { self.kvm_run.exit.internal };
                    let suberror_str = match internal.suberror {
                        1 => " (Emulation failure. This can happen if the guest executed an invalid instruction, or if the kernel image is invalid/unsupported.)",
                        2 => " (Simultaneous exception)",
                        3 => " (Delivery event)",
                        _ => "",
                    };
                    let mut msg = format!(
                        "KVM internal error: suberror = {}{}, ndata = {}",
                        internal.suberror, suberror_str, internal.ndata
                    );
                    for i in 0..(internal.ndata as usize).min(16) {
                        msg.push_str(&format!(", data[{}] = {:#x}", i, internal.data[i]));
                    }
                    Ok(VmExit::Unknown(msg))
                }
                reason => Ok(VmExit::Unknown(format!("unkown kvm exit: {reason:#x}"))),
            },
        }
    }

    pub fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        self.kvm_set_cpuids(cpuids)
    }

    pub fn dump(&self) -> Result<(), Error> {
        Ok(())
    }

    // From vmentry.rs
    #[cfg(target_endian = "little")]
    pub(super) fn entry_mmio(&mut self, data: u64) {
        assert_eq!(self.kvm_run.exit_reason, KVM_EXIT_MMIO);
        let kvm_mmio = unsafe { &mut self.kvm_run.exit.mmio };
        assert_eq!(kvm_mmio.is_write, 0);
        kvm_mmio.data = data.to_ne_bytes();
    }

    pub(super) fn set_immediate_exit(&mut self, enable: bool) {
        self.kvm_run.immediate_exit = enable as u8;
    }

    pub(super) fn entry_io(&mut self, data: u32) {
        assert_eq!(self.kvm_run.exit_reason, KVM_EXIT_IO);
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        assert_eq!(kvm_io.direction, KVM_EXIT_IO_IN);
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        match kvm_io.size {
            1 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data as u8;
            },
            2 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data as u16;
            },
            4 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data;
            },
            _ => unreachable!("kvm_io.size = {}", kvm_io.size),
        }
    }

    // From vmexit.rs
    #[cfg(target_endian = "little")]
    pub(super) fn handle_mmio(&mut self) -> Result<VmExit, Error> {
        let kvm_mmio = unsafe { &self.kvm_run.exit.mmio };
        let exit = VmExit::Mmio {
            addr: kvm_mmio.phys_addr as usize,
            write: if kvm_mmio.is_write > 0 {
                Some(u64::from_ne_bytes(kvm_mmio.data))
            } else {
                None
            },
            size: kvm_mmio.len as u8,
        };
        Ok(exit)
    }

    pub(super) fn handle_io(&mut self) -> Result<VmExit, Error> {
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        assert_eq!(count, 1);
        let write = match (kvm_io.direction, kvm_io.size) {
            (KVM_EXIT_IO_IN, _) => None,
            (KVM_EXIT_IO_OUT, 1) => {
                Some(unsafe { self.kvm_run.data_slice::<u8>(offset, count) }[0] as u32)
            }
            (KVM_EXIT_IO_OUT, 2) => {
                Some(unsafe { self.kvm_run.data_slice::<u16>(offset, count) }[0] as u32)
            }
            (KVM_EXIT_IO_OUT, 4) => {
                Some(unsafe { self.kvm_run.data_slice::<u32>(offset, count) }[0])
            }
            _ => unreachable!(
                "kvm_io.direction = {}, kvm_io.size = {}",
                kvm_io.direction, kvm_io.size
            ),
        };
        Ok(VmExit::Io {
            port: kvm_io.port,
            write,
            size: kvm_io.size,
        })
    }
}
