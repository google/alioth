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

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::thread::JoinHandleExt;
use std::sync::Arc;
use std::thread::JoinHandle;

use libc::{eventfd, write, EFD_CLOEXEC, EFD_NONBLOCK, SIGRTMIN};

use crate::ffi;
use crate::hv::kvm::bindings::{
    KvmIrqfd, KvmMemFlag, KvmMsi, KvmUserspaceMemoryRegion, KVM_CAP_IRQFD, KVM_CAP_NR_MEMSLOTS,
    KVM_CAP_SIGNAL_MSI,
};
use crate::hv::kvm::ioctls::{
    kvm_check_extension, kvm_create_vcpu, kvm_irqfd, kvm_set_user_memory_region, kvm_signal_msi,
};
use crate::hv::kvm::vcpu::{KvmRunBlock, KvmVcpu};
use crate::hv::{Error, IntxSender, MemMapOption, MsiSender, Result, Vm, VmMemory};

pub struct KvmVm {
    pub(super) fd: Arc<OwnedFd>,
    pub(super) vcpu_mmap_size: usize,
    pub(super) memory_created: bool,
}

#[derive(Debug)]
pub struct KvmMemory {
    pub(super) fd: Arc<OwnedFd>,
}

impl VmMemory for KvmMemory {
    fn mem_map(
        &self,
        slot: u32,
        gpa: usize,
        size: usize,
        hva: usize,
        option: MemMapOption,
    ) -> Result<(), Error> {
        let mut flags = KvmMemFlag::empty();
        if !option.read || !option.exec {
            return Err(Error::MemMapOption {
                option,
                hypervisor: "kvm",
            });
        }
        if !option.write {
            flags |= KvmMemFlag::READONLY;
        }
        if option.log_dirty {
            flags |= KvmMemFlag::LOG_DIRTY_PAGES;
        }
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa as _,
            memory_size: size as _,
            userspace_addr: hva as _,
            flags,
        };
        unsafe { kvm_set_user_memory_region(&self.fd, &region) }?;
        Ok(())
    }

    fn unmap(&self, slot: u32, gpa: usize, _size: usize) -> Result<(), Error> {
        let flags = KvmMemFlag::empty();
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa as _,
            memory_size: 0,
            userspace_addr: 0,
            flags,
        };
        unsafe { kvm_set_user_memory_region(&self.fd, &region) }?;
        Ok(())
    }

    fn max_mem_slots(&self) -> Result<u32, Error> {
        let ret = unsafe { kvm_check_extension(&self.fd, KVM_CAP_NR_MEMSLOTS) }?;
        Ok(ret as u32)
    }
}

#[derive(Debug)]
pub struct KvmIntxSender {
    event_fd: OwnedFd,
}

impl IntxSender for KvmIntxSender {
    fn send(&self) -> Result<(), Error> {
        ffi!(unsafe { write(self.event_fd.as_raw_fd(), &1u64 as *const _ as _, 8) })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct KvmMsiSender {
    vm_fd: Arc<OwnedFd>,
}

impl MsiSender for KvmMsiSender {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        let kvm_msi = KvmMsi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            ..Default::default()
        };
        unsafe { kvm_signal_msi(&self.vm_fd, &kvm_msi) }?;
        Ok(())
    }
}

impl KvmVm {
    fn check_extension(&self, id: u64) -> Result<bool, Error> {
        let ret = unsafe { kvm_check_extension(&self.fd, id) }?;
        Ok(ret == 1)
    }
}

impl Vm for KvmVm {
    type Vcpu = KvmVcpu;
    type IntxSender = KvmIntxSender;
    type MsiSender = KvmMsiSender;
    type Memory = KvmMemory;

    fn create_vcpu(&self, id: u32) -> Result<Self::Vcpu, Error> {
        let vcpu_fd = unsafe { kvm_create_vcpu(&self.fd, id) }?;
        let kvm_run = unsafe { KvmRunBlock::new(vcpu_fd, self.vcpu_mmap_size) }?;
        Ok(KvmVcpu {
            fd: unsafe { OwnedFd::from_raw_fd(vcpu_fd) },
            kvm_run,
        })
    }

    fn stop_vcpu<T>(_id: u32, handle: &JoinHandle<T>) -> Result<(), Error> {
        ffi!(unsafe { libc::pthread_kill(handle.as_pthread_t(), SIGRTMIN()) })?;
        Ok(())
    }

    fn create_vm_memory(&mut self) -> Result<Self::Memory, Error> {
        if self.memory_created {
            Err(Error::CreatingMultipleMemory)
        } else {
            let kvm_memory = KvmMemory {
                fd: self.fd.clone(),
            };
            self.memory_created = true;
            Ok(kvm_memory)
        }
    }

    fn create_intx_sender(&self, pin: u8) -> Result<Self::IntxSender, Error> {
        if !self.check_extension(KVM_CAP_IRQFD)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_IRQFD".to_string(),
            })?;
        }
        let event_fd = ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) })?;
        let request = KvmIrqfd {
            fd: event_fd as u32,
            gsi: pin as u32,
            ..Default::default()
        };
        unsafe { kvm_irqfd(&self.fd, &request) }?;
        Ok(KvmIntxSender {
            event_fd: unsafe { OwnedFd::from_raw_fd(event_fd) },
        })
    }

    fn create_msi_sender(&self) -> Result<Self::MsiSender> {
        if !self.check_extension(KVM_CAP_SIGNAL_MSI)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_SIGNAL_MSI".to_string(),
            })?;
        }
        Ok(KvmMsiSender {
            vm_fd: self.fd.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use std::ptr::null_mut;

    use libc::{mmap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};

    use super::*;
    use crate::ffi;
    use crate::hv::{Hypervisor, Kvm, MemMapOption};

    #[test]
    fn test_mem_map() {
        let kvm = Kvm::new().unwrap();
        let mut vm = kvm.create_vm().unwrap();
        let vm_memory = vm.create_vm_memory().unwrap();
        assert_matches!(vm_memory.max_mem_slots(), Ok(1..));
        let prot = PROT_WRITE | PROT_READ | PROT_EXEC;
        let flag = MAP_ANONYMOUS | MAP_PRIVATE;
        let user_mem = ffi!(
            unsafe { mmap(null_mut(), 0x1000, prot, flag, -1, 0,) },
            MAP_FAILED
        )
        .unwrap();
        let option_no_write = MemMapOption {
            read: false,
            write: true,
            exec: true,
            log_dirty: true,
        };
        assert_matches!(
            vm_memory.mem_map(0, 0x0, 0x1000, user_mem as usize, option_no_write),
            Err(Error::MemMapOption {
                option: MemMapOption {
                    read: false,
                    write: true,
                    exec: true,
                    log_dirty: true,
                },
                hypervisor: "kvm"
            })
        );
        let option_no_exec = MemMapOption {
            read: false,
            write: true,
            exec: true,
            log_dirty: true,
        };
        assert_matches!(
            vm_memory.mem_map(0, 0x0, 0x1000, user_mem as usize, option_no_exec),
            Err(Error::MemMapOption {
                option: MemMapOption {
                    read: false,
                    write: true,
                    exec: true,
                    log_dirty: true,
                },
                hypervisor: "kvm"
            })
        );
        let option = MemMapOption {
            read: true,
            write: false,
            exec: true,
            log_dirty: true,
        };
        vm_memory
            .mem_map(0, 0x0, 0x1000, user_mem as usize, option)
            .unwrap();
        vm_memory.mem_map(0, 0x0, 0, 0, option).unwrap();
    }
}
