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

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, SIGRTMIN, eventfd, write};

use super::bindings::{
    KVM_CAP_IRQFD, KVM_CAP_NR_MEMSLOTS, KVM_CAP_SIGNAL_MSI, KvmEncRegion, KvmIrqfd, KvmMemFlag,
    KvmMsi, KvmUserspaceMemoryRegion,
};
use super::ioctls::{
    kvm_check_extension, kvm_create_vcpu, kvm_irqfd, kvm_memory_encrypt_reg_region,
    kvm_memory_encrypt_unreg_region, kvm_set_user_memory_region, kvm_signal_msi,
};
use super::vcpu::{KvmRunBlock, Vcpu};
use crate::ffi;
use crate::hv::{Error, MemMapOption, Result};

pub struct Vm {
    pub(super) fd: Arc<OwnedFd>,
    pub(super) vcpu_mmap_size: usize,
    pub(super) memory_created: bool,
}

#[derive(Debug)]
pub struct VmMemory {
    pub(super) fd: Arc<OwnedFd>,
    #[cfg(test)]
    pub(super) is_fake: bool,
}

impl VmMemory {
    #[cfg(test)]
    pub fn new_fake() -> Self {
        let file = std::fs::File::open("/dev/null").unwrap();
        Self {
            fd: Arc::new(file.into()),
            is_fake: true,
        }
    }

    pub fn mem_map(
        &self,
        slot: u32,
        gpa: usize,
        size: usize,
        hva: usize,
        option: MemMapOption,
    ) -> Result<(), Error> {
        #[cfg(test)]
        if self.is_fake {
            return Ok(());
        }
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

    pub fn unmap(&self, slot: u32, gpa: usize, _size: usize) -> Result<(), Error> {
        #[cfg(test)]
        if self.is_fake {
            return Ok(());
        }
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

    pub fn max_mem_slots(&self) -> Result<u32, Error> {
        #[cfg(test)]
        if self.is_fake {
            return Ok(u16::MAX as u32);
        }
        let ret = unsafe { kvm_check_extension(&self.fd, KVM_CAP_NR_MEMSLOTS) }?;
        Ok(ret as u32)
    }

    pub fn register_encrypted_range(&self, range: &[u8]) -> Result<()> {
        #[cfg(test)]
        if self.is_fake {
            return Ok(());
        }
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_reg_region(&self.fd, &region) }?;
        Ok(())
    }

    pub fn deregister_encrypted_range(&self, range: &[u8]) -> Result<()> {
        #[cfg(test)]
        if self.is_fake {
            return Ok(());
        }
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_unreg_region(&self.fd, &region) }?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct IntxSender {
    event_fd: OwnedFd,
}

impl IntxSender {
    pub fn send(&self) -> Result<(), Error> {
        ffi!(unsafe { write(self.event_fd.as_raw_fd(), &1u64 as *const _ as _, 8) })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct MsiSender {
    vm_fd: Arc<OwnedFd>,
}

impl MsiSender {
    pub fn send(&self, addr: u64, data: u32) -> Result<()> {
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

impl Vm {
    fn check_extension(&self, id: u64) -> Result<bool, Error> {
        let ret = unsafe { kvm_check_extension(&self.fd, id) }?;
        Ok(ret == 1)
    }

    pub fn create_vcpu(&self, id: u32) -> Result<Vcpu, Error> {
        let vcpu_fd = unsafe { kvm_create_vcpu(&self.fd, id) }?;
        let kvm_run = unsafe { KvmRunBlock::new(vcpu_fd, self.vcpu_mmap_size) }?;
        Ok(Vcpu {
            fd: unsafe { OwnedFd::from_raw_fd(vcpu_fd) },
            kvm_run,
        })
    }

    pub fn stop_vcpu<T>(_id: u32, handle: &JoinHandle<T>) -> Result<(), Error> {
        ffi!(unsafe { libc::pthread_kill(handle.as_pthread_t() as _, SIGRTMIN()) })?;
        Ok(())
    }

    pub fn create_vm_memory(&mut self) -> Result<VmMemory, Error> {
        if self.memory_created {
            Err(Error::CreatingMultipleMemory)
        } else {
            let kvm_memory = VmMemory {
                fd: self.fd.clone(),
                #[cfg(test)]
                is_fake: false,
            };
            self.memory_created = true;
            Ok(kvm_memory)
        }
    }

    pub fn create_intx_sender(&self, pin: u8) -> Result<IntxSender, Error> {
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
        Ok(IntxSender {
            event_fd: unsafe { OwnedFd::from_raw_fd(event_fd) },
        })
    }

    pub fn create_msi_sender(&self) -> Result<MsiSender> {
        if !self.check_extension(KVM_CAP_SIGNAL_MSI)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_SIGNAL_MSI".to_string(),
            })?;
        }
        Ok(MsiSender {
            vm_fd: self.fd.clone(),
        })
    }
}
