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

mod bindings;
mod vcpu;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;

use libc::{
    EFD_CLOEXEC, EFD_NONBLOCK, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, MS_ASYNC, PROT_EXEC,
    PROT_READ, PROT_WRITE, SIGRTMIN, c_void, eventfd, mmap, msync, munmap, write,
};
use parking_lot::Mutex;
use vmm_runner::host::{
    Cpuid, Error, Hypervisor, IntxSender, MemMapOption, MemPages, MsiSender, Poll, Result,
    SerialConsole, Tap, Vcpu, Vm, VmMemory,
};

use crate::ffi;
use crate::serial::HostSerialConsole;
use crate::tap::{HostPoll, HostTap};
use bindings::{
    KVM_API_VERSION, KVM_CAP_IRQFD, KVM_CAP_NR_MEMSLOTS, KVM_CAP_SIGNAL_MSI, KVM_MAX_CPUID_ENTRIES,
    KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmEncRegion, KvmIrqfd, KvmMemFlag, KvmMsi,
    KvmUserspaceMemoryRegion, kvm_check_extension, kvm_create_irqchip, kvm_create_vcpu,
    kvm_create_vm, kvm_get_api_version, kvm_get_supported_cpuid, kvm_get_vcpu_mmap_size, kvm_irqfd,
    kvm_memory_encrypt_reg_region, kvm_memory_encrypt_unreg_region, kvm_set_identity_map_addr,
    kvm_set_tss_addr, kvm_set_user_memory_region, kvm_signal_msi,
};
use vcpu::{KvmRunBlock, KvmVcpu};

#[derive(Debug)]
pub struct Kvm {
    fd: OwnedFd,
}

extern "C" fn sigrtmin_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}

impl Kvm {
    pub fn new() -> Result<Self, Error> {
        let kvm_file = File::open("/dev/kvm")?;
        let kvm_fd = OwnedFd::from(kvm_file);
        let version = unsafe { kvm_get_api_version(&kvm_fd) }?;
        if version != KVM_API_VERSION {
            return Err(Error::LackCap {
                cap: format!("current KVM API version {version}, need {KVM_API_VERSION}"),
            });
        }
        let mut action: libc::sigaction = unsafe { transmute([0u8; size_of::<libc::sigaction>()]) };
        action.sa_flags = libc::SA_SIGINFO;
        action.sa_sigaction = sigrtmin_handler as *const () as _;
        ffi!(unsafe { libc::sigfillset(&mut action.sa_mask) })?;
        ffi!(unsafe { libc::sigaction(SIGRTMIN(), &action, null_mut()) })?;
        Ok(Kvm { fd: kvm_fd })
    }
}

impl Hypervisor for Kvm {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error> {
        let vcpu_mmap_size = unsafe { kvm_get_vcpu_mmap_size(&self.fd) }? as usize;
        let vm_fd = unsafe { kvm_create_vm(&self.fd, 0) }?;
        let fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        let kvm_vm = KvmVm {
            fd: Arc::new(fd),
            vcpu_mmap_size,
            memory_created: false,
            vcpu_threads: Mutex::new(BTreeMap::new()),
        };
        unsafe { kvm_create_irqchip(&kvm_vm.fd) }?;
        // TODO should be in parameters
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_tss_addr(&kvm_vm.fd, 0xf000_0000) }?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_identity_map_addr(&kvm_vm.fd, &0xf000_3000) }?;
        Ok(Box::new(kvm_vm))
    }

    #[cfg(target_arch = "x86_64")]
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error> {
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: KVM_MAX_CPUID_ENTRIES as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        unsafe { kvm_get_supported_cpuid(&self.fd, &mut kvm_cpuid2) }?;
        let cpuids = kvm_cpuid2.entries[0..kvm_cpuid2.nent as usize]
            .iter()
            .map(|e| Cpuid {
                func: e.function,
                index: if e.flags.contains(KvmCpuid2Flag::SIGNIFCANT_INDEX) {
                    Some(e.index)
                } else {
                    None
                },
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
            })
            .collect::<Vec<_>>();
        Ok(cpuids)
    }
}

#[derive(Debug)]
pub struct KvmMemPages {
    addr: NonNull<c_void>,
    len: usize,
}

unsafe impl Send for KvmMemPages {}
unsafe impl Sync for KvmMemPages {}

impl KvmMemPages {
    pub fn new_anon(size: usize) -> std::io::Result<Self> {
        let prot = PROT_WRITE | PROT_READ | PROT_EXEC;
        let addr = unsafe { mmap(null_mut(), size, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) };
        if addr == MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let addr = NonNull::new(addr).expect("address from mmap() should not be null");
        Ok(Self { addr, len: size })
    }
}

impl Drop for KvmMemPages {
    fn drop(&mut self) {
        let ret = unsafe { munmap(self.addr.as_ptr(), self.len) };
        if ret != 0 {
            log::error!("munmap({:p}, {:x}) = {:x}", self.addr, self.len, ret);
        } else {
            log::info!("munmap({:p}, {:x}) = {:x}, done", self.addr, self.len, ret);
        }
    }
}

impl MemPages for KvmMemPages {
    fn addr(&self) -> usize {
        self.addr.as_ptr() as usize
    }

    fn size(&self) -> usize {
        self.len
    }

    fn sync(&self) -> std::io::Result<()> {
        ffi!(unsafe { msync(self.addr.as_ptr(), self.len, MS_ASYNC) })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Pthread(libc::pthread_t);

unsafe impl Send for Pthread {}
unsafe impl Sync for Pthread {}

#[derive(Debug)]
pub struct KvmVm {
    fd: Arc<OwnedFd>,
    vcpu_mmap_size: usize,
    memory_created: bool,
    vcpu_threads: Mutex<BTreeMap<u32, Pthread>>,
}

#[derive(Debug)]
pub struct KvmMemory {
    fd: Arc<OwnedFd>,
}

impl VmMemory for KvmMemory {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
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
            guest_phys_addr: gpa,
            memory_size: size as _,
            userspace_addr: hva as _,
            flags,
        };
        unsafe { kvm_set_user_memory_region(&self.fd, &region) }?;
        Ok(())
    }

    fn unmap(&self, slot: u32, gpa: u64, _size: usize) -> Result<(), Error> {
        let flags = KvmMemFlag::empty();
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa,
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

    fn register_encrypted_range(&self, range: &[u8]) -> Result<()> {
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_reg_region(&self.fd, &region) }?;
        Ok(())
    }

    fn deregister_encrypted_range(&self, range: &[u8]) -> Result<()> {
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_unreg_region(&self.fd, &region) }?;
        Ok(())
    }

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
        Ok(Arc::new(KvmMemPages::new_anon(size)?))
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
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error> {
        let vcpu_fd = unsafe { kvm_create_vcpu(&self.fd, id) }?;
        let kvm_run = unsafe { KvmRunBlock::new(vcpu_fd, self.vcpu_mmap_size) }?;
        self.vcpu_threads
            .lock()
            .insert(id, Pthread(unsafe { libc::pthread_self() }));
        Ok(Box::new(KvmVcpu {
            fd: unsafe { OwnedFd::from_raw_fd(vcpu_fd) },
            kvm_run,
        }))
    }

    fn stop_vcpu(&self, id: u32) -> Result<(), Error> {
        if let Some(&Pthread(pthread)) = self.vcpu_threads.lock().get(&id) {
            ffi!(unsafe { libc::pthread_kill(pthread, SIGRTMIN()) })?;
        }
        Ok(())
    }

    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error> {
        if self.memory_created {
            Err(Error::CreatingMultipleMemory)
        } else {
            let kvm_memory = KvmMemory {
                fd: self.fd.clone(),
            };
            self.memory_created = true;
            Ok(Box::new(kvm_memory))
        }
    }

    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error> {
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
        Ok(Box::new(KvmIntxSender {
            event_fd: unsafe { OwnedFd::from_raw_fd(event_fd) },
        }))
    }

    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error> {
        if !self.check_extension(KVM_CAP_SIGNAL_MSI)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_SIGNAL_MSI".to_string(),
            })?;
        }
        Ok(Box::new(KvmMsiSender {
            vm_fd: self.fd.clone(),
        }))
    }

    fn create_serial_console(&self) -> std::io::Result<Box<dyn SerialConsole>> {
        Ok(Box::new(HostSerialConsole::new()?))
    }

    fn create_tap(&self, if_name: Option<&str>) -> std::io::Result<Box<dyn Tap>> {
        Ok(Box::new(HostTap::new(if_name)?))
    }

    fn create_poll(&self) -> std::io::Result<Box<dyn Poll>> {
        Ok(Box::new(HostPoll::new()?))
    }
}
