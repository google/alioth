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

use std::fmt::Debug;
use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::thread::JoinHandleExt;
use std::ptr::null_mut;
use std::sync::Arc;
use std::thread::JoinHandle;

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, SIGRTMIN, eventfd, write};
use thiserror::Error;

use crate::ffi;
use bindings::{
    KVM_API_VERSION, KVM_CAP_IRQFD, KVM_CAP_NR_MEMSLOTS, KVM_CAP_SIGNAL_MSI, KVM_MAX_CPUID_ENTRIES,
    KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmEncRegion, KvmIrqfd, KvmMemFlag, KvmMsi,
    KvmUserspaceMemoryRegion, kvm_check_extension, kvm_create_irqchip, kvm_create_vcpu,
    kvm_create_vm, kvm_get_api_version, kvm_get_supported_cpuid, kvm_get_vcpu_mmap_size, kvm_irqfd,
    kvm_memory_encrypt_reg_region, kvm_memory_encrypt_unreg_region, kvm_set_identity_map_addr,
    kvm_set_tss_addr, kvm_set_user_memory_region, kvm_signal_msi,
};
use vcpu::KvmRunBlock;
pub use vcpu::{KvmVcpu, KvmVcpu as Vcpu};

#[cfg(target_arch = "x86_64")]
pub mod arch {
    use crate::hw::reg::SegAccess;

    #[derive(Debug, Default, Clone)]
    pub struct Cpuid {
        pub func: u32,
        pub index: Option<u32>,
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum Reg {
        Rax,
        Rbx,
        Rcx,
        Rdx,
        Rsi,
        Rdi,
        Rsp,
        Rbp,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        Rip,
        Rflags,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum SReg {
        Cr0,
        Cr2,
        Cr3,
        Cr4,
        Cr8,
        Efer,
        ApicBase,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum SegReg {
        Cs,
        Ds,
        Es,
        Fs,
        Gs,
        Ss,
        Tr,
        Ldtr,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum DtReg {
        Gdtr,
        Idtr,
    }

    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct SegRegVal {
        pub selector: u16,
        pub base: u64,
        pub limit: u32,
        pub access: SegAccess,
    }

    impl SegRegVal {
        pub fn to_desc(&self) -> u64 {
            ((self.base & 0xff00_0000) << (56 - 24))
                | (((self.access.0 as u64) & 0x0000_f0ff) << 40)
                | (((self.limit as u64) & 0x000f_0000) << (48 - 16))
                | ((self.base & 0x00ff_ffff) << 16)
                | ((self.limit as u64) & 0x0000_ffff)
        }
    }

    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct DtRegVal {
        pub base: u64,
        pub limit: u16,
    }
}

#[cfg(target_arch = "x86_64")]
pub use arch::{Cpuid, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};

pub type Hypervisor = Kvm;
pub type Vm = KvmVm;
pub type VmMemory = KvmMemory;

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

    pub fn create_vm(&self) -> Result<KvmVm, Error> {
        let vcpu_mmap_size = unsafe { kvm_get_vcpu_mmap_size(&self.fd) }? as usize;
        let vm_fd = unsafe { kvm_create_vm(&self.fd, 0) }?;
        let fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        let kvm_vm = KvmVm {
            fd: Arc::new(fd),
            vcpu_mmap_size,
            memory_created: false,
        };
        unsafe { kvm_create_irqchip(&kvm_vm.fd) }?;
        // TODO should be in parameters
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_tss_addr(&kvm_vm.fd, 0xf000_0000) }?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_identity_map_addr(&kvm_vm.fd, &0xf000_3000) }?;
        Ok(kvm_vm)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error> {
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

pub struct KvmVm {
    fd: Arc<OwnedFd>,
    vcpu_mmap_size: usize,
    memory_created: bool,
}

#[derive(Debug)]
pub struct KvmMemory {
    fd: Option<Arc<OwnedFd>>,
}

#[cfg(test)]
pub mod test {
    use super::KvmMemory;

    #[allow(non_snake_case)]
    pub fn FakeVmMemory() -> KvmMemory {
        KvmMemory { fd: None }
    }
}

impl KvmMemory {
    pub fn mem_map(
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
        let Some(fd) = &self.fd else {
            return Ok(());
        };
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa as _,
            memory_size: size as _,
            userspace_addr: hva as _,
            flags,
        };
        unsafe { kvm_set_user_memory_region(fd, &region) }?;
        Ok(())
    }

    pub fn unmap(&self, slot: u32, gpa: usize, _size: usize) -> Result<(), Error> {
        let Some(fd) = &self.fd else {
            return Ok(());
        };
        let flags = KvmMemFlag::empty();
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa as _,
            memory_size: 0,
            userspace_addr: 0,
            flags,
        };
        unsafe { kvm_set_user_memory_region(fd, &region) }?;
        Ok(())
    }

    pub fn max_mem_slots(&self) -> Result<u32, Error> {
        let Some(fd) = &self.fd else {
            return Ok(32);
        };
        let ret = unsafe { kvm_check_extension(fd, KVM_CAP_NR_MEMSLOTS) }?;
        Ok(ret as u32)
    }

    pub fn register_encrypted_range(&self, range: &[u8]) -> Result<()> {
        let Some(fd) = &self.fd else {
            return Ok(());
        };
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_reg_region(fd, &region) }?;
        Ok(())
    }

    pub fn deregister_encrypted_range(&self, range: &[u8]) -> Result<()> {
        let Some(fd) = &self.fd else {
            return Ok(());
        };
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_unreg_region(fd, &region) }?;
        Ok(())
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

    pub fn create_vcpu(&self, id: u32) -> Result<KvmVcpu, Error> {
        let vcpu_fd = unsafe { kvm_create_vcpu(&self.fd, id) }?;
        let kvm_run = unsafe { KvmRunBlock::new(vcpu_fd, self.vcpu_mmap_size) }?;
        Ok(KvmVcpu {
            fd: unsafe { OwnedFd::from_raw_fd(vcpu_fd) },
            kvm_run,
        })
    }

    pub fn stop_vcpu<T>(_id: u32, handle: &JoinHandle<T>) -> Result<(), Error> {
        ffi!(unsafe { libc::pthread_kill(handle.as_pthread_t() as _, SIGRTMIN()) })?;
        Ok(())
    }

    pub fn create_vm_memory(&mut self) -> Result<KvmMemory, Error> {
        if self.memory_created {
            Err(Error::CreatingMultipleMemory)
        } else {
            let kvm_memory = KvmMemory {
                fd: Some(self.fd.clone()),
            };
            self.memory_created = true;
            Ok(kvm_memory)
        }
    }

    pub fn create_intx_sender(&self, pin: u8) -> Result<KvmIntxSender, Error> {
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

    pub fn create_msi_sender(&self) -> Result<KvmMsiSender> {
        if !self.check_extension(KVM_CAP_SIGNAL_MSI)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_SIGNAL_MSI".to_string(),
            })?;
        }
        Ok(KvmMsiSender {
            vm_fd: self.fd.clone(),
        })
    }

    pub fn sev_launch_start(&self, _policy: u32) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn sev_launch_update_vmsa(&self) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn sev_launch_update_data(&self, _range: &mut [u8]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn sev_launch_measure(&self) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }

    pub fn sev_launch_finish(&self) -> Result<(), Error> {
        unimplemented!()
    }
}
