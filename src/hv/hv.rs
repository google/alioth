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

mod bindings;
mod ioctls;
pub mod vcpu;
pub mod vm;

use std::fmt::Debug;
use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{FromRawFd, OwnedFd};
use std::ptr::null_mut;
use std::sync::Arc;

use thiserror::Error;

use crate::ffi;
use crate::hv::arch::Cpuid;
use bindings::{KVM_API_VERSION, KVM_MAX_CPUID_ENTRIES, KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2};
use ioctls::{
    kvm_create_irqchip, kvm_create_vm, kvm_get_api_version, kvm_get_supported_cpuid,
    kvm_get_vcpu_mmap_size, kvm_set_identity_map_addr, kvm_set_tss_addr,
};
use libc::SIGRTMIN;

pub use vcpu::Vcpu;
pub use vm::{IntxSender, MsiSender, Vm, VmMemory};

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid memory map option for {hypervisor}: {option:?}")]
    MemMapOption {
        option: MemMapOption,
        hypervisor: &'static str,
    },
    #[error("failed to open /dev/kvm: {source} (note: ensure /dev/kvm exists and you have permission to access it, e.g. member of 'kvm' group or root)")]
    KvmOpen {
        #[source]
        source: std::io::Error,
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
        let kvm_file = File::open("/dev/kvm").map_err(|source| Error::KvmOpen { source })?;
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

    pub fn create_vm(&self) -> Result<Vm, Error> {
        let vcpu_mmap_size = unsafe { kvm_get_vcpu_mmap_size(&self.fd) }? as usize;
        let vm_fd = unsafe { kvm_create_vm(&self.fd, 0) }?;
        let fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        let vm = Vm {
            fd: Arc::new(fd),
            vcpu_mmap_size,
            memory_created: false,
        };
        unsafe { kvm_create_irqchip(&vm.fd) }?;
        // TODO should be in parameters
        unsafe { kvm_set_tss_addr(&vm.fd, 0xf000_0000) }?;
        unsafe { kvm_set_identity_map_addr(&vm.fd, &0xf000_3000) }?;
        Ok(vm)
    }

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_supported_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut kvm_cpuid_exist = false;
        let supported_cpuids = kvm.get_supported_cpuids().unwrap();
        for cpuid in &supported_cpuids {
            if cpuid.func == 0x4000_0000
                && cpuid.ebx.to_le_bytes() == *b"KVMK"
                && cpuid.ecx.to_le_bytes() == *b"VMKV"
                && cpuid.edx.to_le_bytes() == *b"M\0\0\0"
            {
                kvm_cpuid_exist = true;
            }
        }
        assert!(kvm_cpuid_exist);
    }
}
