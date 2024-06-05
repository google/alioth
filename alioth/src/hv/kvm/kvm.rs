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
mod ioctls;
#[path = "sev/sev.rs"]
mod sev;
#[path = "vcpu/vcpu.rs"]
mod vcpu;
mod vm;
mod vmentry;
mod vmexit;

use std::collections::HashMap;
use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use crate::ffi;
#[cfg(target_arch = "x86_64")]
use crate::hv::Cpuid;
use crate::hv::{Error, Hypervisor};
use bindings::{KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KVM_API_VERSION, KVM_MAX_CPUID_ENTRIES};
use ioctls::{kvm_create_irqchip, kvm_create_vm, kvm_get_api_version, kvm_get_vcpu_mmap_size};
use parking_lot::lock_api::RwLock;
use parking_lot::Mutex;
use serde::Deserialize;

use crate::hv::{Coco, VmConfig};
#[cfg(target_arch = "x86_64")]
use ioctls::{kvm_get_supported_cpuid, kvm_set_identity_map_addr, kvm_set_tss_addr};
use libc::SIGRTMIN;
use sev::bindings::{KVM_SEV_ES_INIT, KVM_SEV_INIT};
use sev::SevFd;
use vm::{KvmVm, VmInner};

#[derive(Debug)]
pub struct Kvm {
    fd: OwnedFd,
    config: KvmConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct KvmConfig {
    #[serde(default)]
    pub dev_kvm: Option<PathBuf>,
    #[serde(default)]
    pub dev_sev: Option<PathBuf>,
}

extern "C" fn sigrtmin_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}

impl Kvm {
    pub fn new(config: KvmConfig) -> Result<Self, Error> {
        let kvm_file = match &config.dev_kvm {
            Some(dev_kvm) => File::open(dev_kvm),
            None => File::open("/dev/kvm"),
        }?;
        let kvm_fd = OwnedFd::from(kvm_file);
        let version = unsafe { kvm_get_api_version(&kvm_fd) }?;
        if version != KVM_API_VERSION {
            return Err(Error::LackCap {
                cap: format!("current KVM API version {version}, need {KVM_API_VERSION}"),
            });
        }
        let mut action: libc::sigaction = unsafe { transmute([0u8; size_of::<libc::sigaction>()]) };
        action.sa_flags = libc::SA_SIGINFO;
        action.sa_sigaction = sigrtmin_handler as _;
        ffi!(unsafe { libc::sigfillset(&mut action.sa_mask) })?;
        ffi!(unsafe { libc::sigaction(SIGRTMIN(), &action, null_mut()) })?;
        Ok(Kvm { fd: kvm_fd, config })
    }
}

impl Hypervisor for Kvm {
    type Vm = KvmVm;

    fn create_vm(&self, config: &VmConfig) -> Result<Self::Vm, Error> {
        let vcpu_mmap_size = unsafe { kvm_get_vcpu_mmap_size(&self.fd) }? as usize;
        let vm_fd = unsafe { kvm_create_vm(&self.fd, 0) }?;
        let fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        let sev_fd = if let Some(cv) = &config.coco {
            match cv {
                Coco::AmdSev { .. } => Some(match &self.config.dev_sev {
                    Some(dev_sev) => SevFd::new(dev_sev),
                    None => SevFd::new("/dev/sev"),
                }?),
            }
        } else {
            None
        };
        let kvm_vm = KvmVm {
            vm: Arc::new(VmInner {
                fd,
                sev_fd,
                ioeventfds: Mutex::new(HashMap::new()),
                msi_table: RwLock::new(HashMap::new()),
                next_msi_gsi: AtomicU32::new(0),
            }),
            vcpu_mmap_size,
            memory_created: false,
        };
        if kvm_vm.vm.sev_fd.is_some() {
            match config.coco.as_ref().unwrap() {
                Coco::AmdSev { policy } => {
                    if policy.es() {
                        kvm_vm.sev_op::<()>(KVM_SEV_ES_INIT, None)?;
                    } else {
                        kvm_vm.sev_op::<()>(KVM_SEV_INIT, None)?;
                    }
                }
            }
        }
        unsafe { kvm_create_irqchip(&kvm_vm.vm) }?;
        // TODO should be in parameters
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_tss_addr(&kvm_vm.vm, 0xf000_0000) }?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_identity_map_addr(&kvm_vm.vm, &0xf000_3000) }?;
        Ok(kvm_vm)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_get_supported_cpuid() {
        let kvm = Kvm::new(KvmConfig::default()).unwrap();
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
