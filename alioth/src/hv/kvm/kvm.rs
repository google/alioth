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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use macros::trace_error;
use parking_lot::lock_api::RwLock;
use parking_lot::Mutex;
use serde::Deserialize;
use snafu::{ResultExt, Snafu};

use crate::ffi;
#[cfg(target_arch = "x86_64")]
use crate::hv::Cpuid;
use crate::hv::{error, Coco, Hypervisor, MemMapOption, Result, VmConfig};

use bindings::{
    KvmCap, KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmCreateGuestMemfd, KvmEnableCap,
    KVM_API_VERSION, KVM_MAX_CPUID_ENTRIES, KVM_X86_DEFAULT_VM, KVM_X86_SNP_VM,
};
use ioctls::{
    kvm_check_extension, kvm_create_guest_memfd, kvm_create_irqchip, kvm_create_vm, kvm_enable_cap,
    kvm_get_api_version, kvm_get_vcpu_mmap_size,
};
#[cfg(target_arch = "x86_64")]
use ioctls::{kvm_get_supported_cpuid, kvm_set_identity_map_addr, kvm_set_tss_addr};
use libc::SIGRTMIN;
use sev::bindings::{KvmSevInit, KVM_SEV_ES_INIT, KVM_SEV_INIT, KVM_SEV_INIT2};
use sev::SevFd;
use vm::{KvmVm, VmInner};

#[trace_error]
#[derive(Snafu)]
#[snafu(module, context(suffix(false)))]
pub enum KvmError {
    #[snafu(display("Failed to update GSI routing table"))]
    GsiRouting { error: std::io::Error },
    #[snafu(display("Failed to allocate a GSI number"))]
    AllocateGsi,
    #[snafu(display("CPUID table too long"))]
    CpuidTableTooLong,
    #[snafu(display("Failed to issue an SEV command"))]
    SevCmd { error: std::io::Error },
    #[snafu(display("SEV command error code {code:#x}"))]
    SevErr { code: u32 },
    #[snafu(display("Failed to get KVM API version"))]
    KvmApi { error: std::io::Error },
    #[snafu(display("Failed to open {path:?}"))]
    OpenFile {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("Invalid memory map option {option:?}"))]
    MmapOption { option: MemMapOption },
    #[snafu(display("Failed to mmap a VCPU fd"))]
    MmapVcpuFd { error: std::io::Error },
    #[snafu(display("Failed to check extension {ext}"))]
    CheckExtension {
        ext: &'static str,
        error: std::io::Error,
    },
    #[snafu(display("Failed to enable capability {cap}"))]
    EnableCap {
        cap: &'static str,
        error: std::io::Error,
    },
    #[snafu(display("Failed to create guest memfd"))]
    GuestMemfd { error: std::io::Error },
}

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
    pub fn new(config: KvmConfig) -> Result<Self> {
        let path = match &config.dev_kvm {
            Some(dev_kvm) => dev_kvm.as_path(),
            None => Path::new("/dev/kvm"),
        };
        let kvm_file = File::open(path).with_context(|_| kvm_error::OpenFile { path })?;
        let kvm_fd = OwnedFd::from(kvm_file);
        let version = unsafe { kvm_get_api_version(&kvm_fd) }.context(kvm_error::KvmApi)?;
        if version != KVM_API_VERSION {
            return Err(error::Capability {
                cap: "KVM_API_VERSION (12)",
            }
            .build());
        }
        let mut action: libc::sigaction = unsafe { transmute([0u8; size_of::<libc::sigaction>()]) };
        action.sa_flags = libc::SA_SIGINFO;
        action.sa_sigaction = sigrtmin_handler as _;
        ffi!(unsafe { libc::sigfillset(&mut action.sa_mask) }).context(error::SetupSignal)?;
        ffi!(unsafe { libc::sigaction(SIGRTMIN(), &action, null_mut()) })
            .context(error::SetupSignal)?;
        Ok(Kvm { fd: kvm_fd, config })
    }
}

impl Hypervisor for Kvm {
    type Vm = KvmVm;

    fn create_vm(&self, config: &VmConfig) -> Result<Self::Vm> {
        let vcpu_mmap_size =
            unsafe { kvm_get_vcpu_mmap_size(&self.fd) }.context(error::CreateVm)? as usize;
        let kvm_vm_type = if let Some(Coco::AmdSnp { .. }) = &config.coco {
            KVM_X86_SNP_VM
        } else {
            KVM_X86_DEFAULT_VM
        };
        let vm_fd = unsafe { kvm_create_vm(&self.fd, kvm_vm_type) }.context(error::CreateVm)?;
        let fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        let sev_fd = if let Some(cv) = &config.coco {
            match cv {
                Coco::AmdSev { .. } | Coco::AmdSnp { .. } => Some(match &self.config.dev_sev {
                    Some(dev_sev) => SevFd::new(dev_sev),
                    None => SevFd::new("/dev/sev"),
                }?),
            }
        } else {
            None
        };
        let memfd = if let Some(Coco::AmdSnp { .. }) = &config.coco {
            let mut request = KvmCreateGuestMemfd {
                size: 1 << 48,
                ..Default::default()
            };
            let ret = unsafe { kvm_create_guest_memfd(&fd, &mut request) }
                .context(kvm_error::GuestMemfd)?;
            Some(unsafe { OwnedFd::from_raw_fd(ret) })
        } else {
            None
        };
        let kvm_vm = KvmVm {
            vm: Arc::new(VmInner {
                fd,
                sev_fd,
                memfd,
                ioeventfds: Mutex::new(HashMap::new()),
                msi_table: RwLock::new(HashMap::new()),
                next_msi_gsi: AtomicU32::new(0),
                pin_map: AtomicU32::new(0),
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
                Coco::AmdSnp { .. } => {
                    let bitmap = unsafe { kvm_check_extension(&kvm_vm.vm, KvmCap::EXIT_HYPERCALL) }
                        .context(kvm_error::CheckExtension {
                            ext: "KVM_CAP_EXIT_HYPERCALL",
                        })?;
                    if bitmap != 0 {
                        let request = KvmEnableCap {
                            cap: KvmCap::EXIT_HYPERCALL,
                            args: [bitmap as _, 0, 0, 0],
                            flags: 0,
                            pad: [0; 64],
                        };
                        unsafe { kvm_enable_cap(&kvm_vm.vm, &request) }.context(
                            kvm_error::EnableCap {
                                cap: "KVM_CAP_EXIT_HYPERCALL",
                            },
                        )?;
                    }
                    let mut init = KvmSevInit::default();
                    kvm_vm.sev_op(KVM_SEV_INIT2, Some(&mut init))?;
                    log::debug!("vm-{}: snp init: {init:#x?}", kvm_vm.vm.as_raw_fd());
                }
            }
        }
        unsafe { kvm_create_irqchip(&kvm_vm.vm) }.context(error::CreateDevice)?;
        // TODO should be in parameters
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_tss_addr(&kvm_vm.vm, 0xf000_0000) }.context(error::SetVmParam)?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_identity_map_addr(&kvm_vm.vm, &0xf000_3000) }
            .context(error::SetVmParam)?;
        Ok(kvm_vm)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>> {
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: KVM_MAX_CPUID_ENTRIES as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        unsafe { kvm_get_supported_cpuid(&self.fd, &mut kvm_cpuid2) }.context(error::GuestCpuid)?;
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
