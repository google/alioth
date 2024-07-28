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

mod bindings;
#[cfg(target_arch = "aarch64")]
mod device;
mod ioctls;
#[path = "sev/sev.rs"]
mod sev;
#[path = "vcpu/vcpu.rs"]
mod vcpu;
#[path = "vm/vm.rs"]
mod vm;
mod vmentry;
mod vmexit;

use std::collections::HashMap;
use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use parking_lot::lock_api::RwLock;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_aco::Help;
use snafu::{ResultExt, Snafu};

use crate::errors::{trace_error, DebugTrace};
use crate::ffi;
#[cfg(target_arch = "x86_64")]
use crate::hv::Cpuid;
use crate::hv::{error, Hypervisor, MemMapOption, Result, VmConfig};

#[cfg(target_arch = "aarch64")]
use bindings::KvmDevType;
use bindings::KVM_API_VERSION;
#[cfg(target_arch = "x86_64")]
use bindings::{KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KVM_MAX_CPUID_ENTRIES};
#[cfg(target_arch = "x86_64")]
use ioctls::kvm_get_supported_cpuid;
use ioctls::{kvm_create_vm, kvm_get_api_version, kvm_get_vcpu_mmap_size};
use libc::SIGRTMIN;
use vm::{KvmVm, VmInner};

#[trace_error]
#[derive(DebugTrace, Snafu)]
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
    #[cfg(target_arch = "aarch64")]
    #[snafu(display("Failed to create in-kernel device {type_:?}"))]
    CreateDevice {
        type_: KvmDevType,
        error: std::io::Error,
    },
    #[cfg(target_arch = "aarch64")]
    #[snafu(display("Failed to configure device attributes"))]
    DeviceAttr { error: std::io::Error },
}

#[derive(Debug)]
pub struct Kvm {
    fd: OwnedFd,
    #[cfg(target_arch = "x86_64")]
    config: KvmConfig,
}

#[derive(Debug, Deserialize, Default, Clone, Help)]
pub struct KvmConfig {
    /// Path to the KVM device. [default: /dev/kvm]
    pub dev_kvm: Option<PathBuf>,
    /// Path to the AMD SEV device. [default: /dev/sev]
    #[cfg(target_arch = "x86_64")]
    pub dev_sev: Option<PathBuf>,
}

extern "C" fn sigrtmin_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}

impl Kvm {
    pub fn new(config: KvmConfig) -> Result<Self> {
        let path = match &config.dev_kvm {
            Some(dev_kvm) => dev_kvm.as_path(),
            None => Path::new("/dev/kvm"),
        };
        let kvm_file = File::open(path).context(kvm_error::OpenFile { path })?;
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
        Ok(Kvm {
            fd: kvm_fd,
            #[cfg(target_arch = "x86_64")]
            config,
        })
    }
}

impl Hypervisor for Kvm {
    type Vm = KvmVm;

    fn create_vm(&self, config: &VmConfig) -> Result<Self::Vm> {
        let vcpu_mmap_size =
            unsafe { kvm_get_vcpu_mmap_size(&self.fd) }.context(error::CreateVm)? as usize;
        let kvm_vm_type = Self::determine_vm_type(config)?;
        let vm_fd = unsafe { kvm_create_vm(&self.fd, kvm_vm_type) }.context(error::CreateVm)?;
        let fd = unsafe { OwnedFd::from_raw_fd(vm_fd) };
        #[cfg(target_arch = "x86_64")]
        let kvm_vm_arch = self.create_vm_arch(config)?;
        let memfd = self.create_guest_memfd(config, &fd)?;
        let kvm_vm = KvmVm {
            vm: Arc::new(VmInner {
                fd,
                memfd,
                ioeventfds: Mutex::new(HashMap::new()),
                msi_table: RwLock::new(HashMap::new()),
                next_msi_gsi: AtomicU32::new(0),
                pin_map: AtomicU32::new(0),
                #[cfg(target_arch = "x86_64")]
                arch: kvm_vm_arch,
            }),
            vcpu_mmap_size,
            memory_created: false,
        };
        self.vm_init_arch(config, &kvm_vm)?;
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
