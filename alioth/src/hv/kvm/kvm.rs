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

#[cfg(target_arch = "x86_64")]
#[path = "kvm_x86_64.rs"]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod device;
#[cfg(target_arch = "x86_64")]
mod sev;
#[path = "vcpu/vcpu.rs"]
mod vcpu;
#[path = "vm/vm.rs"]
mod vm;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;
#[cfg(target_arch = "x86_64")]
use std::collections::HashMap;
use std::fs::File;
use std::mem::{size_of, transmute};
use std::num::NonZero;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::ptr::null_mut;

use libc::SIGRTMIN;
use serde::Deserialize;
use serde_aco::Help;
use snafu::{ResultExt, Snafu};

#[cfg(target_arch = "x86_64")]
use crate::arch::cpuid::CpuidIn;
use crate::errors::{DebugTrace, trace_error};
use crate::ffi;
use crate::hv::{Hypervisor, MemMapOption, Result, VmConfig, error};
#[cfg(target_arch = "aarch64")]
use crate::sys::kvm::KvmDevType;
use crate::sys::kvm::{KVM_API_VERSION, KvmCap, kvm_check_extension, kvm_get_api_version};

use self::vm::KvmVm;

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
        path: Box<Path>,
        error: std::io::Error,
    },
    #[snafu(display("Invalid memory map option {option:?}"))]
    MmapOption { option: MemMapOption },
    #[snafu(display("Failed to mmap a VCPU fd"))]
    MmapVcpuFd { error: std::io::Error },
    #[snafu(display("Failed to check KVM capability"))]
    CheckCap { error: std::io::Error },
    #[snafu(display("Failed to enable capability {cap:?}"))]
    EnableCap { cap: KvmCap, error: std::io::Error },
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
    #[snafu(display("Failed to configure kvmclock"))]
    KvmClockCtrl { error: std::io::Error },
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
    pub dev_kvm: Option<Box<Path>>,
    /// Path to the AMD SEV device. [default: /dev/sev]
    #[cfg(target_arch = "x86_64")]
    pub dev_sev: Option<Box<Path>>,
}

extern "C" fn sigrtmin_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}

impl Kvm {
    pub fn new(config: KvmConfig) -> Result<Self> {
        let path = match &config.dev_kvm {
            Some(dev_kvm) => dev_kvm,
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
        action.sa_sigaction = sigrtmin_handler as *const () as _;
        ffi!(unsafe { libc::sigfillset(&mut action.sa_mask) }).context(error::SetupSignal)?;
        ffi!(unsafe { libc::sigaction(SIGRTMIN(), &action, null_mut()) })
            .context(error::SetupSignal)?;
        Ok(Kvm {
            fd: kvm_fd,
            #[cfg(target_arch = "x86_64")]
            config,
        })
    }

    pub fn check_extension(&self, id: KvmCap) -> Result<NonZero<i32>> {
        check_extension(&self.fd, id)
    }
}

impl Hypervisor for Kvm {
    type Vm = KvmVm;

    fn create_vm(&self, config: &VmConfig) -> Result<Self::Vm> {
        KvmVm::new(self, config)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_supported_cpuids(&self) -> Result<HashMap<CpuidIn, CpuidResult>> {
        Kvm::get_supported_cpuids(self)
    }
}

fn check_extension(fd: &OwnedFd, id: KvmCap) -> Result<NonZero<i32>> {
    let ret = unsafe { kvm_check_extension(fd, id) }.context(kvm_error::CheckCap)?;
    if let Some(v) = NonZero::new(ret) {
        Ok(v)
    } else {
        error::Capability { cap: id.name() }.fail()
    }
}
