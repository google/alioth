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

use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::AtomicU32;

use snafu::ResultExt;

use crate::arch::sev::{SnpPageType, SnpPolicy};
use crate::hv::kvm::ioctls::kvm_memory_encrypt_op;
use crate::hv::kvm::sev::bindings::{
    KvmSevCmd, KvmSevLaunchMeasure, KvmSevLaunchStart, KvmSevLaunchUpdateData,
    KvmSevSnpLaunchFinish, KvmSevSnpLaunchStart, KvmSevSnpLaunchUpdate, KVM_SEV_LAUNCH_FINISH,
    KVM_SEV_LAUNCH_MEASURE, KVM_SEV_LAUNCH_START, KVM_SEV_LAUNCH_UPDATE_DATA,
    KVM_SEV_LAUNCH_UPDATE_VMSA, KVM_SEV_SNP_LAUNCH_FINISH, KVM_SEV_SNP_LAUNCH_START,
    KVM_SEV_SNP_LAUNCH_UPDATE,
};
use crate::hv::kvm::sev::SevFd;
use crate::hv::kvm::{kvm_error, KvmError, KvmVm};
use crate::hv::Result;

#[derive(Debug)]
pub struct VmArch {
    pub sev_fd: Option<SevFd>,
    pub pin_map: AtomicU32,
}

impl KvmVm {
    pub fn sev_op<T>(&self, cmd: u32, data: Option<&mut T>) -> Result<(), KvmError> {
        let Some(sev_fd) = &self.vm.arch.sev_fd else {
            unreachable!("SevFd is not initialized")
        };
        let mut req = KvmSevCmd {
            sev_fd: sev_fd.as_fd().as_raw_fd() as u32,
            data: match data {
                Some(p) => p as *mut T as _,
                None => 0,
            },
            id: cmd,
            error: 0,
        };
        unsafe { kvm_memory_encrypt_op(&self.vm, &mut req) }.context(kvm_error::SevCmd)?;
        Ok(())
    }

    pub fn kvm_sev_launch_start(&self, policy: u32) -> Result<()> {
        let mut start = KvmSevLaunchStart {
            policy,
            ..Default::default()
        };
        self.sev_op(KVM_SEV_LAUNCH_START, Some(&mut start))?;
        Ok(())
    }

    pub fn kvm_sev_launch_update_data(&self, range: &mut [u8]) -> Result<()> {
        let mut update_data = KvmSevLaunchUpdateData {
            uaddr: range.as_mut_ptr() as u64,
            len: range.len() as u32,
        };
        self.sev_op(KVM_SEV_LAUNCH_UPDATE_DATA, Some(&mut update_data))?;
        Ok(())
    }

    pub fn kvm_sev_launch_update_vmsa(&self) -> Result<()> {
        self.sev_op::<()>(KVM_SEV_LAUNCH_UPDATE_VMSA, None)?;
        Ok(())
    }

    pub fn kvm_sev_launch_measure(&self) -> Result<Vec<u8>> {
        let mut empty = KvmSevLaunchMeasure { uaddr: 0, len: 0 };
        let _ = self.sev_op(KVM_SEV_LAUNCH_MEASURE, Some(&mut empty));
        assert_ne!(empty.len, 0);
        let mut buf = vec![0u8; empty.len as usize];
        let mut measure = KvmSevLaunchMeasure {
            uaddr: buf.as_mut_ptr() as u64,
            len: buf.len() as u32,
        };
        self.sev_op(KVM_SEV_LAUNCH_MEASURE, Some(&mut measure))?;
        Ok(buf)
    }

    pub fn kvm_sev_launch_finish(&self) -> Result<()> {
        self.sev_op::<()>(KVM_SEV_LAUNCH_FINISH, None)?;
        Ok(())
    }

    pub fn kvm_snp_launch_start(&self, policy: SnpPolicy) -> Result<()> {
        let mut start = KvmSevSnpLaunchStart {
            policy: policy.0,
            ..Default::default()
        };
        self.sev_op(KVM_SEV_SNP_LAUNCH_START, Some(&mut start))?;
        Ok(())
    }

    pub fn kvm_snp_launch_update(
        &self,
        range: &mut [u8],
        gpa: u64,
        type_: SnpPageType,
    ) -> Result<()> {
        let mut update = KvmSevSnpLaunchUpdate {
            uaddr: range.as_mut_ptr() as _,
            len: range.len() as _,
            gfn_start: gpa >> 12,
            type_: type_ as _,
            ..Default::default()
        };
        self.sev_op(KVM_SEV_SNP_LAUNCH_UPDATE, Some(&mut update))?;
        Ok(())
    }

    pub fn kvm_snp_launch_finish(&self) -> Result<()> {
        let mut finish = KvmSevSnpLaunchFinish::default();
        self.sev_op(KVM_SEV_SNP_LAUNCH_FINISH, Some(&mut finish))?;
        Ok(())
    }
}
