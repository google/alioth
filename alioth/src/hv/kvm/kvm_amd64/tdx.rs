// Copyright 2026 Google LLC
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

use std::os::fd::OwnedFd;

use snafu::ResultExt;

use crate::hv::{Result, error};
use crate::sys::kvm::{KvmCpuidFeature, kvm_memory_encrypt_op};
use crate::sys::tdx::{KvmTdxCmd, KvmTdxCmdId};

pub fn tdx_op<T>(fd: &OwnedFd, cmd: KvmTdxCmdId, flags: u32, data: Option<&mut T>) -> Result<()> {
    let mut req = KvmTdxCmd {
        id: cmd,
        flags,
        data: data.map(|d| d as *mut _ as _).unwrap_or(0),
        hw_error: 0,
    };
    unsafe { kvm_memory_encrypt_op(fd, &mut req) }.context(error::MemEncrypt)?;
    if req.hw_error != 0 {
        return error::TdxErr { code: req.hw_error }.fail();
    }
    Ok(())
}

pub const SUPPORTED_KVM_FEATURES: u32 = KvmCpuidFeature::NOP_IO_DELAY.bits()
    | KvmCpuidFeature::PV_UNHALT.bits()
    | KvmCpuidFeature::PV_TLB_FLUSH.bits()
    | KvmCpuidFeature::PV_SEND_IPI.bits()
    | KvmCpuidFeature::POLL_CONTROL.bits()
    | KvmCpuidFeature::PV_SCHED_YIELD.bits()
    | KvmCpuidFeature::MSI_EXT_DEST_ID.bits();
