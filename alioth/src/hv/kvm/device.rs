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

use std::mem::{MaybeUninit, size_of_val};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

use snafu::ResultExt;

use crate::hv::kvm::kvm_error;
use crate::hv::{KvmError, Result};
use crate::sys::kvm::{
    KvmCreateDevice, KvmDevType, KvmDeviceAttr, kvm_create_device, kvm_get_device_attr,
    kvm_set_device_attr,
};

#[derive(Debug)]
pub(super) struct KvmDevice(pub OwnedFd);

impl KvmDevice {
    pub fn new(vm_fd: &impl AsFd, type_: KvmDevType) -> Result<KvmDevice, KvmError> {
        let mut create_device = KvmCreateDevice {
            type_,
            fd: 0,
            flags: 0,
        };
        unsafe { kvm_create_device(vm_fd, &mut create_device) }
            .context(kvm_error::CreateDevice { type_ })?;
        Ok(KvmDevice(unsafe { OwnedFd::from_raw_fd(create_device.fd) }))
    }
}

impl AsFd for KvmDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl KvmDevice {
    pub fn set_attr<T>(&self, group: u32, attr: u64, val: &T) -> Result<(), KvmError> {
        let attr = KvmDeviceAttr {
            group,
            attr,
            addr: if size_of_val(val) == 0 {
                0
            } else {
                val as *const _ as _
            },
            _flags: 0,
        };
        unsafe { kvm_set_device_attr(self, &attr) }.context(kvm_error::DeviceAttr)?;
        Ok(())
    }

    pub fn get_attr<T>(&self, group: u32, attr: u64) -> Result<T, KvmError> {
        let mut val = MaybeUninit::uninit();
        let attr = KvmDeviceAttr {
            group,
            attr,
            addr: val.as_mut_ptr() as _,
            _flags: 0,
        };
        unsafe { kvm_get_device_attr(self, &attr) }.context(kvm_error::DeviceAttr)?;
        Ok(unsafe { val.assume_init() })
    }
}
