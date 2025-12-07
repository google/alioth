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

#[path = "vcpu/vcpu.rs"]
mod vcpu;
mod vm;

use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::os::raw::c_void;

use crate::hv::{Hypervisor, Result, VmConfig};
use crate::sys::os::os_release;

use self::vm::HvfVm;

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct HvReturn(i32);

impl Display for HvReturn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let msg = match self.0 & 0xff {
            0x01 => "Error",
            0x02 => "Busy",
            0x03 => "Bad argument",
            0x04 => "Illegal guest state",
            0x05 => "No resources",
            0x06 => "No device",
            0x07 => "Denied",
            0x0f => "Unsupported",
            _ => "Unknown",
        };
        write!(f, "{msg} {:#x}", self.0 as u32)
    }
}

impl std::error::Error for HvReturn {}

fn check_ret(ret: i32) -> std::io::Result<()> {
    if ret == 0 {
        return Ok(());
    }
    let kind = match (ret as u32) & 0xff {
        0x02 => ErrorKind::ResourceBusy,
        0x03 => ErrorKind::InvalidInput,
        0x05 => ErrorKind::NotFound,
        0x07 => ErrorKind::PermissionDenied,
        0x0f => ErrorKind::Unsupported,
        _ => ErrorKind::Other,
    };
    Err(std::io::Error::new(kind, HvReturn(ret)))
}

#[derive(Debug)]
struct OsObject {
    addr: usize,
}

impl Drop for OsObject {
    fn drop(&mut self) {
        let ptr = self.addr as *mut c_void;
        unsafe { os_release(ptr) };
    }
}

#[derive(Debug)]
pub struct Hvf {}

impl Hypervisor for Hvf {
    type Vm = HvfVm;

    fn create_vm(&self, _config: &VmConfig) -> Result<Self::Vm> {
        HvfVm::new()
    }
}
