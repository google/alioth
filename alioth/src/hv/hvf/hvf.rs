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
#[path = "vcpu/vcpu.rs"]
mod vcpu;
mod vm;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::ptr::null_mut;

use bindings::hv_vm_create;
use parking_lot::Mutex;
use snafu::ResultExt;

use crate::hv::{error, Hypervisor, Result, VmConfig};

use vm::HvfVm;

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct HvReturn(i32);

impl Display for HvReturn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0 as u32)
    }
}

impl std::error::Error for HvReturn {}

fn check_ret(ret: i32) -> std::io::Result<()> {
    if ret == 0 {
        return Ok(());
    }
    let kind = match (ret as u32) & 0xff {
        3 => std::io::ErrorKind::InvalidInput,
        5 => std::io::ErrorKind::NotFound,
        7 => std::io::ErrorKind::PermissionDenied,
        0xf => std::io::ErrorKind::Unsupported,
        _ => std::io::ErrorKind::Other,
    };
    Err(std::io::Error::new(kind, HvReturn(ret)))
}

#[derive(Debug)]
pub struct Hvf {}

impl Hypervisor for Hvf {
    type Vm = HvfVm;
    fn create_vm(&self, _config: &VmConfig) -> Result<Self::Vm> {
        let ret = unsafe { hv_vm_create(null_mut()) };
        check_ret(ret).context(error::CreateVm)?;
        Ok(HvfVm {
            vcpus: Mutex::new(HashMap::new()),
        })
    }
}
