// Copyright 2025 Google LLC
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

use std::ptr::null_mut;

use assert_matches::assert_matches;
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, mmap};

use super::*;
use crate::ffi;
use crate::hv::kvm::KvmConfig;
use crate::hv::{Hypervisor, Kvm, MemMapOption, VmConfig};

#[test]
#[cfg_attr(not(feature = "test-hv"), ignore)]
fn test_mem_map() {
    let kvm = Kvm::new(KvmConfig::default()).unwrap();
    let vm_config = VmConfig { coco: None };
    let mut vm = kvm.create_vm(&vm_config).unwrap();
    let vm_memory = vm.create_vm_memory().unwrap();

    let prot = PROT_WRITE | PROT_READ | PROT_EXEC;
    let flag = MAP_ANONYMOUS | MAP_PRIVATE;
    let user_mem = ffi!(
        unsafe { mmap(null_mut(), 0x1000, prot, flag, -1, 0,) },
        MAP_FAILED
    )
    .unwrap();
    let option_no_write = MemMapOption {
        read: false,
        write: true,
        exec: true,
        log_dirty: true,
    };
    assert_matches!(
        vm_memory.mem_map(0x0, 0x1000, user_mem as usize, option_no_write),
        Err(Error::KvmErr { .. })
    );
    let option_no_exec = MemMapOption {
        read: false,
        write: true,
        exec: true,
        log_dirty: true,
    };
    assert_matches!(
        vm_memory.mem_map(0x0, 0x1000, user_mem as usize, option_no_exec),
        Err(Error::KvmErr { .. })
    );
    let option = MemMapOption {
        read: true,
        write: false,
        exec: true,
        log_dirty: true,
    };
    vm_memory
        .mem_map(0x0, 0x1000, user_mem as usize, option)
        .unwrap();
}
