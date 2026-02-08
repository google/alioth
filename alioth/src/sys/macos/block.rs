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

//! https://clang.llvm.org/docs/Block-ABI-Apple.html

use libc::{c_int, c_ulong, c_void};

use crate::bitflags;

#[repr(C)]
pub struct BlockDescriptor {
    pub reserved: c_ulong,
    pub size: c_ulong,
}

bitflags! {
    #[derive(Default)]
    pub struct BlockFlag(c_int) {
        HAS_STRET = 1 << 29;
    }
}

#[repr(C)]
pub struct Block<F> {
    pub isa: *const c_void,
    pub flags: BlockFlag,
    pub reserved: c_int,
    pub invoke: F,
    pub descriptor: *const BlockDescriptor,
}

unsafe extern "C" {
    pub static _NSConcreteStackBlock: *const c_void;
}
