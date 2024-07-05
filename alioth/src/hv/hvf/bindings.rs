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

use std::os::raw::c_void;

use bitflags::bitflags;

use crate::arch::reg::{EsrEl2, SReg};
use crate::c_enum;

c_enum! {
    pub struct HvReg(u32);
    {
        X0 = 0;
        X1 = 1;
        X2 = 2;
        X3 = 3;
        X4 = 4;
        X5 = 5;
        X6 = 6;
        X7 = 7;
        X8 = 8;
        X9 = 9;
        X10 = 10;
        X11 = 11;
        X12 = 12;
        X13 = 13;
        X14 = 14;
        X15 = 15;
        X16 = 16;
        X17 = 17;
        X18 = 18;
        X19 = 19;
        X20 = 20;
        X21 = 21;
        X22 = 22;
        X23 = 23;
        X24 = 24;
        X25 = 25;
        X26 = 26;
        X27 = 27;
        X28 = 28;
        X29 = 29;
        X30 = 30;
        PC= 31;
        FPCR = 32;
        FPSR = 33;
        CPSR = 34;
    }
}

c_enum! {
    #[derive(Default)]
    pub struct HvExitReason(u32);
    {
        CANCEL = 0;
        EXCEPTION = 1;
        VTIMER_ACTIVATED = 2;
        UNKNOWN = 3;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct HvVcpuExitException {
    pub syndrome: EsrEl2,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct HvVcpuExit {
    pub reason: HvExitReason,
    pub exception: HvVcpuExitException,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    #[repr(transparent)]
    pub struct HvMemoryFlag: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
    }
}

#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
    pub fn hv_vm_create(config: *mut i32) -> i32;
    pub fn hv_vm_destroy() -> i32;
    pub fn hv_vcpu_create(vcpu: &mut u64, exit: &mut *mut HvVcpuExit, config: *mut c_void) -> i32;
    pub fn hv_vcpu_destroy(vcpu: u64) -> i32;
    pub fn hv_vcpu_get_reg(vcpu: u64, reg: HvReg, value: &mut u64) -> i32;
    pub fn hv_vcpu_set_reg(vcpu: u64, reg: HvReg, value: u64) -> i32;
    pub fn hv_vcpu_set_sys_reg(vcpu: u64, reg: SReg, val: u64) -> i32;
    pub fn hv_vcpu_get_sys_reg(vcpu: u64, reg: SReg, val: &mut u64) -> i32;
    pub fn hv_vm_map(addr: *const u8, ipa: u64, size: usize, flags: HvMemoryFlag) -> i32;
    pub fn hv_vm_unmap(ipa: u64, size: usize) -> i32;
}
