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

use bitflags::bitflags;

use crate::arch::tdx::TdAttr;
use crate::consts;
use crate::sys::kvm::KvmCpuid2;

consts! {
    #[derive(Default)]
    pub struct KvmTdxCmdId(u32) {
        CAPABILITIES = 0;
        INIT_VM = 1;
        INIT_VCPU = 2;
        INIT_MEM_REGION = 3;
        FINALIZE_VM = 4;
        GET_CPUID = 5;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmTdxCmd {
    pub id: KvmTdxCmdId,
    pub flags: u32,
    pub data: u64,
    pub hw_error: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmTdxCapabilities<const N: usize> {
    pub supported_attrs: TdAttr,
    pub supported_xfam: u64,
    pub kernel_tdvmcallinfo_1_r11: u64,
    pub user_tdvmcallinfo_1_r11: u64,
    pub kernel_tdvmcallinfo_1_r12: u64,
    pub user_tdvmcallinfo_1_r12: u64,
    pub reserved: [u64; 250],
    pub cpuid: KvmCpuid2<N>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmTdxInitVm<const N: usize> {
    pub attributes: u64,
    pub xfam: u64,
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub reserved: [u64; 12],
    pub cpuid: KvmCpuid2<N>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmTdxInitMemRegion {
    pub source_addr: u64,
    pub gpa: u64,
    pub nr_pages: u64,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KvmTdxInitMemRegionFlag: u32 {
        const MEASURE_MEMORY_REGION = 1 << 0;
    }
}
