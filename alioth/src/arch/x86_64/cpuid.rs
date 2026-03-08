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

use bitfield::bitfield;

use crate::bitflags;

#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct CpuidIn {
    pub func: u32,
    pub index: Option<u32>,
}

bitflags! {
    pub struct Cpuid1Ecx(u32) {
        TSC_DEADLINE = 1 << 24;
        HYPERVISOR = 1 << 31;
    }
}

bitflags! {
    pub struct Cpuid7Index0Ebx(u32) {
        TSC_ADJUST = 1 << 1;
    }
}

bitflags! {
    pub struct Cpuid7Index0Edx(u32) {
        IBRS_IBPB = 1 << 26;
        SPEC_CTRL_ST_PREDICTORS = 1 << 27;
        L1D_FLUSH_INTERFACE = 1 << 28;
        ARCH_CAPABILITIES = 1 << 29;
        CORE_CAPABILITIES = 1 << 30;
        SPEC_CTRL_SSBD = 1 << 31;
    }
}

bitflags! {
    pub struct CpuidExt8Ebx(u32) {
        SSBD_VIRT_SPEC_CTRL = 1 << 25;
    }
}

bitflags! {
    pub struct CpuidExt1fEAx(u32) {
        SEV = 1 << 1;
        SEV_ES = 1 << 3;
        SEV_SNP = 1 << 4;
    }
}

bitfield! {
    pub struct CpuidExt1fEbx(u32);
    impl new;
    pub u8, cbit_pos, set_cbit_pos : 5, 0;
    pub u8, phys_addr_reduction, set_phys_addr_reduction : 11, 6;
    pub u8, num_vmpl, set_num_vmpl : 15, 12;
}

bitflags! {
    pub struct CpuidExt21EAx(u32) {
        NO_SMM_CTL_MSR = 1 << 9;
    }
}
