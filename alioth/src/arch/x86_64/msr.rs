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

use crate::{bitflags, consts};

// Intel Vol.4, Table 2-2.
consts! {
    #[derive(Default)]
    pub struct Msr(u32) {
        EFER = 0xc000_0080;
        STAR = 0xc000_0081;
        LSTAR = 0xc000_0082;
        CSTAR = 0xc000_0083;
        FMASK = 0xc000_0084;
        FS_BASE = 0xc000_0100;
        GS_BASE = 0xc000_0101;
        KERNEL_GS_BASE = 0xc000_0102;
        TSC_AUX = 0xc000_0103;
        MISC_ENABLE = 0x0000_01a0;
        APIC_BASE = 0x0000_001b;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Efer(u64) {
        /// SYSCALL enable
        SCE = 1 << 0;
        /// IA-32e mode enable
        LME = 1 << 8;
        /// IA-32e mode active
        LMA = 1 << 10;
        /// Execute disable bit enable
        NXE = 1 << 11;
    }
}

bitflags! {
    pub struct MiscEnable(u64) {
        /// Enable Fast-Strings
        FAST_STRINGS = 1 << 0;
    }
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct ApicBase(u64);
    impl Debug;
    pub bsp, set_bsp : 8;
    pub x2apic, set_x2apic : 10;
    pub xapic, set_xapic : 11;
    pub base, set_base : 35, 12;
}
