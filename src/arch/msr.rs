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

use bitflags::bitflags;

// Intel Vol.4, Table 2-2.
pub const IA32_EFER: u32 = 0xc000_0080;
pub const IA32_STAR: u32 = 0xc000_0081;
pub const IA32_LSTAR: u32 = 0xc000_0082;
pub const IA32_CSTAR: u32 = 0xc000_0083;
pub const IA32_FMASK: u32 = 0xc000_0084;
pub const IA32_FS_BASE: u32 = 0xc000_0100;
pub const IA32_GS_BASE: u32 = 0xc000_0101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;
pub const IA32_TSC_AUX: u32 = 0xc000_0103;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Efer: u32 {
        /// SYSCALL enable
        const SCE = 1 << 0;
        /// IA-32e mode enable
        const LME = 1 << 8;
        /// IA-32e mode active
        const LMA = 1 << 10;
        /// Execute disable bit enable
        const NXE = 1 << 11;
    }
}
