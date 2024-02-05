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

use crate::arch::reg::SegAccess;

#[derive(Debug, Default, Clone)]
pub struct Cpuid {
    pub func: u32,
    pub index: Option<u32>,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rsp,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rflags,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SReg {
    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Cr8,
    Efer,
    ApicBase,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SegReg {
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    Tr,
    Ldtr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DtReg {
    Gdtr,
    Idtr,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct SegRegVal {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub access: SegAccess,
}

impl SegRegVal {
    pub fn to_desc(&self) -> u64 {
        ((self.base & 0xff00_0000) << (56 - 24))
            | (((self.access.0 as u64) & 0x0000_f0ff) << 40)
            | (((self.limit as u64) & 0x000f_0000) << (48 - 16))
            | ((self.base & 0x00ff_ffff) << 16)
            | ((self.limit as u64) & 0x0000_ffff)
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct DtRegVal {
    pub base: u64,
    pub limit: u16,
}
