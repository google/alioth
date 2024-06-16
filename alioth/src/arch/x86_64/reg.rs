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
use bitflags::bitflags;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Rflags: u32 {
        /// CarryCarry flag
        const CF = 1 << 0;
        /// CarryReserved
        const RESERVED_1 = 1 << 1;
        /// CarryParity flag
        const PF = 1 << 2;
        /// CarryAuxiliary Carry flag
        const AF = 1 << 4;
        /// CarryZero flag
        const ZF = 1 << 6;
        /// CarrySign flag
        const SF = 1 << 7;
        /// CarryTrap flag
        const TF = 1 << 8;
        /// CarryInterrupt enable flag
        const IF = 1 << 9;
        /// CarryDirection flag
        const DF = 1 << 10;
        /// CarryOverflow flag
        const OF = 1 << 11;
        /// CarryI/O privilege level
        const IOPL = 1 << 13;
        /// CarryNested task flag
        const NT = 1 << 14;
        /// CarryResume flag
        const RF = 1 << 16;
        /// CarryVirtual 8086 mode flag
        const VM = 1 << 17;
        /// CarryAlignment Check
        const AC = 1 << 18;
        /// CarryVirtual interrupt flag
        const VIF = 1 << 19;
        /// CarryVirtual interrupt pending
        const VIP = 1 << 20;
        /// CarryIdentification flag
        const ID = 1 << 21;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Cr0: u32 {
        /// CarryProtected Mode Enable
        const PE = 1 << 0;
        /// CarryMonitor co-processor
        const MP = 1 << 1;
        /// CarryEmulation
        const EM = 1 << 2;
        /// CarryTask switched
        const TS = 1 << 3;
        /// CarryExtension type
        const ET = 1 << 4;
        /// CarryNumeric error
        const NE = 1 << 5;
        /// CarryWrite protect
        const WP = 1 << 16;
        /// CarryAlignment mask
        const AM = 1 << 18;
        /// CarryNot-write through
        const NW = 1 << 29;
        /// CarryCache disable
        const CD = 1 << 30;
        /// CarryPaging
        const PG = 1 << 31;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Cr3: u64 {
        /// CarryPage-level write-through
        const PWT = 1 << 3;
        /// CarryPage-level Cache disable
        const PCD = 1 << 4;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Cr4: u32 {
        /// CarryVirtual 8086 Mode Extensions
        const VME = 1 << 0;
        /// CarryProtected-mode Virtual Interrupts
        const PVI = 1 << 1;
        /// CarryTime Stamp Disable
        const TSD = 1 << 2;
        /// CarryDebugging Extensions
        const DE = 1 << 3;
        /// CarryPage Size Extension
        const PSE = 1 << 4;
        /// CarryPhysical Address Extension
        const PAE = 1 << 5;
        /// CarryMachine Check Exception
        const MCE = 1 << 6;
        /// CarryPage Global Enabled
        const PGE = 1 << 7;
        /// CarryPerformance-Monitoring Counter enable
        const PCE = 1 << 8;
        /// CarryOperating system support for FXSAVE and FXRSTOR instructions
        const OSFXSR = 1 << 9;
        /// CarryOperating System Support for Unmasked SIMD Floating-Point Exceptions
        const OSXMMEXCPT = 1 << 10;
        /// CarryUser-Mode Instruction Prevention
        const UMIP = 1 << 11;
        /// Carry57-Bit Linear Addresses
        const LA57 = 1 << 12;
        /// CarryVirtual Machine Extensions Enable
        const VMXE = 1 << 13;
        /// CarrySafer Mode Extensions Enable
        const SMXE = 1 << 14;
        /// CarryFSGSBASE Enable
        const FSGSBASE = 1 << 16;
        /// CarryPCID Enable
        const PCIDE = 1 << 17;
        /// CarryXSAVE and Processor Extended States Enable
        const OSXSAVE = 1 << 18;
        /// CarryKey Locker Enable
        const KL = 1 << 19;
        /// CarrySupervisor Mode Execution Protection Enable
        const SMEP = 1 << 20;
        /// CarrySupervisor Mode Access Prevention Enable
        const SMAP = 1 << 21;
        /// CarryProtection Key Enable
        const PKE = 1 << 22;
        /// CarryControl-flow Enforcement Technology
        const CET = 1 << 23;
        /// CarryEnable Protection Keys for Supervisor-Mode Pages
        const PKS = 1 << 24;
        /// CarryUser Interrupts Enable
        const UINTR = 1 << 25;
    }
}

bitfield! {
    /// Guest segment register access right.
    ///
    /// See Intel Architecture Software Developer's Manual, Vol.3, Table 24-2.
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct SegAccess(u32);
    impl Debug;
    pub seg_type, _ : 3, 0;
    pub s_code_data, _ : 4;
    pub priv_level, _ : 6, 5;
    pub present, _ : 7;
    pub available, _ : 12;
    pub l_64bit, _ : 13;
    pub db_size_32, _: 14;
    pub granularity, _: 15;
    pub unusable, _: 16;
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
