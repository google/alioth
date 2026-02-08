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

bitflags! {
    pub struct Rflags(u32) {
        /// CarryCarry flag
        CF = 1 << 0;
        /// CarryReserved
        RESERVED_1 = 1 << 1;
        /// CarryParity flag
        PF = 1 << 2;
        /// CarryAuxiliary Carry flag
        AF = 1 << 4;
        /// CarryZero flag
        ZF = 1 << 6;
        /// CarrySign flag
        SF = 1 << 7;
        /// CarryTrap flag
        TF = 1 << 8;
        /// CarryInterrupt enable flag
        IF = 1 << 9;
        /// CarryDirection flag
        DF = 1 << 10;
        /// CarryOverflow flag
        OF = 1 << 11;
        /// CarryI/O privilege level
        IOPL = 1 << 13;
        /// CarryNested task flag
        NT = 1 << 14;
        /// CarryResume flag
        RF = 1 << 16;
        /// CarryVirtual 8086 mode flag
        VM = 1 << 17;
        /// CarryAlignment Check
        AC = 1 << 18;
        /// CarryVirtual interrupt flag
        VIF = 1 << 19;
        /// CarryVirtual interrupt pending
        VIP = 1 << 20;
        /// CarryIdentification flag
        ID = 1 << 21;
    }
}

bitflags! {
    pub struct Cr0(u32) {
        /// CarryProtected Mode Enable
        PE = 1 << 0;
        /// CarryMonitor co-processor
        MP = 1 << 1;
        /// CarryEmulation
        EM = 1 << 2;
        /// CarryTask switched
        TS = 1 << 3;
        /// CarryExtension type
        ET = 1 << 4;
        /// CarryNumeric error
        NE = 1 << 5;
        /// CarryWrite protect
        WP = 1 << 16;
        /// CarryAlignment mask
        AM = 1 << 18;
        /// CarryNot-write through
        NW = 1 << 29;
        /// CarryCache disable
        CD = 1 << 30;
        /// CarryPaging
        PG = 1 << 31;
    }
}

bitflags! {
    pub struct Cr3(u64) {
        /// CarryPage-level write-through
        PWT = 1 << 3;
        /// CarryPage-level Cache disable
        PCD = 1 << 4;
    }
}

bitflags! {
    pub struct Cr4(u32) {
        /// CarryVirtual 8086 Mode Extensions
        VME = 1 << 0;
        /// CarryProtected-mode Virtual Interrupts
        PVI = 1 << 1;
        /// CarryTime Stamp Disable
        TSD = 1 << 2;
        /// CarryDebugging Extensions
        DE = 1 << 3;
        /// CarryPage Size Extension
        PSE = 1 << 4;
        /// CarryPhysical Address Extension
        PAE = 1 << 5;
        /// CarryMachine Check Exception
        MCE = 1 << 6;
        /// CarryPage Global Enabled
        PGE = 1 << 7;
        /// CarryPerformance-Monitoring Counter enable
        PCE = 1 << 8;
        /// CarryOperating system support for FXSAVE and FXRSTOR instructions
        OSFXSR = 1 << 9;
        /// CarryOperating System Support for Unmasked SIMD Floating-Point Exceptions
        OSXMMEXCPT = 1 << 10;
        /// CarryUser-Mode Instruction Prevention
        UMIP = 1 << 11;
        /// Carry57-Bit Linear Addresses
        LA57 = 1 << 12;
        /// CarryVirtual Machine Extensions Enable
        VMXE = 1 << 13;
        /// CarrySafer Mode Extensions Enable
        SMXE = 1 << 14;
        /// CarryFSGSBASE Enable
        FSGSBASE = 1 << 16;
        /// CarryPCID Enable
        PCIDE = 1 << 17;
        /// CarryXSAVE and Processor Extended States Enable
        OSXSAVE = 1 << 18;
        /// CarryKey Locker Enable
        KL = 1 << 19;
        /// CarrySupervisor Mode Execution Protection Enable
        SMEP = 1 << 20;
        /// CarrySupervisor Mode Access Prevention Enable
        SMAP = 1 << 21;
        /// CarryProtection Key Enable
        PKE = 1 << 22;
        /// CarryControl-flow Enforcement Technology
        CET = 1 << 23;
        /// CarryEnable Protection Keys for Supervisor-Mode Pages
        PKS = 1 << 24;
        /// CarryUser Interrupts Enable
        UINTR = 1 << 25;
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
