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

use std::sync::Arc;

use parking_lot::Mutex;

use crate::hw::{Board, Result};
use crate::kvm::arch::Cpuid;
use crate::kvm::{Hypervisor, Vcpu};
use crate::loader::InitState;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{AddrOpt, MemRange, MemRegion, MemRegionEntry, MemRegionType};

pub mod layout {
    pub const REAL_MODE_IVT_START: usize = 0x0;

    pub const BIOS_DATA_AREA_START: usize = 0x400;
    pub const BIOS_DATA_END: usize = 0x500;

    pub const BOOT_GDT_START: usize = 0x500;
    pub const BOOT_GDT_LIMIT: usize = 0x100;
    pub const BOOT_IDT_START: usize = 0x600;
    pub const BOOT_IDT_LIMIT: usize = 0xa00;

    pub const LINUX_BOOT_PARAMS_START: usize = 0x1000; // size: 4KiB
    pub const HVM_START_INFO_START: usize = 0x1000; // size: 4KiB

    pub const KERNEL_CMD_LINE_START: usize = 0x2000;
    pub const KERNEL_CMD_LINE_LIMIT: usize = 0x1000;

    pub const BOOT_PAGING_START: usize = 0x3000;
    pub const BOOT_PAGING_LIMIT: usize = 0x4000;

    pub const EBDA_START: usize = 0x8_0000;
    pub const EBDA_END: usize = 0xA_0000;

    pub const KERNEL_IMAGE_START: usize = 0x100_0000; // 16 MiB

    pub const RAM_32_END: usize = 0x8000_0000; // 2 GiB
    pub const RAM_32_SIZE: usize = RAM_32_END; // 2 GiB

    pub const MMIO_32_START: usize = 0x8000_0000; // 2 GiB
    pub const MMIO_32_END: usize = 0xe000_0000; // 3.5 GiB

    pub const PCIE_CONFIG_START: usize = 0xe000_0000; // 3.5 GiB
    pub const PCIE_CONFIG_END: usize = 0xf000_0000; // 3.75 GiB, size = 256 MiB

    pub const IOAPIC_START: usize = 0xfec0_0000;
    pub const APIC_START: usize = 0xfee0_0000;

    pub const MEM_64_START: usize = 0x1_0000_0000; // 4GiB

    pub const PAGE_SIZE: usize = 0x1000; // 4KiB
}

pub mod msr {
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
}

pub mod paging {
    use bitflags::bitflags;

    bitflags! {
        #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct Entry: u32 {
            /// Present
            const P = 1 << 0;
            /// Read/write
            const RW = 1 << 1;
            /// User/supervisor
            const US = 1 << 2;
            /// Page-level write-through
            const PWT = 1 << 3;
            /// Page-level cache disable
            const PCD = 1 << 4;
            /// Accessed
            const A = 1 << 5;
            /// Dirty
            const D = 1 << 6;
            /// Page size
            const PS = 1 << 7;
            /// Global
            const G = 1 << 8;
        }
    }
}

pub mod reg {
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
}

use layout::{BIOS_DATA_END, EBDA_END, EBDA_START, MEM_64_START, RAM_32_SIZE};

pub struct ArchBoard {
    cpuids: Vec<Cpuid>,
}

impl ArchBoard {
    pub fn new(hv: &Hypervisor) -> Result<Self> {
        let mut cpuids = hv.get_supported_cpuids()?;
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ecx |= (1 << 24) | (1 << 31);
            } else if cpuid.func == 0x8000_001f {
                // AMD Volume 3, section E.4.17.
            }
        }
        Ok(Self { cpuids })
    }
}

impl Board {
    pub fn init_boot_vcpu(&self, vcpu: &mut Vcpu, init_state: &InitState) -> Result<()> {
        vcpu.set_sregs(&init_state.sregs, &init_state.seg_regs, &init_state.dt_regs)?;
        vcpu.set_regs(&init_state.regs)?;
        Ok(())
    }

    pub fn init_vcpu(&self, id: u32, vcpu: &mut Vcpu) -> Result<()> {
        let mut cpuids = self.arch.cpuids.clone();
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ebx &= 0x00ff_ffff;
                cpuid.ebx |= id << 24;
            } else if cpuid.func == 0xb {
                cpuid.edx = id;
            }
        }
        vcpu.set_cpuids(cpuids)?;
        Ok(())
    }

    pub fn create_ram(&self) -> Result<()> {
        let config = &self.config;
        let memory = &self.memory;

        let low_mem_size = std::cmp::min(config.mem_size, RAM_32_SIZE);
        let pages_low = ArcMemPages::new_anon(low_mem_size)?;
        let region_low = MemRegion {
            size: low_mem_size,
            ranges: vec![MemRange::Mapped(pages_low)],
            entries: vec![
                MemRegionEntry {
                    size: BIOS_DATA_END,
                    type_: MemRegionType::Reserved,
                },
                MemRegionEntry {
                    size: EBDA_START - BIOS_DATA_END,
                    type_: MemRegionType::Ram,
                },
                MemRegionEntry {
                    size: EBDA_END - EBDA_START,
                    type_: MemRegionType::Acpi,
                },
                MemRegionEntry {
                    size: low_mem_size - EBDA_END,
                    type_: MemRegionType::Ram,
                },
            ],
            callbacks: Mutex::new(vec![]),
        };
        memory.add_region(AddrOpt::Fixed(0), Arc::new(region_low))?;
        if config.mem_size > RAM_32_SIZE {
            let mem_hi = ArcMemPages::new_anon(config.mem_size - RAM_32_SIZE)?;
            let region_hi = MemRegion::with_mapped(mem_hi, MemRegionType::Ram);
            memory.add_region(AddrOpt::Fixed(MEM_64_START), Arc::new(region_hi))?;
        }
        Ok(())
    }
}
