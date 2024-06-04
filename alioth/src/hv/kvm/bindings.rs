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

use std::fmt::{Debug, Formatter, Result};

use bitflags::bitflags;

pub const KVMIO: u8 = 0xAE;
pub const KVM_API_VERSION: i32 = 12;
pub const KVM_MAX_CPUID_ENTRIES: usize = 256;

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KvmCpuid2Flag: u32 {
        const SIGNIFCANT_INDEX = 1;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: KvmCpuid2Flag,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmCpuid2<const N: usize> {
    pub nent: u32,
    pub padding: u32,
    pub entries: [KvmCpuidEntry2; N],
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KvmMemFlag: u32 {
        const LOG_DIRTY_PAGES = 1;
        const READONLY = 2;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: KvmMemFlag,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmSregs2 {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub flags: u64,
    pub pdptrs: [u64; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct KvmRun {
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,
    pub cr8: u64,
    pub apic_base: u64,
    pub exit: KvmExit,
    pub kvm_valid_regs: u64,
    pub kvm_dirty_regs: u64,
    pub s: KvmSyncRegsBlock,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmExit {
    pub mmio: KvmExitMmio,
    pub io: KvmExitIo,
    pub padding: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmExitMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmExitIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmSyncRegsBlock {
    pub padding: [u8; 2048],
}

pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;

pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KvmIrqfdFlag: u32 {
        const DEASSIGN = 1 << 0;
        const RESAMPLE = 1 << 1;
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmIrqfd {
    pub fd: u32,
    pub gsi: u32,
    pub flags: KvmIrqfdFlag,
    pub resamplefd: u32,
    pub pad: [u8; 16usize],
}

pub const KVM_IRQ_ROUTING_IRQCHIP: u32 = 1;
pub const KVM_IRQ_ROUTING_MSI: u32 = 2;

pub const KVM_IRQCHIP_IOAPIC: u32 = 2;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KvmIrqRoutingIrqchip {
    pub irqchip: u32,
    pub pin: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct KvmIrqRoutingMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub devid: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union KvmIrqRoutingType {
    pub irqchip: KvmIrqRoutingIrqchip,
    pub msi: KvmIrqRoutingMsi,
    pub pad: [u32; 8],
}

impl Debug for KvmIrqRoutingType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_list().entries(unsafe { &self.pad }.iter()).finish()
    }
}

impl Default for KvmIrqRoutingType {
    fn default() -> Self {
        KvmIrqRoutingType { pad: [0; 8] }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KvmIrqRoutingEntryFlag: u32 {
        const MSI_VALID_DEVID = 1 << 0;
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct KvmIrqRoutingEntry {
    pub gsi: u32,
    pub type_: u32,
    pub flags: u32,
    pub pad: u32,
    pub routing: KvmIrqRoutingType,
}

impl Debug for KvmIrqRoutingEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut debug_struct = f.debug_struct("KvmIrqRoutingEntry");
        debug_struct.field("gsi", &self.gsi);
        debug_struct.field("flags", &self.flags);
        match self.type_ {
            KVM_IRQ_ROUTING_IRQCHIP => {
                debug_struct.field("irqchip", unsafe { &self.routing.irqchip })
            }
            KVM_IRQ_ROUTING_MSI => debug_struct.field("msi", unsafe { &self.routing.msi }),
            _ => debug_struct.field("unknown", unsafe { &self.routing.pad }),
        };
        debug_struct.finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KvmIrqRouting<const N: usize> {
    pub nr: u32,
    pub _flags: u32,
    pub entries: [KvmIrqRoutingEntry; N],
}

impl<const N: usize> Debug for KvmIrqRouting<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_list()
            .entries(self.entries.iter().take(self.nr as usize))
            .finish()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub flags: u32,
    pub devid: u32,
    pub pad: [u8; 12usize],
}

pub const KVM_CAP_NR_MEMSLOTS: u64 = 10;
pub const KVM_CAP_IRQFD: u64 = 32;
pub const KVM_CAP_SIGNAL_MSI: u64 = 77;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KvmIoEventFdFlag: u32 {
        const DATA_MATCH = 1 << 0;
        const PIO = 1 << 1;
        const DEASSIGN = 1 << 2;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmIoEventFd {
    pub datamatch: u64,
    pub addr: u64,
    pub len: u32,
    pub fd: i32,
    pub flags: KvmIoEventFdFlag,
    pub pad: [u32; 9],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmEncRegion {
    pub addr: u64,
    pub size: u64,
}
