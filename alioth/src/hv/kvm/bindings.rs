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

#[cfg(target_arch = "aarch64")]
use bitfield::bitfield;
use bitflags::bitflags;

use crate::c_enum;

pub const KVMIO: u8 = 0xAE;
pub const KVM_API_VERSION: i32 = 12;

#[cfg(target_arch = "x86_64")]
c_enum! {
    pub struct KvmVmType(u64);
    {
        DEFAULT = 0;
        SW_PROTECTED = 1;
        SEV = 2;
        SEV_ES = 3;
        SNP = 4;
    }
}

#[cfg(target_arch = "aarch64")]
pub struct KvmVmType(#[allow(dead_code)] pub u64);

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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
        const LOG_DIRTY_PAGES = 1 << 0;
        const READONLY = 1 << 1;
        const GUEST_MEMFD = 1 << 2;
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
pub struct KvmUserspaceMemoryRegion2 {
    pub slot: u32,
    pub flags: KvmMemFlag,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub guest_memfd_offset: u64,
    pub guest_memfd: u32,
    pub _pad1: u32,
    pub _pad2: [u64; 14],
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KvmMemoryAttribute: u64 {
        const PRIVATE = 1 << 3;
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmMemoryAttributes {
    pub address: u64,
    pub size: u64,
    pub attributes: KvmMemoryAttribute,
    pub flags: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmCreateGuestMemfd {
    pub size: u64,
    pub flags: u64,
    pub reserved: [u64; 6],
}

#[cfg(target_arch = "x86_64")]
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

c_enum! {
    pub struct KvmExit(u32);
    {
        IO = 2;
        HYPERCALL = 3;
        MMIO = 6;
        SHUTDOWN = 8;
        SYSTEM_EVENT = 24;
    }
}

c_enum! {
    pub struct KvmSystemEvent(u32);
    {
        SHUTDOWN = 1;
        RESET = 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunExitSystemEvent {
    pub type_: KvmSystemEvent,
    pub flags: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct KvmRun {
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],
    pub exit_reason: KvmExit,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,
    pub cr8: u64,
    pub apic_base: u64,
    pub exit: KvmRunExit,
    pub kvm_valid_regs: u64,
    pub kvm_dirty_regs: u64,
    pub s: KvmSyncRegsBlock,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmRunExit {
    pub mmio: KvmRunExitMmio,
    pub io: KvmRunExitIo,
    pub hypercall: KvmRunExitHypercall,
    pub system_event: KvmRunExitSystemEvent,
    pub padding: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunExitMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

c_enum! {
    pub struct KvmExitIo(u8);
    {
        IN = 0;
        OUT = 1;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunExitIo {
    pub direction: KvmExitIo,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmRunExitHypercall {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmSyncRegsBlock {
    pub padding: [u8; 2048],
}

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

#[cfg(target_arch = "x86_64")]
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

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct KvmIrqRoutingEntry {
    pub gsi: u32,
    pub type_: u32,
    pub flags: KvmMsiFlag,
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

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct KvmMsiFlag: u32 {
        #[cfg(target_arch = "aarch64")]
        const VALID_DEVID = 1 << 0;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub flags: KvmMsiFlag,
    pub devid: u32,
    pub pad: [u8; 12usize],
}

c_enum! {
    pub struct KvmCap(u32);
    {
        NR_MEMSLOTS = 10;
        IRQFD = 32;
        SIGNAL_MSI = 77;
        ARM_PSCI_0_2 = 102;
        EXIT_HYPERCALL = 201;
        // GUEST_MEMFD = 234;
        // VM_TYPES = 235;
    }
}

pub const KVM_HC_MAP_GPA_RANGE: u64 = 12;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KvmMapGpaRangeFlag: u64 {
        const PAGE_2M = 1 << 0;
        const PAGE_1G = 1 << 1;
        const ENCRYPTED = 1 << 4;
    }
}

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

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmEnableCap {
    pub cap: KvmCap,
    pub flags: u32,
    pub args: [u64; 4],
    pub pad: [u8; 64],
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmOneReg {
    pub id: u64,
    pub addr: u64,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KvmCreateDevice {
    pub type_: KvmDevType,
    pub fd: i32,
    pub flags: u32,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KvmDeviceAttr {
    pub _flags: u32,
    pub group: u32,
    pub attr: u64,
    pub addr: u64,
}

#[cfg(target_arch = "aarch64")]
c_enum! {
    pub struct KvmDevType(u32);
    {
        ARM_VGIC_V2 = 5;
        ARM_VGIC_V3 = 7;
        ARM_ITS = 8;
    }
}

#[cfg(target_arch = "aarch64")]
c_enum! {
    pub struct KvmDevArmVgicGrp(u32);
    {
        ADDR = 0;
        DIST_REGS = 1;
        CPU_REGS = 2;
        NR_IRQS = 3;
        CTL = 4;
        REDIS_REG = 5;
        CPU_SYSREGS = 6;
    }
}

#[cfg(target_arch = "aarch64")]
c_enum! {
    pub struct KvmVgicAddrType(u64);
    {
        DIST_V2 = 0;
        CPU_V2 = 1;
        DIST_V3 = 2;
        REDIST_V3 = 3;
        ITS = 4;
        REDIST_REGION_V3 = 5;
    }
}

#[cfg(target_arch = "aarch64")]
c_enum! {
    pub struct KvmDevArmVgicCtrl(u64);
    {
        INIT = 0;
        ITS_SAVE_TABLES = 1;
        ITS_RESTORE_TABLES = 2;
        VGIC_SAVE_PENDING_TABLES = 3;
        ITS_RESET = 4;
    }
}

#[cfg(target_arch = "aarch64")]
bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct KvmVgicV3RedistRegion(u64);
    impl Debug;
    pub count, set_count: 63, 52;
    pub base, set_base: 51, 16;
    pub index, set_index: 11, 0;
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmVcpuInit {
    pub target: u32,
    pub features: [u32; 7],
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KvmArmVcpuFeature: u32 {
        const POWER_OFF = 1 << 0;
        const EL1_32BIT = 1 << 1;
        const PSCI_0_2 = 1 << 2;
        const PMU_V3 = 1 << 3;
    }
}
