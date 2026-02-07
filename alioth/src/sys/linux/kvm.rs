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

#[cfg(target_arch = "x86_64")]
use crate::ioctl_writeread_buf;
use crate::sys::ioctl::ioctl_ior;
#[cfg(target_arch = "x86_64")]
use crate::sys::ioctl::ioctl_iowr;
use crate::{
    consts, ioctl_none, ioctl_read, ioctl_write_buf, ioctl_write_ptr, ioctl_write_val,
    ioctl_writeread,
};

pub const KVMIO: u8 = 0xAE;
pub const KVM_API_VERSION: i32 = 12;

#[cfg(target_arch = "x86_64")]
consts! {
    pub struct KvmVmType(u64) {
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

#[cfg(target_arch = "x86_64")]
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

pub const KVM_CPUID_SIGNATURE: u32 = 0x4000_0000;
pub const KVM_CPUID_FEATURES: u32 = 0x4000_0001;

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KvmCpuidFeature: u32 {
        const CLOCKSOURCE = 1 << 0;
        const NOP_IO_DELAY = 1 << 1;
        const MMU_OP = 1 << 2;
        const CLOCKSOURCE2 = 1 << 3;
        const ASYNC_PF = 1 << 4;
        const STEAL_TIME = 1 << 5;
        const PV_EOI = 1 << 6;
        const PV_UNHALT = 1 << 7;
        const PV_TLB_FLUSH = 1 << 9;
        const ASYNC_PF_VMEXIT = 1 << 10;
        const PV_SEND_IPI = 1 << 11;
        const POLL_CONTROL = 1 << 12;
        const PV_SCHED_YIELD = 1 << 13;
        const ASYNC_PF_INT = 1 << 14;
        const MSI_EXT_DEST_ID = 1 << 15;
        const HC_MAP_GPA_RANGE = 1 << 16;
        const MIGRATION_CONTROL = 1 << 17;
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmMsrEntry {
    pub index: u32,
    pub _reserved: u32,
    pub data: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmMsrs<const N: usize> {
    pub nmsrs: u32,
    pub _pad: u32,
    pub entries: [KvmMsrEntry; N],
}

#[cfg(target_arch = "x86_64")]
pub const MAX_IO_MSRS: usize = 256;

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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

consts! {
    pub struct KvmExit(u32) {
        IO = 2;
        HYPERCALL = 3;
        MMIO = 6;
        SHUTDOWN = 8;
        SYSTEM_EVENT = 24;
    }
}

consts! {
    pub struct KvmSystemEvent(u32) {
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

consts! {
    pub struct KvmExitIo(u8) {
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

consts! {
    pub struct KvmCap(u32) {
        IRQFD = 32;
        KVMCLOCK_CTRL = 76;
        SIGNAL_MSI = 77;
        ARM_PSCI_0_2 = 102;
        X2APIC_API = 129;
        EXIT_HYPERCALL = 201;
        // GUEST_MEMFD = 234;
        // VM_TYPES = 235;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KvmX2apicApiFlag: u64 {
        const USE_32BIT_IDS = 1 << 0;
        const DISABLE_BROADCAST_QUIRK = 1 << 1;
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
consts! {
    pub struct KvmDevType(u32) {
        ARM_VGIC_V2 = 5;
        ARM_VGIC_V3 = 7;
        ARM_ITS = 8;
    }
}

#[cfg(target_arch = "aarch64")]
consts! {
    pub struct KvmDevArmVgicGrp(u32) {
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
consts! {
    pub struct KvmVgicAddrType(u64) {
        DIST_V2 = 0;
        CPU_V2 = 1;
        DIST_V3 = 2;
        REDIST_V3 = 3;
        ITS = 4;
        REDIST_REGION_V3 = 5;
    }
}

#[cfg(target_arch = "aarch64")]
consts! {
    pub struct KvmDevArmVgicCtrl(u64) {
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

ioctl_none!(kvm_get_api_version, KVMIO, 0x00);
ioctl_write_val!(kvm_create_vm, KVMIO, 0x01, KvmVmType);
ioctl_write_val!(kvm_check_extension, KVMIO, 0x03, KvmCap);
ioctl_none!(kvm_get_vcpu_mmap_size, KVMIO, 0x04);
#[cfg(target_arch = "x86_64")]
ioctl_writeread_buf!(kvm_get_supported_cpuid, KVMIO, 0x05, KvmCpuid2);

ioctl_write_val!(kvm_create_vcpu, KVMIO, 0x41, u32);
ioctl_write_ptr!(
    kvm_set_user_memory_region,
    KVMIO,
    0x46,
    KvmUserspaceMemoryRegion
);
#[cfg(target_arch = "x86_64")]
ioctl_write_val!(kvm_set_tss_addr, KVMIO, 0x47, u64);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_identity_map_addr, KVMIO, 0x48, u64);
ioctl_write_ptr!(
    kvm_set_user_memory_region2,
    KVMIO,
    0x49,
    KvmUserspaceMemoryRegion2
);

#[cfg(target_arch = "x86_64")]
ioctl_none!(kvm_create_irqchip, KVMIO, 0x60);
ioctl_write_buf!(kvm_set_gsi_routing, KVMIO, 0x6a, KvmIrqRouting);

ioctl_write_ptr!(kvm_irqfd, KVMIO, 0x76, KvmIrqfd);
ioctl_write_ptr!(kvm_ioeventfd, KVMIO, 0x79, KvmIoEventFd);

ioctl_none!(kvm_run, KVMIO, 0x80);
#[cfg(target_arch = "x86_64")]
ioctl_read!(kvm_get_regs, KVMIO, 0x81, KvmRegs);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_regs, KVMIO, 0x82, KvmRegs);
#[cfg(target_arch = "x86_64")]
ioctl_read!(kvm_get_sregs, KVMIO, 0x83, KvmSregs);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_sregs, KVMIO, 0x84, KvmSregs);
#[cfg(target_arch = "x86_64")]
ioctl_write_buf!(kvm_set_msrs, KVMIO, 0x89, KvmMsrs);

#[cfg(target_arch = "x86_64")]
ioctl_write_buf!(kvm_set_cpuid2, KVMIO, 0x90, KvmCpuid2);

ioctl_write_ptr!(kvm_enable_cap, KVMIO, 0xa3, KvmEnableCap);
ioctl_write_ptr!(kvm_signal_msi, KVMIO, 0xa5, KvmMsi);

#[cfg(not(target_arch = "x86_64"))]
ioctl_write_ptr!(kvm_get_one_reg, KVMIO, 0xab, KvmOneReg);
#[cfg(not(target_arch = "x86_64"))]
ioctl_write_ptr!(kvm_set_one_reg, KVMIO, 0xac, KvmOneReg);

ioctl_none!(kvm_kvmclock_ctrl, KVMIO, 0xad);

#[cfg(target_arch = "aarch64")]
ioctl_write_ptr!(kvm_arm_vcpu_init, KVMIO, 0xae, KvmVcpuInit);
#[cfg(target_arch = "aarch64")]
ioctl_read!(kvm_arm_preferred_target, KVMIO, 0xaf, KvmVcpuInit);

#[cfg(target_arch = "x86_64")]
ioctl_writeread!(kvm_memory_encrypt_op, ioctl_iowr::<u64>(KVMIO, 0xba));

ioctl_write_ptr!(
    kvm_memory_encrypt_reg_region,
    ioctl_ior::<KvmEncRegion>(KVMIO, 0xbb),
    KvmEncRegion
);

ioctl_write_ptr!(
    kvm_memory_encrypt_unreg_region,
    ioctl_ior::<KvmEncRegion>(KVMIO, 0xbc),
    KvmEncRegion
);

#[cfg(target_arch = "x86_64")]
ioctl_read!(kvm_get_sregs2, KVMIO, 0xcc, KvmSregs2);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_sregs2, KVMIO, 0xcd, KvmSregs2);

ioctl_write_ptr!(kvm_set_memory_attributes, KVMIO, 0xd2, KvmMemoryAttributes);

#[cfg(target_arch = "x86_64")]
ioctl_writeread!(kvm_create_guest_memfd, KVMIO, 0xd4, KvmCreateGuestMemfd);

#[cfg(target_arch = "aarch64")]
ioctl_writeread!(kvm_create_device, KVMIO, 0xe0, KvmCreateDevice);
#[cfg(target_arch = "aarch64")]
ioctl_write_ptr!(kvm_set_device_attr, KVMIO, 0xe1, KvmDeviceAttr);
#[cfg(target_arch = "aarch64")]
ioctl_write_ptr!(kvm_get_device_attr, KVMIO, 0xe2, KvmDeviceAttr);
