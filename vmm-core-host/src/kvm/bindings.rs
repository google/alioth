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

#![allow(dead_code)]

use bitflags::bitflags;

use crate::ioctls::{ioctl_io, ioctl_ior};
use crate::{
    ioctl_none, ioctl_read, ioctl_write_buf, ioctl_write_ptr, ioctl_write_val, ioctl_writeread_buf,
};

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
#[allow(dead_code)]
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
    pub emulation_failure: KvmExitEmulationFailure,
    pub system_event: KvmExitSystemEvent,
    pub eoi: KvmExitEoi,
    pub msr: KvmExitMsr,
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
#[derive(Debug, Clone, Copy)]
pub struct KvmExitEmulationFailure {
    pub suberror: u32,
    pub ndata: u32,
    pub flags: u64,
    pub insn_size: u8,
    pub insn_bytes: [u8; 15],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmExitSystemEvent {
    pub type_: u32,
    pub ndata: u32,
    pub flags: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmExitEoi {
    pub vector: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmExitMsr {
    pub error: u8,
    pub pad: [u8; 7],
    pub reason: u32,
    pub index: u32,
    pub data: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmVcpuException {
    pub injected: u8,
    pub nr: u8,
    pub has_error_code: u8,
    pub pending: u8,
    pub error_code: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmVcpuInterrupt {
    pub injected: u8,
    pub nr: u8,
    pub soft: u8,
    pub shadow: u8,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmVcpuNmi {
    pub injected: u8,
    pub pending: u8,
    pub masked: u8,
    pub pad: u8,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmVcpuSmi {
    pub smm: u8,
    pub pending: u8,
    pub smm_inside_nmi: u8,
    pub latched_init: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmVcpuEvents {
    pub exception: KvmVcpuException,
    pub interrupt: KvmVcpuInterrupt,
    pub nmi: KvmVcpuNmi,
    pub sipi_vector: u32,
    pub flags: u32,
    pub smi: KvmVcpuSmi,
    pub triple_fault_pending: u8,
    pub reserved: [u8; 26],
    pub exception_has_payload: u8,
    pub exception_payload: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSyncRegs {
    pub regs: KvmRegs,
    pub sregs: KvmSregs,
    pub events: KvmVcpuEvents,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union KvmSyncRegsBlock {
    pub regs: KvmSyncRegs,
    pub padding: [u8; 2048],
}

pub const KVM_SYNC_X86_REGS: u64 = 1 << 0;
pub const KVM_SYNC_X86_SREGS: u64 = 1 << 1;
pub const KVM_SYNC_X86_EVENTS: u64 = 1 << 2;

pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_CPUID: u32 = 10;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
pub const KVM_EXIT_SYSTEM_EVENT: u32 = 24;
pub const KVM_EXIT_IOAPIC_EOI: u32 = 26;
pub const KVM_EXIT_X86_RDMSR: u32 = 29;
pub const KVM_EXIT_X86_WRMSR: u32 = 30;

pub const KVM_INTERNAL_ERROR_EMULATION: u32 = 1;
pub const KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES: u64 = 1 << 0;

pub const KVM_SYSTEM_EVENT_SHUTDOWN: u32 = 1;
pub const KVM_SYSTEM_EVENT_RESET: u32 = 2;

pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmIrqLevel {
    pub irq: u32,
    pub level: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmIrqfd {
    pub fd: u32,
    pub gsi: u32,
    pub flags: u32,
    pub resamplefd: u32,
    pub pad: [u8; 16usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmMsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmMsrs<const N: usize> {
    pub nmsrs: u32,
    pub pad: u32,
    pub entries: [KvmMsrEntry; N],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KvmMpState {
    pub mp_state: u32,
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
pub const KVM_CAP_SYNC_REGS: u64 = 74;
pub const KVM_CAP_SIGNAL_MSI: u64 = 77;
pub const KVM_CAP_SPLIT_IRQCHIP: u64 = 121;
pub const KVM_CAP_EXIT_ON_EMULATION_FAILURE: u64 = 204;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmEnableCap {
    pub cap: u32,
    pub flags: u32,
    pub args: [u64; 4],
    pub pad: [u8; 64],
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
#[derive(Debug, Copy, Clone)]
pub struct KvmIoEventFd {
    pub datamatch: u64,
    pub addr: u64,
    pub len: u32,
    pub fd: i32,
    pub flags: KvmIoEventFdFlag,
    pub pad: [u8; 36],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmEncRegion {
    pub addr: u64,
    pub size: u64,
}

ioctl_none!(kvm_get_api_version, KVMIO, 0x00, 0);
ioctl_write_val!(kvm_create_vm, ioctl_io(KVMIO, 0x01));
ioctl_write_val!(kvm_check_extension, ioctl_io(KVMIO, 0x03));
ioctl_none!(kvm_get_vcpu_mmap_size, KVMIO, 0x04, 0);
#[cfg(target_arch = "x86_64")]
ioctl_writeread_buf!(kvm_get_supported_cpuid, KVMIO, 0x05, KvmCpuid2);

ioctl_write_val!(kvm_create_vcpu, ioctl_io(KVMIO, 0x41), u32);
ioctl_write_ptr!(
    kvm_set_user_memory_region,
    KVMIO,
    0x46,
    KvmUserspaceMemoryRegion
);
#[cfg(target_arch = "x86_64")]
ioctl_write_val!(kvm_set_tss_addr, ioctl_io(KVMIO, 0x47));
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_identity_map_addr, KVMIO, 0x48, u64);

ioctl_none!(kvm_create_irqchip, KVMIO, 0x60, 0);
ioctl_write_ptr!(kvm_irq_line, KVMIO, 0x61, KvmIrqLevel);

ioctl_write_ptr!(kvm_irqfd, KVMIO, 0x76, KvmIrqfd);
ioctl_write_ptr!(kvm_ioeventfd, KVMIO, 0x79, KvmIoEventFd);

ioctl_none!(kvm_run, KVMIO, 0x80, 0);
ioctl_read!(kvm_get_regs, KVMIO, 0x81, KvmRegs);
ioctl_write_ptr!(kvm_set_regs, KVMIO, 0x82, KvmRegs);
#[cfg(target_arch = "x86_64")]
ioctl_read!(kvm_get_sregs, KVMIO, 0x83, KvmSregs);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_sregs, KVMIO, 0x84, KvmSregs);
#[cfg(target_arch = "x86_64")]
ioctl_writeread_buf!(kvm_get_msrs, KVMIO, 0x88, KvmMsrs);
#[cfg(target_arch = "x86_64")]
ioctl_write_buf!(kvm_set_msrs, KVMIO, 0x89, KvmMsrs);

#[cfg(target_arch = "x86_64")]
ioctl_write_buf!(kvm_set_cpuid2, KVMIO, 0x90, KvmCpuid2);

ioctl_read!(kvm_get_mp_state, KVMIO, 0x98, KvmMpState);
ioctl_write_ptr!(kvm_set_mp_state, KVMIO, 0x99, KvmMpState);

ioctl_write_ptr!(kvm_enable_cap, KVMIO, 0xa3, KvmEnableCap);
ioctl_write_ptr!(kvm_signal_msi, KVMIO, 0xa5, KvmMsi);

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
