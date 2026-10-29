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

use core::fmt::{self, Debug, Display, Formatter};

use bitflags::bitflags;

use crate::loader::ExecType;

/// Legacy 64-bit device identifier used in shared-memory Virtio descriptors (`BridgeShm`).
pub type Handle = u64;

/// Dense 0-based vCPU index (`0..num_cpus`).
pub type VcpuId = u32;

/// Dense host physical memory object identifier returned by [`VmmHostCore::mem_alloc`].
pub type MemObjId = u32;

/// Compact `#![no_std]` hypervisor / bridge error code suitable for Ring 0 and Wasm FFI.
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HvError {
    InvalidParam = -1,
    NoMemory = -2,
    WouldBlock = -3,
    Interrupted = -4,
    Unsupported = -5,
    HardwareFault = -6,
}

impl HvError {
    #[inline]
    pub const fn code(self) -> i32 {
        self as i32
    }

    #[inline]
    pub const fn from_code(code: i32) -> Self {
        match code {
            -1 => Self::InvalidParam,
            -2 => Self::NoMemory,
            -3 => Self::WouldBlock,
            -4 => Self::Interrupted,
            -5 => Self::Unsupported,
            _ => Self::HardwareFault,
        }
    }
}

impl Display for HvError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidParam => "invalid parameter",
            Self::NoMemory => "out of memory",
            Self::WouldBlock => "operation would block",
            Self::Interrupted => "operation interrupted",
            Self::Unsupported => "unsupported operation",
            Self::HardwareFault => "hardware or hypervisor fault",
        };
        f.write_str(s)
    }
}

impl core::error::Error for HvError {}

pub type Error = HvError;
pub type HvResult<T> = core::result::Result<T, HvError>;
pub type Result<T, E = HvError> = core::result::Result<T, E>;

bitflags! {
    /// Capabilities advertised by the underlying [`VmmHostCore`] implementation.
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HostCaps: u32 {
        /// Host decodes MMIO exits into `VmExit::Mmio` (e.g. KVM, Xen, ARM64 ISV=1).
        const DECODED_MMIO = 1 << 0;
        /// Host owns an in-hypervisor IOAPIC (`set_gsi_level` supported).
        const HW_IOAPIC    = 1 << 1;
        /// Host supports fast Ring-0 `register_doorbell` matching.
        const DOORBELLS    = 1 << 2;
    }

    /// Stage-2 GPA mapping permissions passed to [`VmmHostCore::gpa_map`].
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemProt: u32 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const EXEC      = 1 << 2;
        const LOG_DIRTY = 1 << 3;
        const RWX       = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

/// Architectural multiprocessor activity state (`INIT` / `SIPI` / `HLT`).
#[repr(u32)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum MpState {
    #[default]
    Runnable = 0,
    Uninitialized = 1,
    InitReceived = 2,
    Halted = 3,
    SipiReceived = 4,
}

impl MpState {
    pub const fn from_u32(v: u32) -> HvResult<Self> {
        match v {
            0 => Ok(Self::Runnable),
            1 => Ok(Self::Uninitialized),
            2 => Ok(Self::InitReceived),
            3 => Ok(Self::Halted),
            4 => Ok(Self::SipiReceived),
            _ => Err(HvError::InvalidParam),
        }
    }
}

pub mod arch {
    use crate::hw::reg::SegAccess;

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
}

pub use arch::{Cpuid, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};

/// Unified architectural register identifier for batched [`VmmHostCore`] register access.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RegId {
    Gpr(Reg),
    SReg(SReg),
    SegReg(SegReg),
    DtReg(DtReg),
    Msr(u32),
    MpState,
}

/// Unified architectural register value paired with [`RegId`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RegVal {
    Scalar(u64),
    Seg(SegRegVal),
    Dt(DtRegVal),
    MpState(MpState),
}

impl Default for RegVal {
    fn default() -> Self {
        Self::Scalar(0)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmExit {
    Io {
        port: u16,
        write: Option<u32>,
        size: u8,
    },
    Mmio {
        gpa: u64,
        write: Option<u64>,
        size: u8,
    },
    Shutdown,
    Reboot,
    Interrupted,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmEntry {
    None,
    Shutdown,
    Reboot,
    Io { data: u32 },
    Mmio { data: u64 },
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IoSpace {
    Pio = 0,
    Mmio = 1,
}

impl IoSpace {
    pub const fn from_u32(v: u32) -> HvResult<Self> {
        match v {
            0 => Ok(Self::Pio),
            1 => Ok(Self::Mmio),
            _ => Err(HvError::InvalidParam),
        }
    }
}

/// Fast-path Ring-0 doorbell registration (e.g. `KVM_IOEVENTFD` / sorted GPA-match table).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DoorbellSpec {
    pub space: IoSpace,
    pub addr: u64,
    pub size: u8,
    pub datamatch: Option<u64>,
    pub dev_id: u32,
    pub queue_idx: u16,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Kernel = 0,
    Initramfs = 1,
}

impl PayloadKind {
    pub const fn from_u32(v: u32) -> HvResult<Self> {
        match v {
            0 => Ok(Self::Kernel),
            1 => Ok(Self::Initramfs),
            _ => Err(HvError::InvalidParam),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreBootInfo {
    pub num_cpus: u32,
    pub mem_size: usize,
    pub exec_type: Option<ExecType>,
    pub kernel_size: u64,
    pub initramfs_size: Option<u64>,
    pub cmd_line: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VirtioDeviceSpec {
    pub dev: u32,
    pub name: String,
    pub device_id: u16,
    pub device_features: u64,
    pub num_queues: u16,
    pub config_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioQueueConfig {
    pub size: u16,
    pub enabled: bool,
    pub desc_gpa: u64,
    pub avail_gpa: u64,
    pub used_gpa: u64,
}

/// Pure single-VM hardware virtualization backend (`#![no_std]`-clean, zero Virtio/UART).
pub trait VmmHostCore: Send + Sync + 'static {
    fn caps(&self) -> HostCaps;
    fn supported_cpuids(&self, dst: &mut [abi::RawCpuid]) -> HvResult<usize>;

    fn vcpu_configure(&self, vcpu: VcpuId, cpuids: &[abi::RawCpuid]) -> HvResult<()>;
    fn vcpu_get_regs(&self, vcpu: VcpuId, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()>;
    fn vcpu_set_regs(&self, vcpu: VcpuId, regs: &[(RegId, RegVal)]) -> HvResult<()>;
    fn vcpu_kick(&self, vcpu: VcpuId) -> HvResult<()>;
    fn vcpu_run(&self, vcpu: VcpuId, entry: VmEntry) -> HvResult<VmExit>;

    fn mem_alloc(&self, size: u64) -> HvResult<MemObjId>;
    fn mem_free(&self, obj: MemObjId) -> HvResult<()>;
    fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()>;
    fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()>;
    fn gpa_map(
        &self,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()>;
    fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()>;

    fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()>;
    fn set_gsi_level(&self, gsi: u32, active: bool) -> HvResult<()>;
    fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()>;
    fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()>;
}

/// Separate `#![no_std]`-clean trait for the Core <-> I/O split channel.
pub trait VmmCoreBridge: Send + Sync + 'static {
    fn boot_info(
        &self,
        out_info: &mut abi::ShmBootInfo,
        out_devs: &mut [abi::ShmVirtioDeviceSpec],
    ) -> HvResult<usize>;
    fn read_payload(&self, kind: PayloadKind, offset: u64, dst: &mut [u8]) -> HvResult<usize>;
    fn configure_device_queues(
        &self,
        dev: u32,
        queues: &[abi::ShmVirtioQueueConfig],
    ) -> HvResult<()>;
    fn update_irq_route(&self, dev: u32, routing: &abi::ShmDeviceMsixRouting) -> HvResult<()>;
    fn send_io_cmd(&self, entry: &abi::CoreToIoEntry) -> HvResult<()>;
    fn recv_io_cmd(&self, blocking: bool, out: &mut abi::IoToCoreEntry) -> HvResult<bool>;
}

pub mod abi {
    use core::sync::atomic::{AtomicU32, Ordering};
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use super::{
        Cpuid, DoorbellSpec, DtReg, DtRegVal, Handle, HvError, HvResult, IoSpace, MpState, Reg,
        RegId, RegVal, SReg, SegReg, SegRegVal, VirtioQueueConfig, VmEntry,
    };
    use crate::hw::reg::SegAccess;

    pub const ENTRY_NONE: u32 = 0;
    pub const ENTRY_SHUTDOWN: u32 = 1;
    pub const ENTRY_REBOOT: u32 = 2;
    pub const ENTRY_IO: u32 = 3;
    pub const ENTRY_MMIO: u32 = 4;

    pub const EXIT_IO: u32 = 0;
    pub const EXIT_MMIO: u32 = 1;
    pub const EXIT_SHUTDOWN: u32 = 2;
    pub const EXIT_REBOOT: u32 = 3;
    pub const EXIT_INTERRUPTED: u32 = 4;

    pub const EXEC_TYPE_NONE: u32 = 0;
    pub const EXEC_TYPE_LINUX: u32 = 1;
    pub const EXEC_TYPE_PVH: u32 = 2;

    pub const REG_CLASS_GPR: u32 = 0;
    pub const REG_CLASS_SREG: u32 = 1;
    pub const REG_CLASS_SEG: u32 = 2;
    pub const REG_CLASS_DT: u32 = 3;
    pub const REG_CLASS_MSR: u32 = 4;
    pub const REG_CLASS_MP_STATE: u32 = 5;

    pub const MAX_VIRTIO_DEVS: usize = 16;
    pub const MAX_QUEUES_PER_DEV: usize = 8;
    pub const MAX_CONFIG_BYTES: usize = 256;
    pub const MAX_DEV_NAME_LEN: usize = 64;
    pub const MAX_CMDLINE_LEN: usize = 4096;
    pub const MAX_RAM_SLOTS: usize = 32;
    pub const RING_CAPACITY: usize = 256;

    pub const CORE_MSG_VIRTIO_START: u32 = 1;
    pub const CORE_MSG_VIRTIO_NOTIFY: u32 = 2;
    pub const CORE_MSG_VIRTIO_RESET: u32 = 3;
    pub const CORE_MSG_SERIAL_TX: u32 = 4;
    pub const CORE_MSG_SHUTDOWN: u32 = 5;

    pub const IO_MSG_VIRTIO_IRQ: u32 = 1;
    pub const IO_MSG_SERIAL_RX: u32 = 2;
    pub const IO_MSG_REQUEST_SHUTDOWN: u32 = 3;

    pub const IO_BRIDGE_EVENT_VIRTIO_START: u32 = 1;
    pub const IO_BRIDGE_EVENT_VIRTIO_NOTIFY: u32 = 2;
    pub const IO_BRIDGE_EVENT_VIRTIO_RESET: u32 = 3;
    pub const IO_BRIDGE_EVENT_POLL: u32 = 4;
    pub const IO_BRIDGE_EVENT_SERIAL_INPUT: u32 = 5;
    pub const IO_BRIDGE_EVENT_SHUTDOWN: u32 = 6;
    pub const IO_BRIDGE_EVENT_SERIAL_TX: u32 = 7;

    pub const IRQ_KIND_CONFIG: u32 = 0;
    pub const IRQ_KIND_QUEUE: u32 = 1;

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, FromZeroes, FromBytes, AsBytes)]
    pub struct RawCpuid {
        pub func: u32,
        pub has_index: u32,
        pub index: u32,
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    impl From<Cpuid> for RawCpuid {
        fn from(c: Cpuid) -> Self {
            Self {
                func: c.func,
                has_index: u32::from(c.index.is_some()),
                index: c.index.unwrap_or(0),
                eax: c.eax,
                ebx: c.ebx,
                ecx: c.ecx,
                edx: c.edx,
            }
        }
    }

    impl From<RawCpuid> for Cpuid {
        fn from(r: RawCpuid) -> Self {
            Self {
                func: r.func,
                index: if r.has_index != 0 {
                    Some(r.index)
                } else {
                    None
                },
                eax: r.eax,
                ebx: r.ebx,
                ecx: r.ecx,
                edx: r.edx,
            }
        }
    }

    /// Flat 32-byte register descriptor + value used for zero-allocation Wasm FFI marshalling.
    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, FromZeroes, FromBytes, AsBytes)]
    pub struct RawRegEntry {
        pub reg_class: u32,
        pub reg_index: u32,
        pub scalar_or_base: u64,
        pub limit: u32,
        pub access: u32,
        pub selector: u16,
        pub _pad: [u8; 6],
    }

    impl RawRegEntry {
        pub fn from_id(id: RegId) -> Self {
            let (reg_class, reg_index) = match id {
                RegId::Gpr(r) => (REG_CLASS_GPR, reg_to_u32(r)),
                RegId::SReg(r) => (REG_CLASS_SREG, sreg_to_u32(r)),
                RegId::SegReg(r) => (REG_CLASS_SEG, seg_reg_to_u32(r)),
                RegId::DtReg(r) => (REG_CLASS_DT, dt_reg_to_u32(r)),
                RegId::Msr(msr) => (REG_CLASS_MSR, msr),
                RegId::MpState => (REG_CLASS_MP_STATE, 0),
            };
            Self {
                reg_class,
                reg_index,
                ..Default::default()
            }
        }

        pub fn from_pair(id: RegId, val: RegVal) -> Self {
            let mut raw = Self::from_id(id);
            raw.set_val(val);
            raw
        }

        pub fn set_val(&mut self, val: RegVal) {
            match val {
                RegVal::Scalar(v) => {
                    self.scalar_or_base = v;
                }
                RegVal::Seg(seg) => {
                    self.scalar_or_base = seg.base;
                    self.limit = seg.limit;
                    self.access = seg.access.0;
                    self.selector = seg.selector;
                }
                RegVal::Dt(dt) => {
                    self.scalar_or_base = dt.base;
                    self.limit = dt.limit as u32;
                }
                RegVal::MpState(state) => {
                    self.scalar_or_base = state as u64;
                }
            }
        }

        pub fn to_id(&self) -> HvResult<RegId> {
            match self.reg_class {
                REG_CLASS_GPR => Ok(RegId::Gpr(reg_from_u32(self.reg_index)?)),
                REG_CLASS_SREG => Ok(RegId::SReg(sreg_from_u32(self.reg_index)?)),
                REG_CLASS_SEG => Ok(RegId::SegReg(seg_reg_from_u32(self.reg_index)?)),
                REG_CLASS_DT => Ok(RegId::DtReg(dt_reg_from_u32(self.reg_index)?)),
                REG_CLASS_MSR => Ok(RegId::Msr(self.reg_index)),
                REG_CLASS_MP_STATE => Ok(RegId::MpState),
                _ => Err(HvError::InvalidParam),
            }
        }

        pub fn to_val(&self) -> HvResult<RegVal> {
            match self.reg_class {
                REG_CLASS_GPR | REG_CLASS_SREG | REG_CLASS_MSR => {
                    Ok(RegVal::Scalar(self.scalar_or_base))
                }
                REG_CLASS_SEG => Ok(RegVal::Seg(SegRegVal {
                    selector: self.selector,
                    base: self.scalar_or_base,
                    limit: self.limit,
                    access: SegAccess(self.access),
                })),
                REG_CLASS_DT => Ok(RegVal::Dt(DtRegVal {
                    base: self.scalar_or_base,
                    limit: self.limit as u16,
                })),
                REG_CLASS_MP_STATE => {
                    Ok(RegVal::MpState(MpState::from_u32(self.scalar_or_base as u32)?))
                }
                _ => Err(HvError::InvalidParam),
            }
        }

        pub fn to_pair(&self) -> HvResult<(RegId, RegVal)> {
            Ok((self.to_id()?, self.to_val()?))
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, FromZeroes, FromBytes, AsBytes)]
    pub struct RawDoorbellSpec {
        pub addr: u64,
        pub datamatch: u64,
        pub space: u32,
        pub has_datamatch: u32,
        pub dev_id: u32,
        pub queue_idx: u16,
        pub size: u8,
        pub _pad: u8,
    }

    impl From<DoorbellSpec> for RawDoorbellSpec {
        fn from(spec: DoorbellSpec) -> Self {
            Self {
                addr: spec.addr,
                datamatch: spec.datamatch.unwrap_or(0),
                space: spec.space as u32,
                has_datamatch: u32::from(spec.datamatch.is_some()),
                dev_id: spec.dev_id,
                queue_idx: spec.queue_idx,
                size: spec.size,
                _pad: 0,
            }
        }
    }

    impl RawDoorbellSpec {
        pub fn to_spec(&self) -> HvResult<DoorbellSpec> {
            Ok(DoorbellSpec {
                space: IoSpace::from_u32(self.space)?,
                addr: self.addr,
                size: self.size,
                datamatch: if self.has_datamatch != 0 {
                    Some(self.datamatch)
                } else {
                    None
                },
                dev_id: self.dev_id,
                queue_idx: self.queue_idx,
            })
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawVmExit {
        pub addr_or_port: u64,
        pub data: u64,
        pub kind: u32,
        pub is_write: u8,
        pub size: u8,
        pub _pad: [u8; 2],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct ShmBootInfo {
        pub num_cpus: u32,
        pub exec_type: u32,
        pub mem_size: u64,
        pub kernel_size: u64,
        pub initramfs_size: u64,
        pub cmd_line_len: u32,
        pub num_virtio_devs: u32,
        pub cmd_line: [u8; MAX_CMDLINE_LEN],
    }

    impl Default for ShmBootInfo {
        fn default() -> Self {
            Self {
                num_cpus: 0,
                exec_type: 0,
                mem_size: 0,
                kernel_size: 0,
                initramfs_size: 0,
                cmd_line_len: 0,
                num_virtio_devs: 0,
                cmd_line: [0; MAX_CMDLINE_LEN],
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct ShmVirtioDeviceSpec {
        pub dev: Handle,
        pub device_features: u64,
        pub device_id: u16,
        pub num_queues: u16,
        pub config_len: u16,
        pub name_len: u16,
        pub name: [u8; MAX_DEV_NAME_LEN],
        pub config_bytes: [u8; MAX_CONFIG_BYTES],
    }

    impl Default for ShmVirtioDeviceSpec {
        fn default() -> Self {
            Self {
                dev: 0,
                device_features: 0,
                device_id: 0,
                num_queues: 0,
                config_len: 0,
                name_len: 0,
                name: [0; MAX_DEV_NAME_LEN],
                config_bytes: [0; MAX_CONFIG_BYTES],
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct ShmVirtioQueueConfig {
        pub size: u16,
        pub enabled: u16,
        pub _pad: u32,
        pub desc_gpa: u64,
        pub avail_gpa: u64,
        pub used_gpa: u64,
    }

    impl From<VirtioQueueConfig> for ShmVirtioQueueConfig {
        fn from(q: VirtioQueueConfig) -> Self {
            Self {
                size: q.size,
                enabled: u16::from(q.enabled),
                _pad: 0,
                desc_gpa: q.desc_gpa,
                avail_gpa: q.avail_gpa,
                used_gpa: q.used_gpa,
            }
        }
    }

    impl From<ShmVirtioQueueConfig> for VirtioQueueConfig {
        fn from(q: ShmVirtioQueueConfig) -> Self {
            Self {
                size: q.size,
                enabled: q.enabled != 0,
                desc_gpa: q.desc_gpa,
                avail_gpa: q.avail_gpa,
                used_gpa: q.used_gpa,
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct ShmMsiEntry {
        pub addr: u64,
        pub data: u32,
        pub enabled: u32,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct ShmDeviceMsixRouting {
        pub config_msi: ShmMsiEntry,
        pub queue_msis: [ShmMsiEntry; MAX_QUEUES_PER_DEV],
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct ShmGuestRamSlot {
        pub gpa: u64,
        pub size: u64,
        pub shm_offset: u64,
        pub active: u32,
        pub _pad: u32,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct CoreToIoEntry {
        pub msg_type: u32,
        pub aux_u16: u16,
        pub _pad: u16,
        pub dev: Handle,
        pub features: u64,
        pub data: [u8; 40],
    }

    impl Default for CoreToIoEntry {
        fn default() -> Self {
            Self {
                msg_type: 0,
                aux_u16: 0,
                _pad: 0,
                dev: 0,
                features: 0,
                data: [0; 40],
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct IoToCoreEntry {
        pub msg_type: u32,
        pub irq_kind: u16,
        pub queue_index: u16,
        pub dev: Handle,
        pub data: [u8; 48],
    }

    impl Default for IoToCoreEntry {
        fn default() -> Self {
            Self {
                msg_type: 0,
                irq_kind: 0,
                queue_index: 0,
                dev: 0,
                data: [0; 48],
            }
        }
    }

    /// Shared-memory layout mapped `MAP_SHARED` into both `vmm-core-host` and `vmm-io-host`.
    #[repr(C)]
    pub struct BridgeShm {
        pub config_ready: AtomicU32,
        pub shutdown_requested: AtomicU32,
        pub ram_slots_lock: AtomicU32,
        pub msix_lock: AtomicU32,

        pub boot_info: ShmBootInfo,
        pub virtio_devs: [ShmVirtioDeviceSpec; MAX_VIRTIO_DEVS],
        pub device_queues: [[ShmVirtioQueueConfig; MAX_QUEUES_PER_DEV]; MAX_VIRTIO_DEVS],
        pub msix_routing: [ShmDeviceMsixRouting; MAX_VIRTIO_DEVS],
        pub ram_slots: [ShmGuestRamSlot; MAX_RAM_SLOTS],

        pub c2i_lock: AtomicU32,
        pub c2i_head: AtomicU32,
        pub c2i_tail: AtomicU32,
        pub _pad_c2i: u32,
        pub c2i_entries: [CoreToIoEntry; RING_CAPACITY],

        pub i2c_lock: AtomicU32,
        pub i2c_head: AtomicU32,
        pub i2c_tail: AtomicU32,
        pub _pad_i2c: u32,
        pub i2c_entries: [IoToCoreEntry; RING_CAPACITY],
    }

    #[inline]
    pub fn spin_lock(lock: &AtomicU32) {
        while lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    #[inline]
    pub fn spin_unlock(lock: &AtomicU32) {
        lock.store(0, Ordering::Release);
    }

    impl BridgeShm {
        /// Push an entry from `vmm-core-host` to `vmm-io-host`.
        /// Coalesces duplicate pending `CORE_MSG_VIRTIO_NOTIFY` entries for `(dev, queue_index)`
        /// and consecutive `CORE_MSG_SERIAL_TX` bytes (up to 40 bytes per entry).
        /// Returns `true` if the consumer (`vmm-io-host`) should be woken.
        pub unsafe fn push_core_to_io(shm: *mut BridgeShm, entry: CoreToIoEntry) -> bool {
            let lock = unsafe { &(*shm).c2i_lock };
            loop {
                spin_lock(lock);
                let head = unsafe { (*shm).c2i_head.load(Ordering::Relaxed) };
                let tail = unsafe { (*shm).c2i_tail.load(Ordering::Acquire) };

                if entry.msg_type == CORE_MSG_VIRTIO_NOTIFY {
                    let mut idx = tail;
                    while idx != head {
                        let existing =
                            unsafe { &(*shm).c2i_entries[(idx as usize) & (RING_CAPACITY - 1)] };
                        if existing.msg_type == CORE_MSG_VIRTIO_NOTIFY
                            && existing.dev == entry.dev
                            && existing.aux_u16 == entry.aux_u16
                        {
                            spin_unlock(lock);
                            return false;
                        }
                        idx = idx.wrapping_add(1);
                    }
                } else if entry.msg_type == CORE_MSG_SERIAL_TX && head != tail {
                    let last_slot = (head.wrapping_sub(1) as usize) & (RING_CAPACITY - 1);
                    let last = unsafe { &mut (*shm).c2i_entries[last_slot] };
                    let cur_len = last.aux_u16 as usize;
                    let add_len = entry.aux_u16 as usize;
                    if last.msg_type == CORE_MSG_SERIAL_TX && cur_len + add_len <= last.data.len() {
                        last.data[cur_len..cur_len + add_len]
                            .copy_from_slice(&entry.data[..add_len]);
                        last.aux_u16 = (cur_len + add_len) as u16;
                        spin_unlock(lock);
                        return false;
                    }
                }

                if head.wrapping_sub(tail) as usize >= RING_CAPACITY {
                    let shutting_down =
                        unsafe { (*shm).shutdown_requested.load(Ordering::Relaxed) != 0 };
                    spin_unlock(lock);
                    if shutting_down {
                        return false;
                    }
                    core::hint::spin_loop();
                    continue;
                }

                let was_empty = head == tail;
                let slot = (head as usize) & (RING_CAPACITY - 1);
                unsafe {
                    (*shm).c2i_entries[slot] = entry;
                    (*shm).c2i_head.store(head.wrapping_add(1), Ordering::Release);
                }
                spin_unlock(lock);
                return was_empty || entry.msg_type != CORE_MSG_VIRTIO_NOTIFY;
            }
        }

        pub unsafe fn pop_core_to_io(shm: *mut BridgeShm) -> Option<CoreToIoEntry> {
            let lock = unsafe { &(*shm).c2i_lock };
            spin_lock(lock);
            let head = unsafe { (*shm).c2i_head.load(Ordering::Acquire) };
            let tail = unsafe { (*shm).c2i_tail.load(Ordering::Relaxed) };
            if head == tail {
                spin_unlock(lock);
                return None;
            }
            let slot = (tail as usize) & (RING_CAPACITY - 1);
            let entry = unsafe { (*shm).c2i_entries[slot] };
            unsafe {
                (*shm).c2i_tail.store(tail.wrapping_add(1), Ordering::Release);
            }
            spin_unlock(lock);
            Some(entry)
        }

        /// Push an entry from `vmm-io-host` to `vmm-core-host`.
        /// Coalesces duplicate pending `IO_MSG_VIRTIO_IRQ` entries for `(dev, irq_kind, queue_index)`.
        pub unsafe fn push_io_to_core(shm: *mut BridgeShm, entry: IoToCoreEntry) -> bool {
            let lock = unsafe { &(*shm).i2c_lock };
            spin_lock(lock);
            let head = unsafe { (*shm).i2c_head.load(Ordering::Relaxed) };
            let tail = unsafe { (*shm).i2c_tail.load(Ordering::Acquire) };

            if entry.msg_type == IO_MSG_VIRTIO_IRQ {
                let mut idx = tail;
                while idx != head {
                    let existing =
                        unsafe { &(*shm).i2c_entries[(idx as usize) & (RING_CAPACITY - 1)] };
                    if existing.msg_type == IO_MSG_VIRTIO_IRQ
                        && existing.dev == entry.dev
                        && existing.irq_kind == entry.irq_kind
                        && existing.queue_index == entry.queue_index
                    {
                        spin_unlock(lock);
                        return false;
                    }
                    idx = idx.wrapping_add(1);
                }
            }

            if head.wrapping_sub(tail) as usize >= RING_CAPACITY {
                spin_unlock(lock);
                return true;
            }

            let was_empty = head == tail;
            let slot = (head as usize) & (RING_CAPACITY - 1);
            unsafe {
                (*shm).i2c_entries[slot] = entry;
                (*shm).i2c_head.store(head.wrapping_add(1), Ordering::Release);
            }
            spin_unlock(lock);
            was_empty || entry.msg_type != IO_MSG_VIRTIO_IRQ
        }

        pub unsafe fn pop_io_to_core(shm: *mut BridgeShm) -> Option<IoToCoreEntry> {
            let lock = unsafe { &(*shm).i2c_lock };
            spin_lock(lock);
            let head = unsafe { (*shm).i2c_head.load(Ordering::Acquire) };
            let tail = unsafe { (*shm).i2c_tail.load(Ordering::Relaxed) };
            if head == tail {
                spin_unlock(lock);
                return None;
            }
            let slot = (tail as usize) & (RING_CAPACITY - 1);
            let entry = unsafe { (*shm).i2c_entries[slot] };
            unsafe {
                (*shm).i2c_tail.store(tail.wrapping_add(1), Ordering::Release);
            }
            spin_unlock(lock);
            Some(entry)
        }
    }

    pub const fn reg_to_u32(r: Reg) -> u32 {
        match r {
            Reg::Rax => 0,
            Reg::Rbx => 1,
            Reg::Rcx => 2,
            Reg::Rdx => 3,
            Reg::Rsi => 4,
            Reg::Rdi => 5,
            Reg::Rsp => 6,
            Reg::Rbp => 7,
            Reg::R8 => 8,
            Reg::R9 => 9,
            Reg::R10 => 10,
            Reg::R11 => 11,
            Reg::R12 => 12,
            Reg::R13 => 13,
            Reg::R14 => 14,
            Reg::R15 => 15,
            Reg::Rip => 16,
            Reg::Rflags => 17,
        }
    }

    pub const fn reg_from_u32(v: u32) -> HvResult<Reg> {
        match v {
            0 => Ok(Reg::Rax),
            1 => Ok(Reg::Rbx),
            2 => Ok(Reg::Rcx),
            3 => Ok(Reg::Rdx),
            4 => Ok(Reg::Rsi),
            5 => Ok(Reg::Rdi),
            6 => Ok(Reg::Rsp),
            7 => Ok(Reg::Rbp),
            8 => Ok(Reg::R8),
            9 => Ok(Reg::R9),
            10 => Ok(Reg::R10),
            11 => Ok(Reg::R11),
            12 => Ok(Reg::R12),
            13 => Ok(Reg::R13),
            14 => Ok(Reg::R14),
            15 => Ok(Reg::R15),
            16 => Ok(Reg::Rip),
            17 => Ok(Reg::Rflags),
            _ => Err(HvError::InvalidParam),
        }
    }

    pub const fn sreg_to_u32(r: SReg) -> u32 {
        match r {
            SReg::Cr0 => 0,
            SReg::Cr2 => 1,
            SReg::Cr3 => 2,
            SReg::Cr4 => 3,
            SReg::Cr8 => 4,
            SReg::Efer => 5,
            SReg::ApicBase => 6,
        }
    }

    pub const fn sreg_from_u32(v: u32) -> HvResult<SReg> {
        match v {
            0 => Ok(SReg::Cr0),
            1 => Ok(SReg::Cr2),
            2 => Ok(SReg::Cr3),
            3 => Ok(SReg::Cr4),
            4 => Ok(SReg::Cr8),
            5 => Ok(SReg::Efer),
            6 => Ok(SReg::ApicBase),
            _ => Err(HvError::InvalidParam),
        }
    }

    pub const fn seg_reg_to_u32(r: SegReg) -> u32 {
        match r {
            SegReg::Cs => 0,
            SegReg::Ds => 1,
            SegReg::Es => 2,
            SegReg::Fs => 3,
            SegReg::Gs => 4,
            SegReg::Ss => 5,
            SegReg::Tr => 6,
            SegReg::Ldtr => 7,
        }
    }

    pub const fn seg_reg_from_u32(v: u32) -> HvResult<SegReg> {
        match v {
            0 => Ok(SegReg::Cs),
            1 => Ok(SegReg::Ds),
            2 => Ok(SegReg::Es),
            3 => Ok(SegReg::Fs),
            4 => Ok(SegReg::Gs),
            5 => Ok(SegReg::Ss),
            6 => Ok(SegReg::Tr),
            7 => Ok(SegReg::Ldtr),
            _ => Err(HvError::InvalidParam),
        }
    }

    pub const fn dt_reg_to_u32(r: DtReg) -> u32 {
        match r {
            DtReg::Gdtr => 0,
            DtReg::Idtr => 1,
        }
    }

    pub const fn dt_reg_from_u32(v: u32) -> HvResult<DtReg> {
        match v {
            0 => Ok(DtReg::Gdtr),
            1 => Ok(DtReg::Idtr),
            _ => Err(HvError::InvalidParam),
        }
    }

    pub const fn encode_vm_entry(e: VmEntry) -> (u32, u64) {
        match e {
            VmEntry::None => (ENTRY_NONE, 0),
            VmEntry::Shutdown => (ENTRY_SHUTDOWN, 0),
            VmEntry::Reboot => (ENTRY_REBOOT, 0),
            VmEntry::Io { data } => (ENTRY_IO, data as u64),
            VmEntry::Mmio { data } => (ENTRY_MMIO, data),
        }
    }

    pub const fn decode_vm_entry(kind: u32, data: u64) -> VmEntry {
        match kind {
            ENTRY_SHUTDOWN => VmEntry::Shutdown,
            ENTRY_REBOOT => VmEntry::Reboot,
            ENTRY_IO => VmEntry::Io { data: data as u32 },
            ENTRY_MMIO => VmEntry::Mmio { data },
            _ => VmEntry::None,
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::hw::reg::SegAccess;
    use crate::sync::Mutex;

    use super::{
        DoorbellSpec, DtReg, DtRegVal, HostCaps, HvError, HvResult, IoSpace, MemObjId, MemProt,
        MpState, Reg, RegId, RegVal, SReg, SegReg, SegRegVal, VcpuId, VmEntry, VmExit, VmmHostCore,
    };

    pub struct FakeHost {
        next_obj: AtomicU32,
        objs: Mutex<BTreeMap<MemObjId, Vec<u8>>>,
        mappings: Mutex<BTreeMap<u64, (u64, MemObjId, u64)>>,
        msis: Mutex<Vec<(u64, u32)>>,
        doorbells: Mutex<Vec<DoorbellSpec>>,
    }

    impl Default for FakeHost {
        fn default() -> Self {
            Self {
                next_obj: AtomicU32::new(1),
                objs: Mutex::new(BTreeMap::new()),
                mappings: Mutex::new(BTreeMap::new()),
                msis: Mutex::new(Vec::new()),
                doorbells: Mutex::new(Vec::new()),
            }
        }
    }

    impl FakeHost {
        pub fn new_arc() -> Arc<dyn VmmHostCore> {
            Arc::new(Self::default())
        }

        pub fn take_msis(&self) -> Vec<(u64, u32)> {
            std::mem::take(&mut *self.msis.lock())
        }

        pub fn doorbells(&self) -> Vec<DoorbellSpec> {
            self.doorbells.lock().clone()
        }
    }

    impl VmmHostCore for FakeHost {
        fn caps(&self) -> HostCaps {
            HostCaps::DECODED_MMIO | HostCaps::DOORBELLS
        }

        fn supported_cpuids(&self, _dst: &mut [super::abi::RawCpuid]) -> HvResult<usize> {
            Ok(0)
        }

        fn vcpu_configure(&self, _vcpu: VcpuId, _cpuids: &[super::abi::RawCpuid]) -> HvResult<()> {
            Ok(())
        }

        fn vcpu_get_regs(
            &self,
            _vcpu: VcpuId,
            _ids: &[RegId],
            _out: &mut [RegVal],
        ) -> HvResult<()> {
            Ok(())
        }

        fn vcpu_set_regs(&self, _vcpu: VcpuId, _regs: &[(RegId, RegVal)]) -> HvResult<()> {
            Ok(())
        }

        fn vcpu_kick(&self, _vcpu: VcpuId) -> HvResult<()> {
            Ok(())
        }

        fn vcpu_run(&self, _vcpu: VcpuId, _entry: VmEntry) -> HvResult<VmExit> {
            Ok(VmExit::Shutdown)
        }

        fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
            let id = self.next_obj.fetch_add(1, Ordering::Relaxed);
            self.objs.lock().insert(id, vec![0u8; size as usize]);
            Ok(id)
        }

        fn mem_free(&self, obj: MemObjId) -> HvResult<()> {
            self.objs
                .lock()
                .remove(&obj)
                .map(|_| ())
                .ok_or(HvError::InvalidParam)
        }

        fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()> {
            let objs = self.objs.lock();
            let buf = objs.get(&obj).ok_or(HvError::InvalidParam)?;
            let start = offset as usize;
            let end = start.checked_add(dst.len()).ok_or(HvError::InvalidParam)?;
            if end > buf.len() {
                return Err(HvError::InvalidParam);
            }
            dst.copy_from_slice(&buf[start..end]);
            Ok(())
        }

        fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()> {
            let mut objs = self.objs.lock();
            let buf = objs.get_mut(&obj).ok_or(HvError::InvalidParam)?;
            let start = offset as usize;
            let end = start.checked_add(src.len()).ok_or(HvError::InvalidParam)?;
            if end > buf.len() {
                return Err(HvError::InvalidParam);
            }
            buf[start..end].copy_from_slice(src);
            Ok(())
        }

        fn gpa_map(
            &self,
            gpa: u64,
            size: u64,
            obj: MemObjId,
            offset: u64,
            prot: MemProt,
        ) -> HvResult<()> {
            if !prot.contains(MemProt::READ) || size == 0 {
                return Err(HvError::InvalidParam);
            }
            let objs = self.objs.lock();
            let buf = objs.get(&obj).ok_or(HvError::InvalidParam)?;
            if offset.checked_add(size).is_none_or(|end| end > buf.len() as u64) {
                return Err(HvError::InvalidParam);
            }
            drop(objs);
            self.mappings.lock().insert(gpa, (size, obj, offset));
            Ok(())
        }

        fn gpa_unmap(&self, gpa: u64, _size: u64) -> HvResult<()> {
            self.mappings
                .lock()
                .remove(&gpa)
                .map(|_| ())
                .ok_or(HvError::InvalidParam)
        }

        fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()> {
            self.msis.lock().push((addr, data));
            Ok(())
        }

        fn set_gsi_level(&self, _gsi: u32, _active: bool) -> HvResult<()> {
            Ok(())
        }

        fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()> {
            self.doorbells.lock().push(spec);
            Ok(())
        }

        fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()> {
            self.doorbells
                .lock()
                .retain(|d| !(d.space == space && d.addr == addr && d.size == size));
            Ok(())
        }
    }

    #[test]
    fn test_raw_reg_entry_roundtrip() {
        use super::abi::RawRegEntry;

        let cases = [
            (RegId::Gpr(Reg::R15), RegVal::Scalar(0xdead_beef_cafe_babe)),
            (RegId::SReg(SReg::Efer), RegVal::Scalar(0x501)),
            (
                RegId::SegReg(SegReg::Cs),
                RegVal::Seg(SegRegVal {
                    selector: 0x10,
                    base: 0,
                    limit: 0xffff_ffff,
                    access: SegAccess(0xa09b),
                }),
            ),
            (
                RegId::DtReg(DtReg::Gdtr),
                RegVal::Dt(DtRegVal {
                    base: 0x500,
                    limit: 0xff,
                }),
            ),
            (RegId::Msr(0xc000_0082), RegVal::Scalar(0xffff_ffff_8100_0000)),
            (RegId::MpState, RegVal::MpState(MpState::Uninitialized)),
        ];

        for (id, val) in cases {
            let raw = RawRegEntry::from_pair(id, val);
            assert_eq!(raw.to_pair().unwrap(), (id, val));
        }
    }

    #[test]
    fn test_bridge_shm_coalescing() {
        use super::abi::{
            BridgeShm, CORE_MSG_SERIAL_TX, CORE_MSG_VIRTIO_NOTIFY, CoreToIoEntry,
            IO_MSG_VIRTIO_IRQ, IRQ_KIND_QUEUE, IoToCoreEntry,
        };

        let layout = Layout::new::<BridgeShm>();
        let shm = unsafe { alloc_zeroed(layout) as *mut BridgeShm };
        assert!(!shm.is_null());

        unsafe {
            let notify_ev = CoreToIoEntry {
                msg_type: CORE_MSG_VIRTIO_NOTIFY,
                aux_u16: 1,
                dev: 3,
                ..Default::default()
            };
            assert!(BridgeShm::push_core_to_io(shm, notify_ev));
            assert!(!BridgeShm::push_core_to_io(shm, notify_ev));
            let popped = BridgeShm::pop_core_to_io(shm).unwrap();
            assert_eq!(popped.msg_type, CORE_MSG_VIRTIO_NOTIFY);
            assert_eq!(popped.dev, 3);
            assert_eq!(popped.aux_u16, 1);
            assert!(BridgeShm::pop_core_to_io(shm).is_none());

            for &b in b"hello" {
                let mut tx = CoreToIoEntry {
                    msg_type: CORE_MSG_SERIAL_TX,
                    aux_u16: 1,
                    ..Default::default()
                };
                tx.data[0] = b;
                let _ = BridgeShm::push_core_to_io(shm, tx);
            }
            let popped_tx = BridgeShm::pop_core_to_io(shm).unwrap();
            assert_eq!(popped_tx.msg_type, CORE_MSG_SERIAL_TX);
            assert_eq!(popped_tx.aux_u16, 5);
            assert_eq!(&popped_tx.data[..5], b"hello");
            assert!(BridgeShm::pop_core_to_io(shm).is_none());

            let irq_ev = IoToCoreEntry {
                msg_type: IO_MSG_VIRTIO_IRQ,
                irq_kind: IRQ_KIND_QUEUE as u16,
                queue_index: 0,
                dev: 2,
                ..Default::default()
            };
            assert!(BridgeShm::push_io_to_core(shm, irq_ev));
            assert!(!BridgeShm::push_io_to_core(shm, irq_ev));
            let popped_irq = BridgeShm::pop_io_to_core(shm).unwrap();
            assert_eq!(popped_irq.msg_type, IO_MSG_VIRTIO_IRQ);
            assert_eq!(popped_irq.dev, 2);
            assert!(BridgeShm::pop_io_to_core(shm).is_none());

            dealloc(shm as *mut u8, layout);
        }
    }
}
