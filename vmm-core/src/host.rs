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

use std::fmt::Debug;
use std::sync::Arc;

use bitflags::bitflags;
use thiserror::Error;

use crate::loader::ExecType;

/// Resource handle (file descriptor / table index).
/// Note: On Linux this is `u32` at the raw Wasm FFI / KVM boundary to match the
/// existing KVM API, but in our host traits it is `u64` to be more generic.
pub type Handle = u64;

pub mod arch {
    use crate::hw::reg::SegAccess;

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
}

pub use arch::{Cpuid, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Interest: u8 {
        const READABLE = 1 << 0;
        const WRITABLE = 1 << 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct PollEvent {
    pub token: Token,
    pub is_readable: bool,
    pub is_writable: bool,
}

impl PollEvent {
    pub fn token(&self) -> Token {
        self.token
    }

    pub fn is_readable(&self) -> bool {
        self.is_readable
    }

    pub fn is_writable(&self) -> bool {
        self.is_writable
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid memory map option for {hypervisor}: {option:?}")]
    MemMapOption {
        option: MemMapOption,
        hypervisor: &'static str,
    },
    #[error("IO error: {source}")]
    StdIo {
        #[from]
        source: std::io::Error,
    },
    #[error("{msg}")]
    Unexpected { msg: String },
    #[error("lack capability: {cap}")]
    LackCap { cap: String },
    #[error("creating multiple memory")]
    CreatingMultipleMemory,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemMapOption {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub log_dirty: bool,
}

impl Default for MemMapOption {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            exec: true,
            log_dirty: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    Io {
        port: u16,
        write: Option<u32>,
        size: u8,
    },
    Mmio {
        addr: u64,
        write: Option<u64>,
        size: u8,
    },
    Shutdown,
    Reboot,
    Unknown(String),
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmEntry {
    None,
    Shutdown,
    Reboot,
    Io { data: u32 },
    Mmio { data: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Kernel = 0,
    Initramfs = 1,
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
    pub dev: Handle,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioIrqKind {
    Config,
    Queue(u16),
}

#[derive(Debug, Clone)]
pub enum IoBridgeEvent {
    VirtioStart {
        dev: Handle,
        driver_features: u64,
        queues: Vec<VirtioQueueConfig>,
    },
    VirtioNotify {
        dev: Handle,
        queue_index: u16,
    },
    VirtioReset {
        dev: Handle,
    },
    Poll(PollEvent),
    SerialInput,
    SerialTx(Vec<u8>),
    Shutdown,
}

pub trait MemPages: Debug + Send + Sync + 'static {
    fn addr(&self) -> u64;
    fn size(&self) -> usize;
    fn sync(&self) -> std::io::Result<()>;
    fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()>;
    fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()>;
}

pub trait VmMemory: Debug + Send + Sync + 'static {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
        size: usize,
        hva: u64,
        option: MemMapOption,
    ) -> Result<(), Error>;

    fn unmap(&self, slot: u32, gpa: u64, size: usize) -> Result<(), Error>;

    fn max_mem_slots(&self) -> Result<u32, Error>;

    fn register_encrypted_range(&self, addr: u64, size: usize) -> Result<()>;

    fn deregister_encrypted_range(&self, addr: u64, size: usize) -> Result<()>;

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>>;
}

pub trait IntxSender: Debug + Send + Sync + 'static {
    fn send(&self) -> Result<(), Error>;
}

impl<T: IntxSender + ?Sized> IntxSender for Arc<T> {
    fn send(&self) -> Result<(), Error> {
        IntxSender::send(self.as_ref())
    }
}

impl<T: IntxSender + ?Sized> IntxSender for Box<T> {
    fn send(&self) -> Result<(), Error> {
        IntxSender::send(self.as_ref())
    }
}

pub trait MsiSender: Debug + Send + Sync + 'static {
    fn send(&self, addr: u64, data: u32) -> Result<()>;
}

impl<T: MsiSender + ?Sized> MsiSender for Arc<T> {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        MsiSender::send(self.as_ref(), addr, data)
    }
}

impl<T: MsiSender + ?Sized> MsiSender for Box<T> {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        MsiSender::send(self.as_ref(), addr, data)
    }
}

pub trait Vcpu: Send + Sync + 'static {
    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error>;
    fn get_reg(&self, reg: Reg) -> Result<u64, Error>;
    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error>;
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error>;
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error>;
    fn get_sreg(&self, reg: SReg) -> Result<u64, Error>;
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error>;
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error>;
    fn dump(&self) -> Result<(), Error>;
}

pub trait Vm: Debug + Send + Sync + 'static {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error>;
    fn stop_vcpu(&self, id: u32) -> Result<(), Error>;
    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error>;
    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error>;
    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error>;
}

pub trait Hypervisor: Debug + Send + Sync + 'static {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error>;
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error>;

    // --- Cross-Split Core <-> IO Bridge Methods ---
    fn core_get_boot_info(&self) -> Result<(CoreBootInfo, Vec<VirtioDeviceSpec>), Error>;
    fn core_read_payload(&self, kind: PayloadKind, offset: u64, dst: &mut [u8]) -> Result<usize, Error>;
    fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> Result<(), Error>;
    fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> Result<(), Error>;
    fn core_virtio_reset(&self, dev: Handle) -> Result<(), Error>;
    fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> Result<(), Error>;
    fn core_serial_tx(&self, byte: u8) -> Result<(), Error>;
    fn core_serial_rx(&self, dst: &mut [u8]) -> Result<usize, Error>;
    fn core_notify_shutdown(&self) -> Result<(), Error>;
}

pub mod abi {
    use std::sync::atomic::{AtomicU32, Ordering};
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use super::{
        Cpuid, DtReg, DtRegVal, Handle, MemMapOption, Reg, SReg, SegReg, SegRegVal,
        VirtioQueueConfig, VmEntry,
    };
    use crate::hw::reg::SegAccess;

    pub const ERR_GENERIC: i32 = -1;
    pub const ERR_WOULD_BLOCK: i32 = -2;
    pub const ERR_INTERRUPTED: i32 = -3;
    pub const ERR_EOF: i32 = -4;

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
    pub const EXIT_UNKNOWN: u32 = 5;

    pub const EXEC_TYPE_NONE: u32 = 0;
    pub const EXEC_TYPE_LINUX: u32 = 1;
    pub const EXEC_TYPE_PVH: u32 = 2;

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
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
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

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawRegVal {
        pub reg: u32,
        pub _pad: u32,
        pub val: u64,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawSegRegVal {
        pub base: u64,
        pub limit: u32,
        pub access: u32,
        pub selector: u16,
        pub _pad: [u8; 6],
    }

    impl From<SegRegVal> for RawSegRegVal {
        fn from(v: SegRegVal) -> Self {
            Self {
                base: v.base,
                limit: v.limit,
                access: v.access.0,
                selector: v.selector,
                _pad: [0; 6],
            }
        }
    }

    impl From<RawSegRegVal> for SegRegVal {
        fn from(v: RawSegRegVal) -> Self {
            Self {
                selector: v.selector,
                base: v.base,
                limit: v.limit,
                access: SegAccess(v.access),
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawSegRegEntry {
        pub reg: u32,
        pub _pad: u32,
        pub val: RawSegRegVal,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawDtRegVal {
        pub base: u64,
        pub limit: u16,
        pub _pad: [u8; 6],
    }

    impl From<DtRegVal> for RawDtRegVal {
        fn from(v: DtRegVal) -> Self {
            Self {
                base: v.base,
                limit: v.limit,
                _pad: [0; 6],
            }
        }
    }

    impl From<RawDtRegVal> for DtRegVal {
        fn from(v: RawDtRegVal) -> Self {
            Self {
                base: v.base,
                limit: v.limit,
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawDtRegEntry {
        pub reg: u32,
        pub _pad: u32,
        pub val: RawDtRegVal,
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

    #[repr(C)]
    #[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawIoBridgeEvent {
        pub kind: u32,
        pub queue_index: u16,
        pub num_queues: u16,
        pub dev: Handle,
        pub driver_features: u64,
        pub token: u64,
        pub is_readable: u8,
        pub is_writable: u8,
        pub tx_len: u8,
        pub _pad: [u8; 5],
        pub tx_bytes: [u8; 40],
        pub queues: [ShmVirtioQueueConfig; MAX_QUEUES_PER_DEV],
    }

    impl Default for RawIoBridgeEvent {
        fn default() -> Self {
            Self {
                kind: 0,
                queue_index: 0,
                num_queues: 0,
                dev: 0,
                driver_features: 0,
                token: 0,
                is_readable: 0,
                is_writable: 0,
                tx_len: 0,
                _pad: [0; 5],
                tx_bytes: [0; 40],
                queues: [ShmVirtioQueueConfig::default(); MAX_QUEUES_PER_DEV],
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
            std::hint::spin_loop();
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
        /// Returns `true` if the consumer (`vmm-io-host`) should be woken via `eventfd`.
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
                    std::thread::yield_now();
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
                    let existing = unsafe { &(*shm).i2c_entries[(idx as usize) & (RING_CAPACITY - 1)] };
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

    pub fn reg_to_u32(r: Reg) -> u32 {
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

    pub fn reg_from_u32(v: u32) -> Reg {
        match v {
            0 => Reg::Rax,
            1 => Reg::Rbx,
            2 => Reg::Rcx,
            3 => Reg::Rdx,
            4 => Reg::Rsi,
            5 => Reg::Rdi,
            6 => Reg::Rsp,
            7 => Reg::Rbp,
            8 => Reg::R8,
            9 => Reg::R9,
            10 => Reg::R10,
            11 => Reg::R11,
            12 => Reg::R12,
            13 => Reg::R13,
            14 => Reg::R14,
            15 => Reg::R15,
            16 => Reg::Rip,
            _ => Reg::Rflags,
        }
    }

    pub fn sreg_to_u32(r: SReg) -> u32 {
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

    pub fn sreg_from_u32(v: u32) -> SReg {
        match v {
            0 => SReg::Cr0,
            1 => SReg::Cr2,
            2 => SReg::Cr3,
            3 => SReg::Cr4,
            4 => SReg::Cr8,
            5 => SReg::Efer,
            _ => SReg::ApicBase,
        }
    }

    pub fn seg_reg_to_u32(r: SegReg) -> u32 {
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

    pub fn seg_reg_from_u32(v: u32) -> SegReg {
        match v {
            0 => SegReg::Cs,
            1 => SegReg::Ds,
            2 => SegReg::Es,
            3 => SegReg::Fs,
            4 => SegReg::Gs,
            5 => SegReg::Ss,
            6 => SegReg::Tr,
            _ => SegReg::Ldtr,
        }
    }

    pub fn dt_reg_to_u32(r: DtReg) -> u32 {
        match r {
            DtReg::Gdtr => 0,
            DtReg::Idtr => 1,
        }
    }

    pub fn dt_reg_from_u32(v: u32) -> DtReg {
        match v {
            0 => DtReg::Gdtr,
            _ => DtReg::Idtr,
        }
    }

    pub fn mem_map_option_to_u32(o: MemMapOption) -> u32 {
        (u32::from(o.read))
            | (u32::from(o.write) << 1)
            | (u32::from(o.exec) << 2)
            | (u32::from(o.log_dirty) << 3)
    }

    pub fn mem_map_option_from_u32(v: u32) -> MemMapOption {
        MemMapOption {
            read: (v & 1) != 0,
            write: (v & 2) != 0,
            exec: (v & 4) != 0,
            log_dirty: (v & 8) != 0,
        }
    }

    pub fn encode_vm_entry(e: VmEntry) -> (u32, u64) {
        match e {
            VmEntry::None => (ENTRY_NONE, 0),
            VmEntry::Shutdown => (ENTRY_SHUTDOWN, 0),
            VmEntry::Reboot => (ENTRY_REBOOT, 0),
            VmEntry::Io { data } => (ENTRY_IO, data as u64),
            VmEntry::Mmio { data } => (ENTRY_MMIO, data),
        }
    }

    pub fn decode_vm_entry(kind: u32, data: u64) -> VmEntry {
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
    use std::sync::Arc;

    use super::{Error, MemMapOption, MemPages, Result, VmMemory};
    use crate::hw::layout::PAGE_SIZE;

    #[derive(Debug)]
    pub struct FakeMemPages {
        addr: usize,
        size: usize,
        layout: Option<Layout>,
    }

    impl FakeMemPages {
        pub fn new(size: usize) -> Self {
            let layout = Layout::from_size_align(size, PAGE_SIZE).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Self {
                addr: ptr as usize,
                size,
                layout: Some(layout),
            }
        }

        pub unsafe fn from_raw(addr: u64, size: usize) -> Self {
            Self {
                addr: addr as usize,
                size,
                layout: None,
            }
        }
    }

    impl Drop for FakeMemPages {
        fn drop(&mut self) {
            if let Some(layout) = self.layout {
                unsafe { dealloc(self.addr as *mut u8, layout) };
            }
        }
    }

    impl MemPages for FakeMemPages {
        fn addr(&self) -> u64 {
            self.addr as u64
        }

        fn size(&self) -> usize {
            self.size
        }

        fn sync(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()> {
            let src =
                unsafe { std::slice::from_raw_parts((self.addr + offset) as *const u8, dst.len()) };
            dst.copy_from_slice(src);
            Ok(())
        }

        fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
            let dst = unsafe {
                std::slice::from_raw_parts_mut((self.addr + offset) as *mut u8, src.len())
            };
            dst.copy_from_slice(src);
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct FakeVmMemoryStruct;

    impl VmMemory for FakeVmMemoryStruct {
        fn mem_map(
            &self,
            _slot: u32,
            _gpa: u64,
            _size: usize,
            _hva: u64,
            option: MemMapOption,
        ) -> Result<(), Error> {
            if !option.read || !option.exec {
                return Err(Error::MemMapOption {
                    option,
                    hypervisor: "fake",
                });
            }
            Ok(())
        }

        fn unmap(&self, _slot: u32, _gpa: u64, _size: usize) -> Result<(), Error> {
            Ok(())
        }

        fn max_mem_slots(&self) -> Result<u32, Error> {
            Ok(32)
        }

        fn register_encrypted_range(&self, _addr: u64, _size: usize) -> Result<()> {
            Ok(())
        }

        fn deregister_encrypted_range(&self, _addr: u64, _size: usize) -> Result<()> {
            Ok(())
        }

        fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
            Ok(Arc::new(FakeMemPages::new(size)))
        }
    }

    #[allow(non_snake_case)]
    pub fn FakeVmMemory() -> Box<dyn VmMemory> {
        Box::new(FakeVmMemoryStruct)
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
            // 1. Duplicate CORE_MSG_VIRTIO_NOTIFY for the same (dev, queue) should coalesce
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

            // 2. Consecutive CORE_MSG_SERIAL_TX bytes should coalesce into one entry
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

            // 3. Duplicate IO_MSG_VIRTIO_IRQ for the same (dev, irq_kind, queue_index) should coalesce
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
