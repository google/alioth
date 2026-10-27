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

use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::path::{Path, PathBuf};

use bitflags::bitflags;
use zerocopy::{AsBytes, FromBytes};

use crate::virtio::dev::net::NetFeature;

/// Resource handle (file descriptor / table index).
/// Note: On Linux this is `u32` at the raw Wasm FFI / KVM boundary to match the
/// existing KVM API, but in our host traits it is `u64` to be more generic.
pub type Handle = u64;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecKind {
    Linux = 1,
    Pvh = 2,
}

#[derive(Debug, Clone)]
pub struct IoBootConfig {
    pub num_cpus: u32,
    pub mem_size: usize,
    pub exec_kind: Option<ExecKind>,
    pub kernel_path: Option<PathBuf>,
    pub initramfs_path: Option<PathBuf>,
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

pub trait Tap: Debug + Send + Sync + 'static {
    fn detected_offload(&self) -> NetFeature;
    fn enable_offload(&mut self, feature: NetFeature) -> io::Result<()>;
    fn register(&self, token: Token, interests: Interest) -> io::Result<()>;
    fn deregister(&self);
    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize>;
    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize>;
}

impl Read for &dyn Tap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Tap::read_vectored(*self, &mut [IoSliceMut::new(buf)])
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        Tap::read_vectored(*self, bufs)
    }
}

impl Write for &dyn Tap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Tap::write_vectored(*self, &[IoSlice::new(buf)])
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        Tap::write_vectored(*self, bufs)
    }
}

pub trait BlockBackend: Debug + Send + Sync + 'static {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()>;
    fn write_at(&self, offset: u64, src: &[u8]) -> io::Result<()>;
    fn flush(&self) -> io::Result<()>;
}

pub trait SerialConsole: Debug + Send + Sync + 'static {
    fn write_byte(&self, byte: u8) -> io::Result<()>;
    fn read_input(&self, data: &mut VecDeque<u8>) -> io::Result<Option<usize>>;
    fn shutdown(&self) -> io::Result<()>;
}

pub trait GuestMemAccess: Debug + Send + Sync + 'static {
    fn read_bytes(&self, gpa: u64, dst: &mut [u8]) -> io::Result<()>;
    fn write_bytes(&self, gpa: u64, src: &[u8]) -> io::Result<()>;
}

impl dyn GuestMemAccess {
    pub fn read<T: FromBytes>(&self, gpa: u64) -> io::Result<T> {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        self.read_bytes(gpa, &mut buf)?;
        T::read_from(&buf).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "FromBytes::read_from failed")
        })
    }

    pub fn write<T: AsBytes>(&self, gpa: u64, val: &T) -> io::Result<()> {
        self.write_bytes(gpa, val.as_bytes())
    }
}

pub trait IoHost: GuestMemAccess {
    fn create_tap(&self, if_name: Option<&str>) -> io::Result<Box<dyn Tap>>;
    fn open_block(&self, path: &Path, read_only: bool) -> io::Result<Box<dyn BlockBackend>>;
    fn create_serial_console(&self) -> io::Result<Box<dyn SerialConsole>>;

    fn io_register_vm_config(
        &self,
        boot_cfg: &IoBootConfig,
        virtio_devs: &[VirtioDeviceSpec],
    ) -> io::Result<()>;
    fn io_next_event(&self) -> io::Result<IoBridgeEvent>;
    fn io_request_shutdown(&self) -> io::Result<()>;
    fn io_virtio_irq(&self, dev: Handle, kind: VirtioIrqKind) -> io::Result<()>;
    fn io_serial_push_rx(&self, data: &[u8]) -> io::Result<()>;
}

pub mod abi {
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use super::{Handle, VirtioQueueConfig};

    pub const ERR_GENERIC: i32 = -1;
    pub const ERR_WOULD_BLOCK: i32 = -2;
    pub const ERR_INTERRUPTED: i32 = -3;
    pub const ERR_EOF: i32 = -4;

    pub const EXEC_TYPE_NONE: u32 = 0;
    pub const EXEC_TYPE_LINUX: u32 = 1;
    pub const EXEC_TYPE_PVH: u32 = 2;

    pub const MAX_VIRTIO_DEVS: usize = 16;
    pub const MAX_QUEUES_PER_DEV: usize = 8;
    pub const MAX_CONFIG_BYTES: usize = 256;
    pub const MAX_DEV_NAME_LEN: usize = 64;
    pub const MAX_CMDLINE_LEN: usize = 4096;
    pub const MAX_PATH_LEN: usize = 1024;

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
    #[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawIoBootConfig {
        pub num_cpus: u32,
        pub exec_type: u32,
        pub mem_size: u64,
        pub kernel_path_len: u32,
        pub initramfs_path_len: u32,
        pub cmd_line_len: u32,
        pub _pad: u32,
        pub kernel_path: [u8; MAX_PATH_LEN],
        pub initramfs_path: [u8; MAX_PATH_LEN],
        pub cmd_line: [u8; MAX_CMDLINE_LEN],
    }

    impl Default for RawIoBootConfig {
        fn default() -> Self {
            Self {
                num_cpus: 0,
                exec_type: 0,
                mem_size: 0,
                kernel_path_len: 0,
                initramfs_path_len: 0,
                cmd_line_len: 0,
                _pad: 0,
                kernel_path: [0; MAX_PATH_LEN],
                initramfs_path: [0; MAX_PATH_LEN],
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
}
