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

use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitfield::bitfield;
use bitflags::bitflags;
use parking_lot::Mutex;
use snafu::{ResultExt, Snafu};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::errors::{BoxTrace, DebugTrace, trace_error};
use crate::mem::LayoutChanged;
use crate::mem::mapped::ArcMemPages;
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::{ffi, mem};

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct VuFeature: u64 {
        const MQ = 1 << 0;
        const LOG_SHMFD = 1 << 1;
        const RARP = 1 << 2;
        const REPLY_ACK = 1 << 3;
        const MTU = 1 << 4;
        const BACKEND_REQ = 1 << 5;
        const CROSS_ENDIAN = 1 << 6;
        const CRYPTO_SESSION = 1 << 7;
        const PAGEFAULT = 1 << 8;
        const CONFIG = 1 << 9;
        const BACKEND_SEND_FD = 1 << 10;
        const HOST_NOTIFIER = 1 << 11;
        const INFLIGHT_SHMFD = 1 << 12;
        const RESET_DEVICE = 1 << 13;
        const INBAND_NOTIFICATIONS = 1 << 14;
        const CONFIGURE_MEM_SLOTS = 1 << 15;
        const STATUS = 1 << 16;
        const XEN_MMAP = 1 << 17;
        const SHARED_OBJECT = 1 << 18;
        const DEVICE_STATE = 1 << 19;
    }
}

pub const VHOST_USER_GET_FEATURES: u32 = 1;
pub const VHOST_USER_SET_FEATURES: u32 = 2;
pub const VHOST_USER_SET_OWNER: u32 = 3;
#[deprecated]
pub const VHOST_USER_RESET_OWNER: u32 = 4;
pub const VHOST_USER_SET_MEM_TABLE: u32 = 5;
pub const VHOST_USER_SET_LOG_BASE: u32 = 6;
pub const VHOST_USER_SET_LOG_FD: u32 = 7;
pub const VHOST_USER_SET_VIRTQ_NUM: u32 = 8;
pub const VHOST_USER_SET_VIRTQ_ADDR: u32 = 9;
pub const VHOST_USER_SET_VIRTQ_BASE: u32 = 10;
pub const VHOST_USER_GET_VIRTQ_BASE: u32 = 11;
pub const VHOST_USER_SET_VIRTQ_KICK: u32 = 12;
pub const VHOST_USER_SET_VIRTQ_CALL: u32 = 13;
pub const VHOST_USER_SET_VIRTQ_ERR: u32 = 14;
pub const VHOST_USER_GET_PROTOCOL_FEATURES: u32 = 15;
pub const VHOST_USER_SET_PROTOCOL_FEATURES: u32 = 16;
pub const VHOST_USER_GET_QUEUE_NUM: u32 = 17;
pub const VHOST_USER_SET_VIRTQ_ENABLE: u32 = 18;
pub const VHOST_USER_SEND_RARP: u32 = 19;
pub const VHOST_USER_NET_SET_MTU: u32 = 20;
pub const VHOST_USER_SET_BACKEND_REQ_FD: u32 = 21;
pub const VHOST_USER_IOTLB_MSG: u32 = 22;
pub const VHOST_USER_SET_VIRTQ_ENDIAN: u32 = 23;
pub const VHOST_USER_GET_CONFIG: u32 = 24;
pub const VHOST_USER_SET_CONFIG: u32 = 25;
pub const VHOST_USER_CREATE_CRYPTO_SESSION: u32 = 26;
pub const VHOST_USER_CLOSE_CRYPTO_SESSION: u32 = 27;
pub const VHOST_USER_POSTCOPY_ADVISE: u32 = 28;
pub const VHOST_USER_POSTCOPY_LISTEN: u32 = 29;
pub const VHOST_USER_POSTCOPY_END: u32 = 30;
pub const VHOST_USER_GET_INFLIGHT_FD: u32 = 31;
pub const VHOST_USER_SET_INFLIGHT_FD: u32 = 32;
pub const VHOST_USER_GPU_SET_SOCKET: u32 = 33;
pub const VHOST_USER_RESET_DEVICE: u32 = 34;
pub const VHOST_USER_GET_MAX_MEM_SLOTS: u32 = 36;
pub const VHOST_USER_ADD_MEM_REG: u32 = 37;
pub const VHOST_USER_REM_MEM_REG: u32 = 38;
pub const VHOST_USER_SET_STATUS: u32 = 39;
pub const VHOST_USER_GET_STATUS: u32 = 40;
pub const VHOST_USER_GET_SHARED_OBJECT: u32 = 41;
pub const VHOST_USER_SET_DEVICE_STATE_FD: u32 = 42;
pub const VHOST_USER_CHECK_DEVICE_STATE: u32 = 43;

bitfield! {
    #[derive(Copy, Clone, Default, IntoBytes, FromBytes, Immutable)]
    #[repr(transparent)]
    pub struct MessageFlag(u32);
    impl Debug;
    need_reply, set_need_reply: 3;
    reply, set_reply: 2;
    version, set_version: 1, 0;
}

impl MessageFlag {
    pub const NEED_REPLY: u32 = 1 << 3;
    pub const REPLY: u32 = 1 << 2;
    pub const VERSION_1: u32 = 0x1;

    pub const fn sender() -> Self {
        MessageFlag(MessageFlag::VERSION_1 | MessageFlag::NEED_REPLY)
    }

    pub const fn receiver() -> Self {
        MessageFlag(MessageFlag::VERSION_1 | MessageFlag::REPLY)
    }
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct VirtqState {
    pub index: u32,
    pub val: u32,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct VirtqAddr {
    pub index: u32,
    pub flags: u32,
    pub desc_hva: u64,
    pub used_hva: u64,
    pub avail_hva: u64,
    pub log_guest_addr: u64,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct MemoryRegion {
    pub gpa: u64,
    pub size: u64,
    pub hva: u64,
    pub mmap_offset: u64,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct MemorySingleRegion {
    pub _padding: u64,
    pub region: MemoryRegion,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct MemoryMultipleRegion {
    pub num: u32,
    pub _padding: u32,
    pub regions: [MemoryRegion; 8],
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct DeviceConfig {
    pub offset: u32,
    pub size: u32,
    pub flags: u32,
    pub region: [u8; 256],
}

#[derive(Debug, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct Message {
    pub request: u32,
    pub flag: MessageFlag,
    pub size: u32,
}

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Cannot access socket {path:?}"))]
    AccessSocket {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Invalid vhost-user response message, want {want}, got {got}"))]
    InvalidResp { want: u32, got: u32 },
    #[snafu(display("Invalid vhost-user message size, want {want}, get {got}"))]
    MsgSize { want: usize, got: usize },
    #[snafu(display("Invalid vhost-user message payload size, want {want}, got {got}"))]
    PayloadSize { want: usize, got: u32 },
    #[snafu(display("vhost-user backend replied error code {ret:#x} to request {req:#x}"))]
    RequestErr { ret: u64, req: u32 },
    #[snafu(display("vhost-user backend signaled an error of queue {index:#x}"))]
    QueueErr { index: u16 },
    #[snafu(display("vhost-user backend is missing device feature {feature:#x}"))]
    DeviceFeature { feature: u64 },
    #[snafu(display("vhost-user backend is missing protocol feature {feature:x?}"))]
    ProtocolFeature { feature: VuFeature },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct VuDev {
    conn: Mutex<UnixStream>,
    channel: Option<UnixStream>,
}

impl VuDev {
    pub fn new<P: AsRef<Path>>(sock: P) -> Result<Self> {
        let conn = UnixStream::connect(&sock).context(error::AccessSocket {
            path: sock.as_ref(),
        })?;
        Ok(VuDev {
            conn: Mutex::new(conn),
            channel: None,
        })
    }

    pub fn setup_channel(&mut self) -> Result<()> {
        if self.channel.is_some() {
            return Ok(());
        }
        let mut socket_fds = [0; 2];
        ffi!(unsafe {
            libc::socketpair(libc::PF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr())
        })?;
        let channel = unsafe { UnixStream::from_raw_fd(socket_fds[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(socket_fds[1]) };
        self.set_backend_req_fd(peer.as_fd())?;
        self.channel = Some(channel);
        Ok(())
    }

    pub fn get_channel(&self) -> Option<&UnixStream> {
        self.channel.as_ref()
    }

    fn send_msg<T: IntoBytes + Immutable, R: FromBytes + IntoBytes>(
        &self,
        req: u32,
        payload: &T,
        fds: &[BorrowedFd],
    ) -> Result<R> {
        let vhost_msg = Message {
            request: req,
            flag: MessageFlag::sender(),
            size: size_of::<T>() as u32,
        };
        let bufs = [
            IoSlice::new(vhost_msg.as_bytes()),
            IoSlice::new(payload.as_bytes()),
        ];
        let mut conn = self.conn.lock();
        send_msg_with_fds(&conn, &bufs, fds)?;

        let mut resp = Message::new_zeroed();
        let mut payload = R::new_zeroed();
        let mut ret_code = u64::MAX;
        let mut bufs = if size_of::<R>() == 0 {
            [
                IoSliceMut::new(resp.as_mut_bytes()),
                IoSliceMut::new(ret_code.as_mut_bytes()),
            ]
        } else {
            [
                IoSliceMut::new(resp.as_mut_bytes()),
                IoSliceMut::new(payload.as_mut_bytes()),
            ]
        };
        let read_size = conn.read_vectored(&mut bufs)?;
        let expect_size = size_of::<Message>() + bufs[1].len();
        if read_size != expect_size {
            return error::MsgSize {
                want: expect_size,
                got: read_size,
            }
            .fail();
        }
        if resp.request != req {
            return error::InvalidResp {
                want: req,
                got: resp.request,
            }
            .fail();
        }
        if size_of::<R>() != 0 {
            if resp.size != size_of::<R>() as u32 {
                return error::PayloadSize {
                    want: size_of::<R>(),
                    got: resp.size,
                }
                .fail();
            }
        } else {
            if resp.size != size_of::<u64>() as u32 {
                return error::PayloadSize {
                    want: size_of::<u64>(),
                    got: resp.size,
                }
                .fail();
            }
            if ret_code != 0 {
                return error::RequestErr { ret: ret_code, req }.fail();
            }
        }
        Ok(payload)
    }

    pub fn get_features(&self) -> Result<u64> {
        self.send_msg(VHOST_USER_GET_FEATURES, &(), &[])
    }

    pub fn set_features(&self, payload: &u64) -> Result<()> {
        self.send_msg(VHOST_USER_SET_FEATURES, payload, &[])
    }

    pub fn get_protocol_features(&self) -> Result<u64> {
        self.send_msg(VHOST_USER_GET_PROTOCOL_FEATURES, &(), &[])
    }

    pub fn set_protocol_features(&self, payload: &u64) -> Result<u64> {
        self.send_msg(VHOST_USER_SET_PROTOCOL_FEATURES, payload, &[])
    }

    pub fn set_owner(&self) -> Result<()> {
        self.send_msg(VHOST_USER_SET_OWNER, &(), &[])
    }

    pub fn set_virtq_num(&self, payload: &VirtqState) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_NUM, payload, &[])
    }

    pub fn set_virtq_addr(&self, payload: &VirtqAddr) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_ADDR, payload, &[])
    }

    pub fn set_virtq_base(&self, payload: &VirtqState) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_BASE, payload, &[])
    }

    pub fn get_config(&self, payload: &DeviceConfig) -> Result<DeviceConfig> {
        self.send_msg(VHOST_USER_GET_CONFIG, payload, &[])
    }

    pub fn set_config(&self, payload: &DeviceConfig) -> Result<()> {
        self.send_msg(VHOST_USER_SET_CONFIG, payload, &[])
    }

    pub fn get_virtq_base(&self, payload: &VirtqState) -> Result<VirtqState> {
        self.send_msg(VHOST_USER_GET_VIRTQ_BASE, payload, &[])
    }

    pub fn get_queue_num(&self) -> Result<u64> {
        self.send_msg(VHOST_USER_GET_QUEUE_NUM, &(), &[])
    }

    pub fn set_virtq_kick(&self, payload: &u64, fd: BorrowedFd) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_KICK, payload, &[fd])
    }

    pub fn set_virtq_call(&self, payload: &u64, fd: BorrowedFd) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_CALL, payload, &[fd])
    }

    pub fn set_virtq_err(&self, payload: &u64, fd: BorrowedFd) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_ERR, payload, &[fd])
    }

    pub fn set_virtq_enable(&self, payload: &VirtqState) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_ENABLE, payload, &[])
    }

    pub fn set_status(&self, payload: &u64) -> Result<()> {
        self.send_msg(VHOST_USER_SET_STATUS, payload, &[])
    }

    pub fn get_status(&self) -> Result<u64> {
        self.send_msg(VHOST_USER_GET_STATUS, &(), &[])
    }

    pub fn add_mem_region(&self, payload: &MemorySingleRegion, fd: BorrowedFd) -> Result<()> {
        self.send_msg(VHOST_USER_ADD_MEM_REG, payload, &[fd])
    }

    pub fn remove_mem_region(&self, payload: &MemorySingleRegion) -> Result<()> {
        self.send_msg(VHOST_USER_REM_MEM_REG, payload, &[])
    }

    fn set_backend_req_fd(&self, fd: BorrowedFd) -> Result<()> {
        self.send_msg(VHOST_USER_SET_BACKEND_REQ_FD, &0u64, &[fd])
    }

    pub fn receive_from_channel(
        &self,
        buf: &mut [u8],
        fds: &mut [Option<OwnedFd>],
    ) -> Result<(u32, u32)> {
        let mut msg = Message::new_zeroed();
        let mut bufs = [IoSliceMut::new(msg.as_mut_bytes()), IoSliceMut::new(buf)];
        let Some(channel) = &self.channel else {
            return error::ProtocolFeature {
                feature: VuFeature::BACKEND_REQ,
            }
            .fail();
        };
        let r_size = recv_msg_with_fds(channel, &mut bufs, fds)?;
        let expected_size = size_of::<Message>() + msg.size as usize;
        if r_size != expected_size {
            return error::MsgSize {
                want: expected_size,
                got: r_size,
            }
            .fail();
        }
        Ok((msg.request, msg.size))
    }

    pub fn ack_request<T: IntoBytes + Immutable>(&self, req: u32, payload: &T) -> Result<()> {
        let Some(channel) = &self.channel else {
            return error::ProtocolFeature {
                feature: VuFeature::BACKEND_REQ,
            }
            .fail();
        };
        let msg = Message {
            request: req,
            flag: MessageFlag::receiver(),
            size: size_of_val(payload) as _,
        };
        let bufs = [
            IoSlice::new(msg.as_bytes()),
            IoSlice::new(payload.as_bytes()),
        ];
        Write::write_vectored(&mut (&*channel), &bufs)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct UpdateVuMem {
    pub dev: Arc<VuDev>,
}

impl LayoutChanged for UpdateVuMem {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((fd, offset)) = pages.fd() else {
            return Ok(());
        };
        let region = MemorySingleRegion {
            _padding: 0,
            region: MemoryRegion {
                gpa: gpa as _,
                size: pages.size() as _,
                hva: pages.addr() as _,
                mmap_offset: offset,
            },
        };
        let ret = self.dev.add_mem_region(&region, fd);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!(
            "vu-{}: added memory region {:x?}",
            self.dev.conn.lock().as_raw_fd(),
            region.region
        );
        Ok(())
    }

    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((_, offset)) = pages.fd() else {
            return Ok(());
        };
        let region = MemorySingleRegion {
            _padding: 0,
            region: MemoryRegion {
                gpa: gpa as _,
                size: pages.size() as _,
                hva: pages.addr() as _,
                mmap_offset: offset,
            },
        };
        let ret = self.dev.remove_mem_region(&region);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!(
            "vu-{}: removed memory region {:x?}",
            self.dev.conn.lock().as_raw_fd(),
            region.region
        );
        Ok(())
    }
}
