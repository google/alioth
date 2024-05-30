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

use std::io::{IoSlice, IoSliceMut, Read};
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::ptr::null_mut;

use bitfield::bitfield;
use bitflags::bitflags;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::ffi;
use crate::virtio::{Error, Result};

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
    #[derive(Copy, Clone, Default, AsBytes, FromBytes, FromZeroes)]
    #[repr(transparent)]
    pub struct MessageFlag(u32);
    impl Debug;
    need_reply, set_need_reply: 3;
    reply, set_reply: 2;
    version, set_version: 1, 0;
}

impl MessageFlag {
    pub const VERSION_1: u32 = 0x1;
    pub const REPLY: u32 = 1 << 2;
    pub const NEED_REPLY: u32 = 1 << 3;
    pub const fn sender() -> Self {
        MessageFlag(MessageFlag::VERSION_1 | MessageFlag::NEED_REPLY)
    }
}

#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct VirtqState {
    pub index: u32,
    pub val: u32,
}

#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct VirtqAddr {
    pub index: u32,
    pub flags: u32,
    pub desc_hva: u64,
    pub used_hva: u64,
    pub avail_hva: u64,
    pub log_guest_addr: u64,
}

#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct MemoryRegion {
    pub gpa: u64,
    pub size: u64,
    pub hva: u64,
    pub mmap_offset: u64,
}

#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct MemorySingleRegion {
    pub _padding: u64,
    pub region: MemoryRegion,
}

#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct MemoryMultipleRegion {
    pub num: u32,
    pub _padding: u32,
    pub regions: [MemoryRegion; 8],
}

#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct DeviceConfig {
    pub offset: u32,
    pub size: u32,
    pub flags: u32,
    pub region: [u8; 256],
}

#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct Message {
    pub request: u32,
    pub flag: MessageFlag,
    pub size: u32,
}

#[derive(Debug)]
pub struct VuDev {
    conn: UnixStream,
}

impl VuDev {
    pub fn new<P: AsRef<Path>>(sock: P) -> Result<Self> {
        Ok(VuDev {
            conn: UnixStream::connect(sock)?,
        })
    }

    fn send_msg<T: AsBytes, R: FromBytes + AsBytes>(
        &self,
        req: u32,
        payload: &T,
        fds: &[RawFd],
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
        let fd_size = size_of_val(fds);
        let mut cmsg_buf = if fds.is_empty() {
            vec![]
        } else {
            vec![0u8; unsafe { libc::CMSG_SPACE(fd_size as _) } as _]
        };
        let uds_msg = libc::msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: bufs.as_ptr() as _,
            msg_iovlen: if size_of::<T>() == 0 { 1 } else { 2 },
            msg_control: if fds.is_empty() {
                null_mut()
            } else {
                cmsg_buf.as_mut_ptr() as _
            },
            msg_controllen: cmsg_buf.len(),
            msg_flags: 0,
        };
        if !fds.is_empty() {
            let cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(&uds_msg) };
            let cmsg = libc::cmsghdr {
                cmsg_level: libc::SOL_SOCKET,
                cmsg_type: libc::SCM_RIGHTS,
                cmsg_len: unsafe { libc::CMSG_LEN(fd_size as _) } as _,
            };
            unsafe { std::ptr::write_unaligned(cmsg_ptr, cmsg) };
            let data =
                unsafe { std::slice::from_raw_parts_mut(libc::CMSG_DATA(cmsg_ptr), fd_size) };
            data.copy_from_slice(fds.as_bytes());
        }
        ffi!(unsafe { libc::sendmsg(self.conn.as_raw_fd(), &uds_msg, 0) })?;

        let mut resp = Message::new_zeroed();
        let mut payload = R::new_zeroed();
        let mut ret_code = u64::MAX;
        let mut bufs = if size_of::<R>() == 0 {
            [
                IoSliceMut::new(resp.as_bytes_mut()),
                IoSliceMut::new(ret_code.as_bytes_mut()),
            ]
        } else {
            [
                IoSliceMut::new(resp.as_bytes_mut()),
                IoSliceMut::new(payload.as_bytes_mut()),
            ]
        };
        let read_size = (&self.conn).read_vectored(&mut bufs)?;
        let expect_size = size_of::<Message>() + bufs[1].len();
        if read_size != expect_size {
            return Err(Error::InvalidVhostRespSize(expect_size, read_size));
        }
        if resp.request != req {
            return Err(Error::InvalidVhostRespMsg(req, resp.request));
        }
        if size_of::<R>() != 0 {
            if resp.size != size_of::<R>() as u32 {
                return Err(Error::InvalidVhostRespPayloadSize(
                    size_of::<R>(),
                    resp.size,
                ));
            }
        } else {
            if resp.size != size_of::<u64>() as u32 {
                return Err(Error::InvalidVhostRespPayloadSize(
                    size_of::<u64>(),
                    resp.size,
                ));
            }
            if ret_code != 0 {
                return Err(Error::VuRequestErr(ret_code, req));
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
    pub fn set_virtq_kick(&self, payload: &u64, fd: RawFd) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_KICK, payload, &[fd])
    }
    pub fn set_virtq_call(&self, payload: &u64, fd: RawFd) -> Result<()> {
        self.send_msg(VHOST_USER_SET_VIRTQ_CALL, payload, &[fd])
    }
    pub fn set_virtq_err(&self, payload: &u64, fd: RawFd) -> Result<()> {
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
    pub fn add_mem_region(&self, payload: &MemorySingleRegion, fd: RawFd) -> Result<()> {
        self.send_msg(VHOST_USER_ADD_MEM_REG, payload, &[fd])
    }
    pub fn remove_mem_region(&self, payload: &MemorySingleRegion) -> Result<()> {
        self.send_msg(VHOST_USER_REM_MEM_REG, payload, &[])
    }
}
