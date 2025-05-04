// Copyright 2025 Google LLC
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
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use snafu::ResultExt;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::ffi;
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::virtio::vu::bindings::{
    DeviceConfig, MAX_CONFIG_SIZE, MemorySingleRegion, Message, MessageFlag, VirtqAddr, VirtqState,
    VuBackMsg, VuFrontMsg,
};
use crate::virtio::vu::{Result, error};

fn send<T, R>(
    mut conn: &UnixStream,
    req: u32,
    payload: &T,
    in_: &[u8],
    out: &mut [u8],
    fds: &[BorrowedFd],
) -> Result<R>
where
    T: IntoBytes + Immutable,
    R: FromBytes + IntoBytes,
{
    let vhost_msg = Message {
        request: req,
        flag: MessageFlag::sender(),
        size: (size_of::<T>() + in_.len()) as u32,
    };
    let bufs = [
        IoSlice::new(vhost_msg.as_bytes()),
        IoSlice::new(payload.as_bytes()),
        IoSlice::new(in_),
    ];
    let done = send_msg_with_fds(conn, &bufs, fds)?;
    let want = size_of_val(&vhost_msg) + vhost_msg.size as usize;
    if done != want {
        return error::PartialWrite { done, want }.fail();
    }

    let mut resp = Message::new_zeroed();
    let mut payload = R::new_zeroed();
    let mut ret_code = u64::MAX;
    let mut bufs = [
        IoSliceMut::new(resp.as_mut_bytes()),
        if size_of::<R>() > 0 {
            IoSliceMut::new(payload.as_mut_bytes())
        } else {
            IoSliceMut::new(ret_code.as_mut_bytes())
        },
        IoSliceMut::new(out),
    ];
    let resp_size = bufs[1].len() + bufs[2].len();
    let expect_size = size_of::<Message>() + resp_size;

    let size = conn.read_vectored(&mut bufs)?;
    if size != expect_size {
        return error::MsgSize {
            want: expect_size,
            got: size,
        }
        .fail();
    }
    if resp.request != req {
        return error::Response {
            want: req,
            got: resp.request,
        }
        .fail();
    }
    if resp.size as usize != resp_size {
        return error::PayloadSize {
            want: resp_size,
            got: resp.size,
        }
        .fail();
    }
    if size_of::<R>() == 0 && ret_code != 0 {
        return error::RequestErr { ret: ret_code, req }.fail();
    }

    Ok(payload)
}

fn reply<T>(conn: &UnixStream, req: u32, payload: &T, fds: &[BorrowedFd]) -> Result<()>
where
    T: IntoBytes + Immutable,
{
    let msg = Message {
        request: req,
        flag: MessageFlag::receiver(),
        size: size_of_val(payload) as _,
    };
    let bufs = [
        IoSlice::new(msg.as_bytes()),
        IoSlice::new(payload.as_bytes()),
    ];
    let done = send_msg_with_fds(conn, &bufs, fds)?;
    let want = size_of_val(&msg) + size_of_val(payload);
    if done != want {
        return error::PartialWrite { want, done }.fail();
    }
    Ok(())
}

fn reply_config(mut conn: &UnixStream, config: &DeviceConfig, buf: &[u8]) -> Result<()> {
    let msg = Message {
        request: VuFrontMsg::GET_CONFIG.raw(),
        flag: MessageFlag::receiver(),
        size: (size_of_val(config) + buf.len()) as _,
    };
    let bufs = [
        IoSlice::new(msg.as_bytes()),
        IoSlice::new(config.as_bytes()),
        IoSlice::new(buf),
    ];
    let done = conn.write_vectored(&bufs)?;
    let want = size_of_val(&msg) + msg.size as usize;
    if done != want {
        return error::PartialWrite { want, done }.fail();
    }

    Ok(())
}

fn recv_with_fds<T>(conn: &UnixStream, fds: &mut [Option<OwnedFd>]) -> Result<T>
where
    T: IntoBytes + Immutable + FromBytes,
{
    let mut msg = T::new_zeroed();
    let mut bufs = [IoSliceMut::new(msg.as_mut_bytes())];
    let size = recv_msg_with_fds(conn, &mut bufs, fds)?;
    if size != size_of::<T>() {
        error::MsgSize {
            want: size_of::<T>(),
            got: size,
        }
        .fail()
    } else {
        Ok(msg)
    }
}

fn recv_config(mut conn: &UnixStream, buf: &mut [u8]) -> Result<DeviceConfig> {
    let mut dev_config = DeviceConfig::new_zeroed();
    let mut bufs = [
        IoSliceMut::new(dev_config.as_mut_bytes()),
        IoSliceMut::new(buf),
    ];
    let got = conn.read_vectored(&mut bufs)?;
    let want = size_of::<DeviceConfig>() + dev_config.size as usize;
    if got != want {
        return error::PayloadSize {
            want,
            got: got as u32,
        }
        .fail();
    }
    Ok(dev_config)
}

#[derive(Debug)]
pub struct VuSession {
    pub conn: UnixStream,
}

impl VuSession {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = UnixStream::connect(&path).context(error::AccessSocket {
            path: path.as_ref(),
        })?;
        Ok(VuSession { conn })
    }

    fn send<T, R>(&self, req: VuFrontMsg, payload: &T, fds: &[BorrowedFd]) -> Result<R>
    where
        T: IntoBytes + Immutable,
        R: FromBytes + IntoBytes,
    {
        send(&self.conn, req.raw(), payload, &[], &mut [], fds)
    }

    pub fn recv_payload<T>(&self) -> Result<T>
    where
        T: IntoBytes + Immutable + FromBytes,
    {
        recv_with_fds(&self.conn, &mut [])
    }

    pub fn recv_config(&self, buf: &mut [u8]) -> Result<DeviceConfig> {
        recv_config(&self.conn, buf)
    }

    pub fn recv_msg(&self, fds: &mut [Option<OwnedFd>]) -> Result<Message> {
        recv_with_fds(&self.conn, fds)
    }

    pub fn reply<T: IntoBytes + Immutable>(
        &self,
        req: VuFrontMsg,
        payload: &T,
        fds: &[BorrowedFd],
    ) -> Result<()> {
        reply(&self.conn, req.raw(), payload, fds)
    }

    pub fn reply_config(&self, config: &DeviceConfig, buf: &[u8]) -> Result<()> {
        reply_config(&self.conn, config, buf)
    }

    pub fn get_features(&self) -> Result<u64> {
        self.send(VuFrontMsg::GET_FEATURES, &(), &[])
    }

    pub fn set_features(&self, payload: &u64) -> Result<()> {
        self.send(VuFrontMsg::SET_FEATURES, payload, &[])
    }

    pub fn get_protocol_features(&self) -> Result<u64> {
        self.send(VuFrontMsg::GET_PROTOCOL_FEATURES, &(), &[])
    }

    pub fn set_protocol_features(&self, payload: &u64) -> Result<u64> {
        self.send(VuFrontMsg::SET_PROTOCOL_FEATURES, payload, &[])
    }

    pub fn set_owner(&self) -> Result<()> {
        self.send(VuFrontMsg::SET_OWNER, &(), &[])
    }

    pub fn set_virtq_num(&self, payload: &VirtqState) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_NUM, payload, &[])
    }

    pub fn set_virtq_addr(&self, payload: &VirtqAddr) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_ADDR, payload, &[])
    }

    pub fn set_virtq_base(&self, payload: &VirtqState) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_BASE, payload, &[])
    }

    pub fn get_config(&self, payload: &DeviceConfig, buf: &mut [u8]) -> Result<DeviceConfig> {
        let in_ = [0; MAX_CONFIG_SIZE];
        let len = buf.len();
        let req = VuFrontMsg::GET_CONFIG.raw();
        send(&self.conn, req, payload, &in_[..len], buf, &[])
    }

    pub fn set_config(&self, payload: &DeviceConfig, buf: &[u8]) -> Result<()>
    where
        DeviceConfig: IntoBytes,
    {
        let req = VuFrontMsg::SET_CONFIG.raw();
        send(&self.conn, req, payload, buf, &mut [], &[])
    }

    pub fn get_virtq_base(&self, payload: &VirtqState) -> Result<VirtqState> {
        self.send(VuFrontMsg::GET_VIRTQ_BASE, payload, &[])
    }

    pub fn get_queue_num(&self) -> Result<u64> {
        self.send(VuFrontMsg::GET_QUEUE_NUM, &(), &[])
    }

    pub fn set_virtq_kick(&self, payload: &u64, fd: BorrowedFd) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_KICK, payload, &[fd])
    }

    pub fn set_virtq_call(&self, payload: &u64, fd: BorrowedFd) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_CALL, payload, &[fd])
    }

    pub fn set_virtq_err(&self, payload: &u64, fd: BorrowedFd) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_ERR, payload, &[fd])
    }

    pub fn set_virtq_enable(&self, payload: &VirtqState) -> Result<()> {
        self.send(VuFrontMsg::SET_VIRTQ_ENABLE, payload, &[])
    }

    pub fn set_status(&self, payload: &u64) -> Result<()> {
        self.send(VuFrontMsg::SET_STATUS, payload, &[])
    }

    pub fn get_status(&self) -> Result<u64> {
        self.send(VuFrontMsg::GET_STATUS, &(), &[])
    }

    pub fn add_mem_region(&self, payload: &MemorySingleRegion, fd: BorrowedFd) -> Result<()> {
        self.send(VuFrontMsg::ADD_MEM_REG, payload, &[fd])
    }

    pub fn remove_mem_region(&self, payload: &MemorySingleRegion) -> Result<()> {
        self.send(VuFrontMsg::REM_MEM_REG, payload, &[])
    }

    fn set_backend_req_fd(&self, fd: BorrowedFd) -> Result<()> {
        self.send(VuFrontMsg::SET_BACKEND_REQ_FD, &(), &[fd])
    }

    pub fn create_channel(&self) -> Result<VuChannel> {
        let mut socket_fds = [0; 2];
        ffi!(unsafe {
            libc::socketpair(libc::PF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr())
        })?;
        let channel = unsafe { UnixStream::from_raw_fd(socket_fds[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(socket_fds[1]) };
        self.set_backend_req_fd(peer.as_fd())?;
        Ok(VuChannel { conn: channel })
    }
}

#[derive(Debug)]
pub struct VuChannel {
    pub conn: UnixStream,
}

impl VuChannel {
    pub fn recv_payload<T>(&self) -> Result<T>
    where
        T: IntoBytes + Immutable + FromBytes,
    {
        recv_with_fds(&self.conn, &mut [])
    }

    pub fn recv_msg(&self, fds: &mut [Option<OwnedFd>]) -> Result<Message> {
        recv_with_fds(&self.conn, fds)
    }

    pub fn reply<T: IntoBytes + Immutable>(
        &self,
        req: VuBackMsg,
        payload: &T,
        fds: &[BorrowedFd],
    ) -> Result<()> {
        reply(&self.conn, req.raw(), payload, fds)
    }
}
