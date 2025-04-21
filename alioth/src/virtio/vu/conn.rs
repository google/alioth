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

use std::io::{IoSlice, IoSliceMut, Read};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use snafu::ResultExt;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::ffi;
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::virtio::vu::bindings::{
    DeviceConfig, MemorySingleRegion, Message, MessageFlag, VirtqAddr, VirtqState, VuBackMsg,
    VuFrontMsg,
};
use crate::virtio::vu::{Result, error};

fn send<T, R>(mut conn: &UnixStream, req: u32, payload: &T, fds: &[BorrowedFd]) -> Result<R>
where
    T: IntoBytes + Immutable,
    R: FromBytes + IntoBytes,
{
    let vhost_msg = Message {
        request: req,
        flag: MessageFlag::sender(),
        size: size_of::<T>() as u32,
    };
    let bufs = [
        IoSlice::new(vhost_msg.as_bytes()),
        IoSlice::new(payload.as_bytes()),
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
    ];
    let resp_size = bufs[1].len() as u32;
    let expect_size = size_of::<Message>() + bufs[1].len();

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
    if resp.size != resp_size {
        return error::PayloadSize {
            want: size_of::<R>(),
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
        send(&self.conn, req.raw(), payload, fds)
    }

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
        req: VuFrontMsg,
        payload: &T,
        fds: &[BorrowedFd],
    ) -> Result<()> {
        reply(&self.conn, req.raw(), payload, fds)
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

    pub fn get_config(&self, payload: &DeviceConfig) -> Result<DeviceConfig> {
        self.send(VuFrontMsg::GET_CONFIG, payload, &[])
    }

    pub fn set_config(&self, payload: &DeviceConfig) -> Result<()> {
        self.send(VuFrontMsg::SET_CONFIG, payload, &[])
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
