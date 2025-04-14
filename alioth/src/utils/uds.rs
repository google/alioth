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

use std::io::{ErrorKind, IoSlice, IoSliceMut, Result};
use std::iter::zip;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::ptr::{null_mut, read_unaligned, write_unaligned};

use crate::ffi;

pub const UDS_MAX_FD: usize = 32;

const CMSG_BUF_LEN: usize =
    unsafe { libc::CMSG_SPACE((UDS_MAX_FD * size_of::<RawFd>()) as u32) } as usize;

pub fn recv_msg_with_fds(
    conn: &UnixStream,
    bufs: &mut [IoSliceMut],
    fds: &mut [Option<OwnedFd>],
) -> Result<usize> {
    let mut cmsg_buf = [0u64; CMSG_BUF_LEN / size_of::<u64>()];
    let mut uds_msg = libc::msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: bufs.as_mut_ptr() as _,
        msg_iovlen: bufs.len() as _,
        msg_control: cmsg_buf.as_mut_ptr() as _,
        msg_controllen: CMSG_BUF_LEN as _,
        msg_flags: 0,
    };
    let flag = libc::MSG_CMSG_CLOEXEC;
    let size = ffi!(unsafe { libc::recvmsg(conn.as_raw_fd(), &mut uds_msg, flag) })?;

    if size == 0 {
        let buffer_size = bufs.iter().map(|b| b.len()).sum::<usize>();
        let err = if buffer_size == 0 {
            ErrorKind::InvalidInput
        } else {
            ErrorKind::ConnectionAborted
        };
        return Err(err.into());
    }

    if uds_msg.msg_flags & libc::MSG_CTRUNC > 0 {
        return Err(ErrorKind::OutOfMemory.into());
    }

    let mut overflow = false;
    let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(&uds_msg) };
    let mut iter = fds.iter_mut();
    while !cmsg_ptr.is_null() {
        let cmsg = unsafe { read_unaligned(cmsg_ptr) };
        if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
            continue;
        }

        let cmsg_data_ptr = unsafe { libc::CMSG_DATA(cmsg_ptr) } as *const RawFd;
        for i in 0.. {
            let len = unsafe { libc::CMSG_LEN((size_of::<RawFd>() * (i + 1)) as u32) };
            if len > cmsg.cmsg_len as u32 {
                break;
            }

            let raw_fd = unsafe { read_unaligned(cmsg_data_ptr.add(i)) };
            let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            if let Some(fd) = iter.next() {
                *fd = Some(owned_fd);
            } else {
                overflow = true;
            }
        }
        cmsg_ptr = unsafe { libc::CMSG_NXTHDR(&uds_msg, cmsg_ptr) };
    }

    if overflow {
        Err(ErrorKind::OutOfMemory.into())
    } else {
        Ok(size as usize)
    }
}

pub fn send_msg_with_fds(conn: &UnixStream, bufs: &[IoSlice], fds: &[RawFd]) -> Result<usize> {
    if fds.len() > UDS_MAX_FD {
        return Err(ErrorKind::OutOfMemory.into());
    }

    let mut raw_fds = [0; UDS_MAX_FD];
    for (raw_fd, fd) in zip(&mut raw_fds, fds) {
        *raw_fd = fd.as_raw_fd();
    }
    let fds_size = size_of_val(fds) as u32;
    let buf_len = if fds_size > 0 {
        unsafe { libc::CMSG_SPACE(fds_size) }
    } else {
        0
    } as usize;
    let mut cmsg_buf = [0u64; CMSG_BUF_LEN / size_of::<u64>()];
    let uds_msg = libc::msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: bufs.as_ptr() as _,
        msg_iovlen: bufs.len() as _,
        msg_control: cmsg_buf.as_mut_ptr() as _,
        msg_controllen: buf_len as _,
        msg_flags: 0,
    };
    if fds_size > 0 {
        let cmsg = libc::cmsghdr {
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
            cmsg_len: unsafe { libc::CMSG_LEN(fds_size) } as _,
        };
        let cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(&uds_msg) };
        unsafe {
            write_unaligned(cmsg_ptr, cmsg);
            write_unaligned(libc::CMSG_DATA(cmsg_ptr) as *mut _, raw_fds);
        }
    }
    let size = ffi!(unsafe { libc::sendmsg(conn.as_raw_fd(), &uds_msg, 0) })?;
    Ok(size as usize)
}
