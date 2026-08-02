// Copyright 2026 Google LLC
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

use std::io::{IoSlice, IoSliceMut};
use std::os::unix::net::UnixStream;
use std::thread;

use assert_matches::assert_matches;
use zerocopy::{FromBytes, IntoBytes};

use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::vfio::user::Error;
use crate::vfio::user::bindings::{
    VfioUserCmd, VfioUserHeader, VfioUserHeaderFlag, VfioUserMessageType, VfioUserVersion,
};
use crate::vfio::user::conn::VfioUserSession;

#[test]
fn test_vfio_user_version_server_mismatch() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        let mut header_buf = [0u8; size_of::<VfioUserHeader>()];
        let mut recv_fds = [const { None }; 32];
        let mut header_slice = [IoSliceMut::new(&mut header_buf)];
        recv_msg_with_fds(&server, &mut header_slice, &mut recv_fds).unwrap();
        let (req_header, _) = VfioUserHeader::read_from_prefix(&header_buf).unwrap();

        // Server sends major version 1 (mismatch)
        let reply_version = VfioUserVersion { major: 1, minor: 0 };
        let reply_hdr = VfioUserHeader {
            msg_id: req_header.msg_id,
            cmd: VfioUserCmd::VERSION,
            msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserVersion>()) as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
            error_no: 0,
        };
        let slices = [
            IoSlice::new(reply_hdr.as_bytes()),
            IoSlice::new(reply_version.as_bytes()),
        ];
        send_msg_with_fds(&server, &slices, &[]).unwrap();
    });

    let session = VfioUserSession::new(client);
    let res = session.negotiate_version();
    assert_matches!(
        res,
        Err(Error::Version {
            major: 1,
            minor: 0,
            ..
        })
    );

    server_handle.join().unwrap();
}

#[test]
fn test_vfio_user_server_error_response() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        let mut req_header = VfioUserHeader::default();
        let mut header_slice = [IoSliceMut::new(req_header.as_mut_bytes())];
        recv_msg_with_fds(&server, &mut header_slice, &mut []).unwrap();

        // Server replies with ERROR flag and EINVAL
        let reply_hdr = VfioUserHeader {
            msg_id: req_header.msg_id,
            cmd: req_header.cmd,
            msg_size: size_of::<VfioUserHeader>() as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, true),
            error_no: 22,
        };
        let slices = [IoSlice::new(reply_hdr.as_bytes())];
        send_msg_with_fds(&server, &slices, &[]).unwrap();
    });

    let session = VfioUserSession::new(client);
    let res = session.reset();
    assert_matches!(
        res,
        Err(Error::ServerErr {
            cmd: VfioUserCmd::DEVICE_RESET,
            code: 22,
            ..
        })
    );

    server_handle.join().unwrap();
}
