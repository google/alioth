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
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::thread;

use assert_matches::assert_matches;
use zerocopy::{FromBytes, IntoBytes};

use crate::sync::notifier::Notifier;
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::vfio::user::Error;
use crate::vfio::user::bindings::{
    VfioUserCmd, VfioUserHeader, VfioUserHeaderFlag, VfioUserIoFdType, VfioUserMessageType,
    VfioUserRegionIoFds, VfioUserSubRegionIoeventFd, VfioUserVersion,
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

/// Receives a `DEVICE_GET_REGION_IO_FDS` request and replies with `entries`,
/// as libvfio-user does: the sub-region array is only sent if the client left
/// room for all of it, otherwise the reply is the header alone.
fn serve_region_io_fds(
    server: &UnixStream,
    entries: &[VfioUserSubRegionIoeventFd],
    fds: &[BorrowedFd<'_>],
) -> VfioUserRegionIoFds {
    let mut req_header = VfioUserHeader::default();
    let mut req = VfioUserRegionIoFds::default();
    let mut req_slice = [
        IoSliceMut::new(req_header.as_mut_bytes()),
        IoSliceMut::new(req.as_mut_bytes()),
    ];
    recv_msg_with_fds(server, &mut req_slice, &mut []).unwrap();
    assert_eq!(req_header.cmd, VfioUserCmd::DEVICE_GET_REGION_IO_FDS);
    assert_eq!(req.flags, 0);
    assert_eq!(req.count, 0);

    let argsz = size_of::<VfioUserRegionIoFds>() + size_of_val(entries);
    let reply = VfioUserRegionIoFds {
        argsz: argsz as u32,
        flags: 0,
        index: req.index,
        count: entries.len() as u32,
    };
    let fits = req.argsz as usize >= argsz;
    let (payload, fds): (&[u8], &[BorrowedFd]) = if fits {
        (entries.as_bytes(), fds)
    } else {
        (&[], &[])
    };
    let reply_hdr = VfioUserHeader {
        msg_id: req_header.msg_id,
        cmd: req_header.cmd,
        msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserRegionIoFds>() + payload.len())
            as u32,
        flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
        error_no: 0,
    };
    let slices = [
        IoSlice::new(reply_hdr.as_bytes()),
        IoSlice::new(reply.as_bytes()),
        IoSlice::new(payload),
    ];
    send_msg_with_fds(server, &slices, fds).unwrap();
    req
}

fn ioeventfd(offset: u64, fd_index: u32) -> VfioUserSubRegionIoeventFd {
    VfioUserSubRegionIoeventFd {
        offset,
        size: 4,
        fd_index,
        type_: VfioUserIoFdType::IOEVENTFD,
        ..Default::default()
    }
}

#[test]
fn test_vfio_user_get_region_io_fds() {
    let (client, server) = UnixStream::pair().unwrap();
    let notifier = Notifier::new().unwrap();
    let server_handle = thread::spawn(move || {
        // Two sub-regions sharing one file descriptor.
        let entries = [ioeventfd(0x1000, 0), ioeventfd(0x1004, 0)];
        serve_region_io_fds(&server, &entries, &[notifier.as_fd()])
    });

    let session = VfioUserSession::new(client);
    let (entries, fds) = session.get_region_io_fds(2).unwrap();

    let req = server_handle.join().unwrap();
    assert_eq!(req.index, 2);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].offset, 0x1000);
    assert_eq!(entries[1].offset, 0x1004);
    assert_eq!(entries[1].fd_index, 0);
    assert!(fds[0].is_some());
    assert!(fds[1].is_none());
}

#[test]
fn test_vfio_user_get_region_io_fds_empty() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || serve_region_io_fds(&server, &[], &[]));

    let session = VfioUserSession::new(client);
    let (entries, fds) = session.get_region_io_fds(0).unwrap();

    server_handle.join().unwrap();
    assert!(entries.is_empty());
    assert!(fds.iter().all(Option::is_none));
}

#[test]
fn test_vfio_user_get_region_io_fds_too_many() {
    // More sub-regions than the first request makes room for, so the server
    // replies with the header only and the client has to ask again.
    let count = 40;
    let (client, server) = UnixStream::pair().unwrap();
    let notifier = Notifier::new().unwrap();
    let server_handle = thread::spawn(move || {
        let entries: Vec<_> = (0..count)
            .map(|i| ioeventfd(0x1000 + i as u64 * 4, 0))
            .collect();
        let first = serve_region_io_fds(&server, &entries, &[notifier.as_fd()]);
        let second = serve_region_io_fds(&server, &entries, &[notifier.as_fd()]);
        (first, second)
    });

    let session = VfioUserSession::new(client);
    let (entries, fds) = session.get_region_io_fds(0).unwrap();

    let (first, second) = server_handle.join().unwrap();
    let entry_size = size_of::<VfioUserSubRegionIoeventFd>();
    assert_eq!(
        first.argsz as usize,
        size_of::<VfioUserRegionIoFds>() + 32 * entry_size
    );
    assert_eq!(
        second.argsz as usize,
        size_of::<VfioUserRegionIoFds>() + count * entry_size
    );
    assert_eq!(entries.len(), count);
    assert!(fds[0].is_some());
}

#[test]
fn test_vfio_user_get_region_io_fds_bad_argsz() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        let mut req_header = VfioUserHeader::default();
        let mut req = VfioUserRegionIoFds::default();
        let mut req_slice = [
            IoSliceMut::new(req_header.as_mut_bytes()),
            IoSliceMut::new(req.as_mut_bytes()),
        ];
        recv_msg_with_fds(&server, &mut req_slice, &mut []).unwrap();

        // count and argsz disagree, e.g. a server sending 40-byte entries.
        let reply = VfioUserRegionIoFds {
            argsz: (size_of::<VfioUserRegionIoFds>() + 40) as u32,
            flags: 0,
            index: req.index,
            count: 1,
        };
        let reply_hdr = VfioUserHeader {
            msg_id: req_header.msg_id,
            cmd: req_header.cmd,
            msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserRegionIoFds>() + 40) as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
            error_no: 0,
        };
        let slices = [
            IoSlice::new(reply_hdr.as_bytes()),
            IoSlice::new(reply.as_bytes()),
            IoSlice::new(&[0u8; 40]),
        ];
        send_msg_with_fds(&server, &slices, &[]).unwrap();
    });

    let session = VfioUserSession::new(client);
    let res = session.get_region_io_fds(1);
    assert_matches!(res, Err(Error::IoFds { count: 1, .. }));

    server_handle.join().unwrap();
}

#[test]
fn test_vfio_user_get_region_io_fds_short_reply() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        let mut req_header = VfioUserHeader::default();
        let mut req = VfioUserRegionIoFds::default();
        let mut req_slice = [
            IoSliceMut::new(req_header.as_mut_bytes()),
            IoSliceMut::new(req.as_mut_bytes()),
        ];
        recv_msg_with_fds(&server, &mut req_slice, &mut []).unwrap();

        // count <= capacity and argsz matches count, but the reply omits the
        // sub-region array payload.
        let reply = VfioUserRegionIoFds {
            argsz: (size_of::<VfioUserRegionIoFds>() + size_of::<VfioUserSubRegionIoeventFd>())
                as u32,
            flags: 0,
            index: req.index,
            count: 1,
        };
        let reply_hdr = VfioUserHeader {
            msg_id: req_header.msg_id,
            cmd: req_header.cmd,
            msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserRegionIoFds>()) as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
            error_no: 0,
        };
        let slices = [
            IoSlice::new(reply_hdr.as_bytes()),
            IoSlice::new(reply.as_bytes()),
        ];
        send_msg_with_fds(&server, &slices, &[]).unwrap();
    });

    let session = VfioUserSession::new(client);
    let res = session.get_region_io_fds(1);
    assert_matches!(res, Err(Error::PartialRead { .. }));

    server_handle.join().unwrap();
}
