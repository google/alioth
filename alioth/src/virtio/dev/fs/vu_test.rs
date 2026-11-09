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

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::{slice, thread};

use assert_matches::assert_matches;
use libc::PROT_NONE;
use rstest::rstest;
use zerocopy::IntoBytes;

use crate::mem::mapped::ArcMemPages;
use crate::virtio::dev::fs::vu::handle_backend_req;
use crate::virtio::vu::Error as VuError;
use crate::virtio::vu::bindings::{Message, MessageFlag, VhostUserMmap, VuBackMsg};
use crate::virtio::vu::conn::VuChannel;
use crate::virtio::{Error, Result};

const WINDOW_SIZE: u64 = 0x1000;

fn fixture_window() -> ArcMemPages {
    ArcMemPages::from_anonymous(WINDOW_SIZE as usize, Some(PROT_NONE), None).unwrap()
}

/// Returns the channel of the frontend and that of the backend.
fn fixture_channels() -> (VuChannel, VuChannel) {
    let (front, back) = UnixStream::pair().unwrap();
    (VuChannel { conn: front }, VuChannel { conn: back })
}

/// Receives a request from the backend and handles it.
fn handle_req(front: &VuChannel, window: &ArcMemPages) -> Result<()> {
    let mut fd = None;
    let msg = front.recv_msg(slice::from_mut(&mut fd)).unwrap();
    handle_backend_req("test", front, window, &msg, fd)
}

#[rstest]
#[case(0, true)]
#[case(WINDOW_SIZE, false)]
fn shmem_map(#[case] offset: u64, #[case] valid: bool) {
    let window = fixture_window();
    let (front, back) = fixture_channels();
    let file = tempfile::tempfile().unwrap();
    file.set_len(WINDOW_SIZE).unwrap();

    let payload = VhostUserMmap {
        shm_offset: offset,
        len: WINDOW_SIZE,
        ..Default::default()
    };
    let backend = thread::spawn(move || back.shmem_map(&payload, file.as_fd()));
    // A failed request does not stop the frontend.
    assert_matches!(handle_req(&front, &window), Ok(()));
    let ret = backend.join().unwrap();
    if valid {
        assert_matches!(ret, Ok(()));
    } else {
        assert_matches!(ret, Err(VuError::RequestErr { ret: u64::MAX, .. }));
    }
}

#[test]
fn unsupported_req() {
    let window = fixture_window();
    let (front, back) = fixture_channels();

    let msg = Message {
        request: VuBackMsg::CONFIG_CHANGE_MSG.raw(),
        flag: MessageFlag::sender(),
        size: 0,
    };
    (&back.conn).write_all(msg.as_bytes()).unwrap();
    assert_matches!(
        handle_req(&front, &window),
        Err(Error::Vu { source, .. }) if matches!(*source, VuError::UnsupportedReq { req: 2, .. })
    );
}

#[test]
fn no_reply() {
    let window = fixture_window();
    let (front, back) = fixture_channels();

    // The backend does not ask for a reply.
    let msg = Message {
        request: VuBackMsg::SHMEM_UNMAP.raw(),
        flag: MessageFlag(MessageFlag::VERSION_1),
        size: size_of::<VhostUserMmap>() as u32,
    };
    let payload = VhostUserMmap {
        len: WINDOW_SIZE,
        ..Default::default()
    };
    (&back.conn).write_all(msg.as_bytes()).unwrap();
    (&back.conn).write_all(payload.as_bytes()).unwrap();
    assert_matches!(handle_req(&front, &window), Ok(()));

    back.conn.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 1];
    assert_matches!(
        (&back.conn).read(&mut buf),
        Err(e) if e.kind() == ErrorKind::WouldBlock
    );
}
