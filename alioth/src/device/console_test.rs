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

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use flume::Sender;
use libc::{O_NOCTTY, POLLIN, pollfd};
use mio::Token;
use parking_lot::Mutex;
use rstest::rstest;
use tempfile::TempDir;

use crate::device::console::{
    Console, ConsoleSpec, ConsoleThread, PTY_TAIL_SIZE, PtyConsole, PtyConsoleSpec, UartRecv,
};
use crate::device::{Error, Result};
use crate::ffi;
use crate::sync::notifier::Notifier;

#[derive(Debug)]
pub struct TestConsole {
    pub notifier: Mutex<Notifier>,
    pub inbound: Mutex<VecDeque<u8>>,
    pub outbound: Mutex<VecDeque<u8>>,
}

impl TestConsole {
    pub fn new() -> Result<Self> {
        Ok(Self {
            notifier: Mutex::new(Notifier::new()?),
            inbound: Mutex::new(VecDeque::new()),
            outbound: Mutex::new(VecDeque::new()),
        })
    }
}

impl Read for &TestConsole {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(&mut *self.inbound.lock(), buf)
    }
}

impl Write for &TestConsole {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(&mut *self.outbound.lock(), buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut *self.outbound.lock())
    }
}

impl Console for TestConsole {
    const TOKEN_INPUT: Token = Token(0);

    fn activate(&self, registry: &mio::Registry) -> io::Result<()> {
        registry.register(
            &mut *self.notifier.lock(),
            Self::TOKEN_INPUT,
            mio::Interest::READABLE,
        )
    }

    fn deactivate(&self, registry: &mio::Registry) -> io::Result<()> {
        registry.deregister(&mut *self.notifier.lock())
    }
}

struct ChannelRecv(Sender<Vec<u8>>);

impl UartRecv for ChannelRecv {
    fn receive(&self, bytes: &[u8]) {
        self.0.send(bytes.to_vec()).unwrap();
    }
}

fn open_slave(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_NOCTTY)
        .open(path)
        .unwrap()
}

/// Reads from `file` until the data ends with `suffix`, waiting at most 5
/// seconds for each read.
fn read_until(mut file: &File, suffix: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buf = [0; 4096];
    while !data.ends_with(suffix) {
        let mut fds = pollfd {
            fd: file.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        assert_eq!(ffi!(unsafe { libc::poll(&mut fds, 1, 5000) }).unwrap(), 1);
        let len = file.read(&mut buf).unwrap();
        data.extend_from_slice(&buf[..len]);
    }
    data
}

#[test]
fn test_pty_console() {
    let console = Arc::new(PtyConsole::new(&PtyConsoleSpec::default()).unwrap());
    let (tx, rx) = flume::unbounded();
    let _thread = ConsoleThread::new("pty".into(), ChannelRecv(tx), console.clone()).unwrap();

    // The console keeps working after a client disconnects.
    for _ in 0..2 {
        let mut client = open_slave(console.path());

        client.write_all(b"a\r\n").unwrap();
        let mut input = Vec::new();
        while input.len() < 3 {
            input.extend(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        }
        assert_eq!(input, b"a\r\n");

        (&*console).write_all(b"b\r\n").unwrap();
        assert_eq!(read_until(&client, b"b\r\n"), b"b\r\n");
    }
}

#[test]
fn test_pty_console_full() {
    let console = PtyConsole::new(&PtyConsoleSpec::default()).unwrap();

    // Far more output than the PTY buffer holds, with nobody reading. The PTY
    // cannot take all of it, so the last write finds the buffer full and
    // replaces the unread output with the newest output.
    let mut output = vec![b'.'; 1 << 20];
    output.extend(b"~ # l");
    (&console).write_all(&output).unwrap();

    // A client connecting late sees the newest output.
    let client = open_slave(console.path());
    let tail = &output[output.len() - PTY_TAIL_SIZE..];
    assert_eq!(read_until(&client, b"~ # l"), tail);
}

#[test]
fn test_pty_console_link() {
    let temp_dir = TempDir::new().unwrap();
    let link: Box<Path> = temp_dir.path().join("console").into();
    let spec = PtyConsoleSpec {
        link: Some(link.clone()),
    };

    // A stale link is replaced, and removed with the console.
    unix::fs::symlink("/dev/null", &link).unwrap();
    let console = PtyConsole::new(&spec).unwrap();
    assert_eq!(fs::read_link(&link).unwrap(), console.path());
    drop(console);
    assert!(!link.is_symlink());

    // Other files are left alone.
    fs::write(&link, "data").unwrap();
    let err = PtyConsole::new(&spec).unwrap_err();
    assert_matches!(err, Error::System { error, .. } if error.kind() == ErrorKind::AlreadyExists);
    assert_eq!(fs::read_to_string(&link).unwrap(), "data");
}

#[rstest]
#[case("pty", PtyConsoleSpec { link: None })]
#[case("pty,link=/tmp/console", PtyConsoleSpec { link: Some(Path::new("/tmp/console").into()) })]
fn test_pty_console_spec(#[case] arg: &str, #[case] spec: PtyConsoleSpec) {
    let parsed: ConsoleSpec = serde_aco::from_arg(arg).unwrap();
    assert_eq!(parsed, ConsoleSpec::Pty(spec));
}
