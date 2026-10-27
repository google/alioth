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
use std::fmt::{Debug, Formatter};
use std::io::{self, ErrorKind};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{
    F_GETFL, F_SETFL, O_NONBLOCK, OPOST, STDIN_FILENO, STDOUT_FILENO, TCSANOW, cfmakeraw, fcntl,
    tcgetattr, tcsetattr, termios,
};
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use parking_lot::Mutex;
use vmm_io::host::SerialConsole;

use crate::ffi;

struct StdinBackup {
    termios: Option<termios>,
    flag: Option<i32>,
}

impl StdinBackup {
    fn new() -> StdinBackup {
        let mut termios_backup = None;
        let mut t = MaybeUninit::uninit();
        if unsafe { tcgetattr(STDIN_FILENO, t.as_mut_ptr()) } == 0 {
            termios_backup = Some(unsafe { t.assume_init() });
        }
        let mut flag_backup = None;
        match ffi!(unsafe { fcntl(STDIN_FILENO, F_GETFL) }) {
            Ok(f) => flag_backup = Some(f),
            Err(e) => log::error!("fcntl(STDIN_FILENO, F_GETFL) failed: {e}"),
        }
        StdinBackup {
            termios: termios_backup,
            flag: flag_backup,
        }
    }
}

impl Drop for StdinBackup {
    fn drop(&mut self) {
        if let Some(t) = self.termios.take() {
            if let Err(e) = ffi!(unsafe { tcsetattr(STDIN_FILENO, 1, &t) }) {
                log::error!("Restoring termios: {e:?}");
            }
        }
        if let Some(f) = self.flag.take() {
            if let Err(e) = ffi!(unsafe { fcntl(STDIN_FILENO, F_SETFL, f) }) {
                log::error!("Restoring stdin flag to {f:#x}: {e:?}")
            }
        }
    }
}

pub struct HostSerialConsole {
    registry: Registry,
    registered: AtomicBool,
    backup: Mutex<Option<StdinBackup>>,
}

impl Debug for HostSerialConsole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSerialConsole").finish()
    }
}

impl HostSerialConsole {
    pub fn new(registry: Registry, token: Token) -> io::Result<Self> {
        let backup = StdinBackup::new();
        if backup.termios.is_some() {
            let mut raw_termios = MaybeUninit::uninit();
            if unsafe { tcgetattr(STDIN_FILENO, raw_termios.as_mut_ptr()) } == 0 {
                unsafe { cfmakeraw(raw_termios.as_mut_ptr()) };
                unsafe { raw_termios.assume_init_mut().c_oflag |= OPOST };
                let _ = unsafe { tcsetattr(STDIN_FILENO, TCSANOW, raw_termios.as_ptr()) };
            }
        }
        if let Ok(flag) = ffi!(unsafe { fcntl(STDIN_FILENO, F_GETFL) }) {
            let _ = ffi!(unsafe { fcntl(STDIN_FILENO, F_SETFL, flag | O_NONBLOCK) });
        }
        let registered = registry
            .register(&mut SourceFd(&STDIN_FILENO), token, Interest::READABLE)
            .is_ok();
        Ok(Self {
            registry,
            registered: AtomicBool::new(registered),
            backup: Mutex::new(Some(backup)),
        })
    }

    fn deregister_stdin(&self) {
        if self.registered.swap(false, Ordering::AcqRel) {
            let _ = self.registry.deregister(&mut SourceFd(&STDIN_FILENO));
        }
    }
}

impl SerialConsole for HostSerialConsole {
    fn write_byte(&self, byte: u8) -> io::Result<()> {
        ffi!(unsafe { libc::write(STDOUT_FILENO, &byte as *const u8 as _, 1) })?;
        Ok(())
    }

    fn read_input(&self, data: &mut VecDeque<u8>) -> io::Result<Option<usize>> {
        let mut total_size = 0;
        let mut buf = [0u8; 64];
        loop {
            match ffi!(unsafe { libc::read(STDIN_FILENO, buf.as_mut_ptr() as _, buf.len()) }) {
                Ok(0) => {
                    self.deregister_stdin();
                    break;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) => {
                    data.extend(&buf[0..len as usize]);
                    total_size += len as usize;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Some(total_size))
    }

    fn shutdown(&self) -> io::Result<()> {
        self.deregister_stdin();
        let _ = self.backup.lock().take();
        Ok(())
    }
}

impl Drop for HostSerialConsole {
    fn drop(&mut self) {
        self.deregister_stdin();
    }
}
