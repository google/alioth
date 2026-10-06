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

use libc::{
    F_GETFL, F_SETFL, O_NONBLOCK, OPOST, STDIN_FILENO, STDOUT_FILENO, TCSANOW, cfmakeraw, fcntl,
    tcgetattr, tcsetattr, termios,
};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use parking_lot::Mutex;
use vmm_runner::host::SerialConsole;

use crate::ffi;

const TOKEN_SHUTDOWN: Token = Token(0);
const TOKEN_STDIN: Token = Token(1);

struct StdinBackup {
    termios: Option<termios>,
    flag: Option<i32>,
}

impl StdinBackup {
    fn new() -> StdinBackup {
        let mut termios_backup = None;
        let mut t = MaybeUninit::uninit();
        match ffi!(unsafe { tcgetattr(STDIN_FILENO, t.as_mut_ptr()) }) {
            Ok(_) => termios_backup = Some(unsafe { t.assume_init() }),
            Err(e) => log::error!("tcgetattr() failed: {e}"),
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
    poll: Mutex<Poll>,
    waker: Waker,
    events: Mutex<Events>,
    backup: Mutex<Option<StdinBackup>>,
}

impl Debug for HostSerialConsole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSerialConsole").finish()
    }
}

impl HostSerialConsole {
    pub fn new() -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_SHUTDOWN)?;
        Ok(Self {
            poll: Mutex::new(poll),
            waker,
            events: Mutex::new(Events::with_capacity(16)),
            backup: Mutex::new(None),
        })
    }
}

impl SerialConsole for HostSerialConsole {
    fn write_byte(&self, byte: u8) -> io::Result<()> {
        ffi!(unsafe { libc::write(STDOUT_FILENO, &byte as *const u8 as _, 1) })?;
        Ok(())
    }

    fn read_input(&self, data: &mut VecDeque<u8>) -> io::Result<Option<usize>> {
        let mut poll = self.poll.lock();
        {
            let mut backup = self.backup.lock();
            if backup.is_none() {
                *backup = Some(StdinBackup::new());

                let mut raw_termios = MaybeUninit::uninit();
                ffi!(unsafe { tcgetattr(STDIN_FILENO, raw_termios.as_mut_ptr()) })?;
                unsafe { cfmakeraw(raw_termios.as_mut_ptr()) };
                unsafe { raw_termios.assume_init_mut().c_oflag |= OPOST };
                ffi!(unsafe { tcsetattr(STDIN_FILENO, TCSANOW, raw_termios.as_ptr()) })?;

                let flag = ffi!(unsafe { fcntl(STDIN_FILENO, F_GETFL) })?;
                ffi!(unsafe { fcntl(STDIN_FILENO, F_SETFL, flag | O_NONBLOCK) })?;
                poll.registry().register(
                    &mut SourceFd(&STDIN_FILENO),
                    TOKEN_STDIN,
                    Interest::READABLE,
                )?;
            }
        }
        let mut events = self.events.lock();
        poll.poll(&mut events, None)?;
        let mut total_size = 0;
        for event in events.iter() {
            match event.token() {
                TOKEN_SHUTDOWN => return Ok(None),
                TOKEN_STDIN => {
                    let mut buf = [0u8; 16];
                    loop {
                        match ffi!(unsafe { libc::read(STDIN_FILENO, buf.as_mut_ptr() as _, 16) }) {
                            Ok(0) => break,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Ok(len) => {
                                data.extend(&buf[0..len as usize]);
                                total_size += len as usize;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(Some(total_size))
    }

    fn shutdown(&self) -> io::Result<()> {
        self.waker.wake()
    }
}
