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

use std::io::{ErrorKind, Result};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::thread::JoinHandle;

use libc::{
    cfmakeraw, fcntl, tcgetattr, tcsetattr, termios, F_GETFL, F_SETFL, OPOST, O_NONBLOCK,
    STDIN_FILENO, STDOUT_FILENO, TCSANOW,
};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::ffi;

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
            Err(e) => log::error!("tcgetattr() failed: {e:?}"),
        }
        let mut flag_backup = None;
        match ffi! { unsafe { fcntl(STDIN_FILENO, F_GETFL) } } {
            Ok(f) => flag_backup = Some(f),
            Err(e) => log::error!("fcntl(STDIN_FILENO, F_GETFL) failed: {e:?}"),
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
            if let Err(e) = ffi!(unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &t) }) {
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

pub trait UartRecv: Send + 'static {
    fn receive(&self, bytes: &[u8]);
}

struct ConsoleWorker<U: UartRecv> {
    name: Arc<str>,
    uart: U,
    poll: Poll,
}

impl<U: UartRecv> ConsoleWorker<U> {
    fn setup_termios(&mut self) -> Result<()> {
        let mut raw_termios = MaybeUninit::uninit();
        ffi!(unsafe { tcgetattr(STDIN_FILENO, raw_termios.as_mut_ptr()) })?;
        unsafe { cfmakeraw(raw_termios.as_mut_ptr()) };
        unsafe { raw_termios.assume_init_mut().c_oflag |= OPOST };
        ffi!(unsafe { tcsetattr(STDIN_FILENO, TCSANOW, raw_termios.as_ptr()) })?;

        let flag = ffi!(unsafe { fcntl(STDIN_FILENO, F_GETFL) })?;
        ffi!(unsafe { fcntl(STDIN_FILENO, F_SETFL, flag | O_NONBLOCK) })?;
        self.poll.registry().register(
            &mut SourceFd(&STDIN_FILENO),
            TOKEN_STDIN,
            Interest::READABLE,
        )?;

        Ok(())
    }

    fn read_input(&self) -> Result<usize> {
        let mut total_size = 0;
        let mut buf = [0u8; 16];
        loop {
            match ffi!(unsafe { libc::read(STDIN_FILENO, buf.as_mut_ptr() as _, 16) }) {
                Ok(0) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) => {
                    self.uart.receive(&buf[0..len as usize]);
                    total_size += len as usize;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(total_size)
    }

    fn do_work_inner(&mut self) -> Result<()> {
        self.setup_termios()?;
        let mut events = Events::with_capacity(16);
        loop {
            self.poll.poll(&mut events, None)?;
            for event in events.iter() {
                if event.token() == TOKEN_SHUTDOWN {
                    return Ok(());
                }
                self.read_input()?;
            }
        }
    }

    fn do_work(&mut self) {
        log::trace!("{}: start", self.name);
        let _backup = StdinBackup::new();
        if let Err(e) = self.do_work_inner() {
            log::error!("{}: {e:?}", self.name)
        } else {
            log::trace!("{}: done", self.name)
        }
    }
}

#[derive(Debug)]
pub struct Console {
    pub name: Arc<str>,
    worker_thread: Option<JoinHandle<()>>,
    exit_waker: Waker,
}

const TOKEN_SHUTDOWN: Token = Token(1);
const TOKEN_STDIN: Token = Token(0);

impl Console {
    pub fn new(name: impl Into<Arc<str>>, uart: impl UartRecv) -> Result<Self> {
        let name = name.into();
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_SHUTDOWN)?;
        let mut worker = ConsoleWorker {
            name: name.clone(),
            uart,
            poll,
        };
        let worker_thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || worker.do_work())?;
        let console = Console {
            name,
            worker_thread: Some(worker_thread),
            exit_waker: waker,
        };
        Ok(console)
    }

    pub fn transmit(&self, bytes: &[u8]) {
        let ret =
            ffi!(unsafe { libc::write(STDOUT_FILENO, bytes.as_ptr() as *const _, bytes.len()) });
        if let Err(e) = ret {
            log::error!("{}: cannot write {bytes:#02x?}: {e:?}", self.name)
        }
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        if let Err(e) = self.exit_waker.wake() {
            log::error!("{}: {e:?}", self.name);
            return;
        }
        let Some(thread) = self.worker_thread.take() else {
            return;
        };
        if let Err(e) = thread.join() {
            log::error!("{}: {e:?}", self.name);
        }
    }
}
