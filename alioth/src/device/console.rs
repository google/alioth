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

use std::fmt::Debug;
use std::io::{self, ErrorKind, Read, Write};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::thread::JoinHandle;

use libc::{
    F_GETFL, F_SETFL, O_NONBLOCK, OPOST, STDIN_FILENO, STDOUT_FILENO, TCSANOW, cfmakeraw, fcntl,
    tcgetattr, tcsetattr, termios,
};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};

use crate::device::Result;
use crate::ffi;
use crate::sync::notifier::Notifier;

pub trait Console: Debug + Send + Sync + 'static {
    const TOKEN_INPUT: Token;
    fn activate(&self, registry: &Registry) -> io::Result<()>;
    fn deactivate(&self, registry: &Registry) -> io::Result<()>;
}

#[derive(Debug)]
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
        if let Some(t) = self.termios.take()
            && let Err(e) = ffi!(unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &t) })
        {
            log::error!("Restoring termios: {e:?}");
        }
        if let Some(f) = self.flag.take()
            && let Err(e) = ffi!(unsafe { fcntl(STDIN_FILENO, F_SETFL, f) })
        {
            log::error!("Restoring stdin flag to {f:#x}: {e:?}")
        }
    }
}

#[derive(Debug)]
pub struct StdioConsole {
    _backup: StdinBackup,
}

impl StdioConsole {
    pub fn new() -> Result<Self> {
        let backup = StdinBackup::new();
        let mut raw_termios = MaybeUninit::uninit();
        ffi!(unsafe { tcgetattr(STDIN_FILENO, raw_termios.as_mut_ptr()) })?;
        unsafe { cfmakeraw(raw_termios.as_mut_ptr()) };
        unsafe { raw_termios.assume_init_mut().c_oflag |= OPOST };
        ffi!(unsafe { tcsetattr(STDIN_FILENO, TCSANOW, raw_termios.as_ptr()) })?;

        let flag = ffi!(unsafe { fcntl(STDIN_FILENO, F_GETFL) })?;
        ffi!(unsafe { fcntl(STDIN_FILENO, F_SETFL, flag | O_NONBLOCK) })?;
        Ok(StdioConsole { _backup: backup })
    }
}

impl Read for &StdioConsole {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = ffi!(unsafe { libc::read(STDIN_FILENO, buf.as_mut_ptr() as _, 16) })?;
        Ok(count as usize)
    }
}

impl Write for &StdioConsole {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count =
            ffi!(unsafe { libc::write(STDOUT_FILENO, buf.as_ptr() as *const _, buf.len()) })?;
        Ok(count as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Console for StdioConsole {
    const TOKEN_INPUT: Token = Token(0);

    fn activate(&self, registry: &Registry) -> io::Result<()> {
        registry.register(
            &mut SourceFd(&STDIN_FILENO),
            Self::TOKEN_INPUT,
            Interest::READABLE,
        )
    }

    fn deactivate(&self, registry: &Registry) -> io::Result<()> {
        registry.deregister(&mut SourceFd(&STDIN_FILENO))
    }
}

pub trait UartRecv: Send + 'static {
    fn receive(&self, bytes: &[u8]);
}

const TOKEN_SHUTDOWN: Token = Token(1 << 63);

struct ThreadWorker<U, C> {
    name: Arc<str>,
    uart: U,
    console: Arc<C>,
    poll: Poll,
}

impl<U, C> ThreadWorker<U, C>
where
    U: UartRecv,
    C: Console,
    for<'a> &'a C: Read + Write,
{
    fn read_input(&self) -> Result<usize> {
        let mut total_size = 0;
        let mut buf = [0u8; 16];
        loop {
            match self.console.as_ref().read(&mut buf) {
                Ok(0) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) => {
                    self.uart.receive(&buf[0..len]);
                    total_size += len;
                }
                Err(e) => Err(e)?,
            }
        }
        Ok(total_size)
    }

    fn do_work_inner(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(16);
        loop {
            self.poll.poll(&mut events, None)?;
            for event in events.iter() {
                if event.token() != C::TOKEN_INPUT {
                    return Ok(());
                }
                self.read_input()?;
            }
        }
    }

    fn do_work(&mut self) {
        match self.do_work_inner() {
            Ok(()) => log::trace!("{}: done", self.name),
            Err(e) => log::error!("{}: {e:?}", self.name),
        }
    }
}

#[derive(Debug)]
pub struct ConsoleThread {
    pub name: Arc<str>,
    worker_thread: Option<JoinHandle<()>>,
    exit_notifier: Notifier,
}

impl ConsoleThread {
    pub fn new<U, C>(name: Arc<str>, uart: U, console: Arc<C>) -> Result<Self>
    where
        U: UartRecv,
        C: Console,
        for<'a> &'a C: Read + Write,
    {
        let poll = Poll::new()?;
        let registry = poll.registry();
        let mut notifier = Notifier::new()?;
        registry.register(&mut notifier, TOKEN_SHUTDOWN, Interest::READABLE)?;
        console.activate(registry)?;
        let mut worker = ThreadWorker {
            name: name.clone(),
            uart,
            poll,
            console,
        };
        let worker_thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || worker.do_work())?;
        let console = ConsoleThread {
            name,
            worker_thread: Some(worker_thread),
            exit_notifier: notifier,
        };
        Ok(console)
    }
}

impl Drop for ConsoleThread {
    fn drop(&mut self) {
        if let Err(e) = self.exit_notifier.notify() {
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
