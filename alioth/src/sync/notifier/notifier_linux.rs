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

use std::fs::File;
use std::io::{ErrorKind, Read, Result, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, eventfd};
use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};

use crate::ffi;

#[derive(Debug)]
pub struct Notifier {
    fd: File,
}

impl Notifier {
    pub fn new() -> Result<Self> {
        let fd = ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) })?;
        Ok(Notifier {
            fd: unsafe { File::from_raw_fd(fd) },
        })
    }

    pub fn notify(&self) -> Result<()> {
        let mut fd = &self.fd;
        let Err(e) = fd.write(&1u64.to_ne_bytes()) else {
            return Ok(());
        };
        if e.kind() != ErrorKind::WouldBlock {
            return Err(e);
        };
        let mut buf = [0u8; 8];
        let _ = fd.read(&mut buf)?;
        let _ = fd.write(&1u64.to_ne_bytes())?;
        Ok(())
    }
}

impl Source for Notifier {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> Result<()> {
        registry.register(&mut SourceFd(&self.fd.as_raw_fd()), token, interests)
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> Result<()> {
        registry.reregister(&mut SourceFd(&self.fd.as_raw_fd()), token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> std::io::Result<()> {
        registry.deregister(&mut SourceFd(&self.fd.as_raw_fd()))
    }
}

impl AsFd for Notifier {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
