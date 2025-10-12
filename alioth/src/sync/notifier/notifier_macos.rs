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
use std::io::{ErrorKind, Result};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::ptr::{null, null_mut};

use mio::event::Source;
use mio::{Interest, Registry, Token};

use crate::ffi;

#[derive(Debug)]
pub struct Notifier {
    fd: OwnedFd,
    registered: Option<(Token, OwnedFd)>,
}

impl Notifier {
    pub fn new() -> Result<Self> {
        Ok(Notifier {
            fd: File::open("/dev/null")?.into(),
            registered: None,
        })
    }

    pub fn notify(&self) -> Result<()> {
        let Some((token, kqfd)) = &self.registered else {
            return Err(ErrorKind::NotFound.into());
        };
        let event = libc::kevent {
            ident: self.fd.as_raw_fd() as _,
            filter: libc::EVFILT_USER,
            flags: libc::EV_ADD | libc::EV_RECEIPT,
            fflags: libc::NOTE_TRIGGER,
            data: 0,
            udata: token.0 as _,
        };
        ffi!(unsafe { libc::kevent(kqfd.as_raw_fd(), &event, 1, null_mut(), 0, null()) })?;
        Ok(())
    }
}

impl Source for Notifier {
    fn register(&mut self, registry: &Registry, token: Token, _: Interest) -> Result<()> {
        let event = libc::kevent {
            ident: self.fd.as_raw_fd() as _,
            filter: libc::EVFILT_USER,
            flags: libc::EV_ADD | libc::EV_CLEAR | libc::EV_RECEIPT,
            fflags: 0,
            data: 0,
            udata: null_mut(),
        };

        let kqfd = registry.as_raw_fd();
        let kqfd = ffi!(unsafe { libc::dup(kqfd) })?;
        let kqfd = unsafe { OwnedFd::from_raw_fd(kqfd) };

        ffi!(unsafe { libc::kevent(kqfd.as_raw_fd(), &event, 1, null_mut(), 0, null()) })?;
        self.registered = Some((token, kqfd));
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> Result<()> {
        let event = libc::kevent {
            ident: self.fd.as_raw_fd() as _,
            filter: libc::EVFILT_USER,
            flags: libc::EV_DELETE | libc::EV_RECEIPT,
            fflags: 0,
            data: 0,
            udata: null_mut(),
        };

        let kqfd = registry.as_raw_fd();

        ffi!(unsafe { libc::kevent(kqfd, &event, 1, null_mut(), 0, null()) })?;
        self.registered = None;
        Ok(())
    }

    fn reregister(&mut self, _: &Registry, _: Token, _: Interest) -> Result<()> {
        Err(ErrorKind::Unsupported.into())
    }
}
