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

#[cfg(target_os = "linux")]
pub mod io_uring;
pub mod mio;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{ErrorKind, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

#[cfg(target_os = "linux")]
use libc::{EFD_CLOEXEC, EFD_NONBLOCK, eventfd};
use serde::Deserialize;
use serde_aco::Help;
#[cfg(target_os = "linux")]
use snafu::ResultExt;

#[cfg(target_os = "linux")]
use crate::ffi;
use crate::virtio::Result;
#[cfg(target_os = "linux")]
use crate::virtio::error;

#[derive(Debug, Clone, Copy, Default, Deserialize, Help)]
pub enum WorkerApi {
    /// I/O event queue backed by epoll/kqeueu.
    #[default]
    #[serde(alias = "mio")]
    Mio,
    /// Linux io_uring.
    #[cfg(target_os = "linux")]
    #[serde(alias = "iouring", alias = "io_uring")]
    IoUring,
}

#[derive(Debug)]
pub struct Waker(
    #[cfg(target_os = "linux")] File,
    #[cfg(not(target_os = "linux"))] ::mio::Waker,
);

impl Waker {
    #[cfg(target_os = "linux")]
    pub fn new_eventfd() -> Result<Self> {
        let efd =
            ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) }).context(error::CreateWaker)?;
        Ok(Waker(unsafe { File::from_raw_fd(efd) }))
    }

    #[cfg(target_os = "linux")]
    pub fn wake(&self) -> Result<()> {
        let mut fd = &self.0;
        let Err(e) = fd.write(&1u64.to_ne_bytes()) else {
            return Ok(());
        };
        if e.kind() != ErrorKind::WouldBlock {
            return Err(e.into());
        };
        let mut buf = [0u8; 8];
        let _ = fd.read(&mut buf)?;
        let _ = fd.write(&1u64.to_ne_bytes())?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn wake(&self) -> Result<()> {
        self.0.wake()?;
        Ok(())
    }
}
