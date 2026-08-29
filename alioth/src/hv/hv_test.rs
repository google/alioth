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

use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use parking_lot::{Condvar, Mutex, RwLock};
use snafu::ResultExt;

use crate::hv::{IoeventFd, IrqFd, IrqSender, MsiSender, Result, error};

#[derive(Debug)]
struct TestIrqFdInner {
    addr_hi: u32,
    addr_lo: u32,
    data: u32,
    masked: bool,
}

impl Default for TestIrqFdInner {
    fn default() -> Self {
        Self {
            addr_hi: 0,
            addr_lo: 0,
            data: 0,
            masked: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct TestIrqFd {
    inner: RwLock<TestIrqFdInner>,
}

impl IrqFd for TestIrqFd {
    fn get_addr_hi(&self) -> u32 {
        self.inner.read().addr_hi
    }

    fn get_addr_lo(&self) -> u32 {
        self.inner.read().addr_lo
    }

    fn get_data(&self) -> u32 {
        self.inner.read().data
    }

    fn get_masked(&self) -> bool {
        self.inner.read().masked
    }

    fn set_addr_hi(&self, val: u32) -> Result<()> {
        self.inner.write().addr_hi = val;
        Ok(())
    }

    fn set_addr_lo(&self, val: u32) -> Result<()> {
        self.inner.write().addr_lo = val;
        Ok(())
    }

    fn set_data(&self, val: u32) -> Result<()> {
        self.inner.write().data = val;
        Ok(())
    }

    fn set_masked(&self, val: bool) -> Result<bool> {
        let masked = &mut self.inner.write().masked;
        let changed = *masked != val;
        log::debug!("val: {}, masked: {}, changed: {}", val, *masked, changed);
        *masked = val;
        Ok(changed)
    }
}

impl AsFd for TestIrqFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(0) }
    }
}

#[derive(Debug)]
pub struct TestIrqSender {
    pub count: Mutex<u8>,
    pub condvar: Condvar,
}

impl TestIrqSender {
    pub fn new() -> Self {
        Self {
            count: Mutex::new(0),
            condvar: Condvar::new(),
        }
    }
}

impl IrqSender for TestIrqSender {
    fn send(&self) -> Result<()> {
        let mut count = self.count.lock();
        *count += 1;
        self.condvar.notify_one();
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct TestMsiSender {
    pub messages: Arc<Mutex<Vec<(u64, u32)>>>,
    pub fail_mode: Option<ErrorKind>,
}

impl MsiSender for TestMsiSender {
    type IrqFd = TestIrqFd;

    fn send(&self, addr: u64, data: u32) -> Result<()> {
        if let Some(kind) = self.fail_mode {
            return Err(io::Error::from(kind)).context(error::SendInterrupt);
        }
        self.messages.lock().push((addr, data));
        Ok(())
    }

    fn create_irqfd(&self) -> Result<Self::IrqFd> {
        if let Some(kind) = self.fail_mode {
            return Err(io::Error::from(kind)).context(error::IrqFd);
        }
        Ok(TestIrqFd::default())
    }
}

#[derive(Debug, Default)]
pub struct TestIoeventFd;

impl AsFd for TestIoeventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(0) }
    }
}

impl IoeventFd for TestIoeventFd {}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RegisteredAddr {
    pub gpa: u64,
    pub len: u8,
    pub data: Option<u64>,
}

#[derive(Debug, Default)]
pub struct TestIoeventFdRegistry {
    pub registered: Arc<Mutex<Vec<RegisteredAddr>>>,
    pub deregistered: Arc<Mutex<usize>>,
    pub fail_mode: Option<ErrorKind>,
}

impl super::IoeventFdRegistry for TestIoeventFdRegistry {
    type IoeventFd = TestIoeventFd;

    fn create(&self) -> Result<Self::IoeventFd> {
        if let Some(kind) = self.fail_mode {
            return Err(io::Error::from(kind)).context(error::IoeventFd);
        }
        Ok(TestIoeventFd)
    }

    fn register(&self, _fd: &Self::IoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()> {
        self.registered
            .lock()
            .push(RegisteredAddr { gpa, len, data });
        Ok(())
    }

    fn deregister(&self, _fd: &Self::IoeventFd) -> Result<()> {
        *self.deregistered.lock() += 1;
        Ok(())
    }
}
