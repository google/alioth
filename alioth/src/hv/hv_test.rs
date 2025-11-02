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

use std::os::fd::{AsFd, BorrowedFd};

use parking_lot::RwLock;

use crate::hv::{IrqFd, Result};

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
        unreachable!()
    }
}
