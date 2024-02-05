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

use std::sync::{Arc, RwLock};

use super::mmio::{Mmio, MmioRange};
use super::Result;

#[derive(Debug)]
pub struct IoBus {
    inner: RwLock<MmioRange>,
}

pub type IoDev = Arc<dyn Mmio + Send + Sync + 'static>;

impl Default for IoBus {
    fn default() -> Self {
        Self::new()
    }
}

impl IoBus {
    pub fn new() -> IoBus {
        Self {
            inner: RwLock::new(MmioRange::with_size(u16::MAX as usize)),
        }
    }

    pub(super) fn add(&self, port: u16, dev: IoDev) -> Result<()> {
        let mut inner = self.inner.write()?;
        let dev = inner.add(port as usize, dev)?;
        dev.mapped(port as usize)?;
        Ok(())
    }

    pub fn read(&self, port: u16, size: u8) -> Result<u32> {
        let inner = self.inner.read()?;
        inner.read(port as usize, size).map(|v| v as u32)
    }

    pub fn write(&self, port: u16, size: u8, val: u32) -> Result<()> {
        let inner = self.inner.read()?;
        inner.write(port as usize, size, val as u64)
    }
}
