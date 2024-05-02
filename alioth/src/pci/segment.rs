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

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::mem;
use crate::mem::emulated::Mmio;
use crate::pci::config::PciConfig;
use crate::pci::{Bdf, Error, Result};

#[derive(Debug)]
pub struct PciSegment {
    pub(super) configs: RwLock<HashMap<Bdf, Arc<dyn PciConfig>>>,
}

impl PciSegment {
    pub fn add(&self, bdf: Bdf, config: Arc<dyn PciConfig>) -> Result<()> {
        let mut configs = self.configs.write();
        if let Some(c) = configs.insert(bdf, config) {
            configs.insert(bdf, c);
            Err(Error::BdfExists(bdf))
        } else {
            Ok(())
        }
    }
}

impl Mmio for PciSegment {
    fn size(&self) -> usize {
        // 256 MiB: 256 buses, 32 devices, 8 functions
        256 * 32 * 8 * 4096
    }

    fn read(&self, offset: usize, size: u8) -> Result<u64, mem::Error> {
        let bdf = Bdf((offset >> 12) as u16);
        let configs = self.configs.read();
        if let Some(config) = configs.get(&bdf) {
            config.read(offset & 0xfff, size)
        } else {
            Ok(u64::MAX)
        }
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> Result<(), mem::Error> {
        let bdf = Bdf((offset >> 12) as u16);
        let configs = self.configs.read();
        if let Some(config) = configs.get(&bdf) {
            config.write(offset & 0xfff, size, val)
        } else {
            Ok(())
        }
    }
}
