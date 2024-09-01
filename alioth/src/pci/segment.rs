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

use parking_lot::{Mutex, RwLock};

use crate::mem;
use crate::mem::emulated::{Action, Mmio};
use crate::pci::config::PciConfig;
use crate::pci::{Bdf, Pci, PciDevice, Result};

#[derive(Debug)]
struct EmptyDevice;

impl Pci for EmptyDevice {
    fn config(&self) -> Arc<dyn PciConfig> {
        unreachable!()
    }

    fn reset(&self) -> Result<()> {
        unreachable!()
    }
}

#[derive(Debug)]
pub struct PciSegment {
    pub devices: RwLock<HashMap<Bdf, PciDevice>>,
    pub(super) next_bdf: Mutex<u16>,
}

impl PciSegment {
    fn add_dev(
        configs: &mut HashMap<Bdf, PciDevice>,
        bdf: Bdf,
        dev: PciDevice,
    ) -> Option<PciDevice> {
        let name = dev.name.clone();
        if let Some(exist_dev) = configs.insert(bdf, dev) {
            if exist_dev.name == name {
                None
            } else {
                configs.insert(bdf, exist_dev)
            }
        } else {
            None
        }
    }

    pub fn reserve(&self, bdf: Option<Bdf>, name: Arc<str>) -> Option<Bdf> {
        let mut empty_dev = PciDevice {
            name: name.clone(),
            dev: Arc::new(EmptyDevice),
        };
        let mut configs = self.devices.write();
        match bdf {
            Some(bdf) => {
                if Self::add_dev(&mut configs, bdf, empty_dev).is_none() {
                    return Some(bdf);
                }
            }
            None => {
                let mut next_dev = self.next_bdf.lock();
                for _ in 0..(u16::MAX >> 3) {
                    let bdf = Bdf(*next_dev);
                    *next_dev += 8;
                    match Self::add_dev(&mut configs, bdf, empty_dev) {
                        None => return Some(bdf),
                        Some(d) => empty_dev = d,
                    }
                }
            }
        };
        None
    }

    pub fn add(&self, bdf: Bdf, config: PciDevice) -> Option<PciDevice> {
        let mut configs = self.devices.write();
        Self::add_dev(&mut configs, bdf, config)
    }
}

impl Mmio for PciSegment {
    fn size(&self) -> u64 {
        // 256 MiB: 256 buses, 32 devices, 8 functions
        256 * 32 * 8 * 4096
    }

    fn read(&self, offset: u64, size: u8) -> Result<u64, mem::Error> {
        let bdf = Bdf((offset >> 12) as u16);
        let configs = self.devices.read();
        if let Some(config) = configs.get(&bdf) {
            config.dev.config().read(offset & 0xfff, size)
        } else {
            Ok(u64::MAX)
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let bdf = Bdf((offset >> 12) as u16);
        let configs = self.devices.read();
        if let Some(config) = configs.get(&bdf) {
            config.dev.config().write(offset & 0xfff, size, val)
        } else {
            Ok(Action::None)
        }
    }
}
