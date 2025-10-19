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
use std::iter::zip;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::mem::emulated::{Action, Mmio};
use crate::pci::config::{BAR_IO, BAR_MEM64, BAR_PREFETCHABLE, PciConfig};
use crate::pci::{Bdf, Pci, PciDevice, Result};
use crate::{align_up, mem};

#[derive(Debug)]
struct EmptyDevice;

impl Pci for EmptyDevice {
    fn config(&self) -> &dyn PciConfig {
        unreachable!()
    }

    fn reset(&self) -> Result<()> {
        unreachable!()
    }
}

#[derive(Debug)]
pub struct PciSegment {
    devices: RwLock<HashMap<Bdf, PciDevice>>,
    next_bdf: Mutex<u16>,
}

impl PciSegment {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            next_bdf: Mutex::new(0),
        }
    }

    pub fn max_bus(&self) -> Option<u8> {
        let devices = self.devices.read();
        devices.keys().map(|bdf| bdf.bus()).max()
    }

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

    /// Assigns addresses to all devices' base address registers
    ///
    /// `resources` is an array of 4 `(start, end)` tuples, corresponds to
    ///
    /// - IO space,
    /// - 32-bit non-prefetchable memory space,
    /// - 32-bit prefetchable memory space,
    /// - 64-bit prefetchable memory space,
    ///
    /// respectively.
    pub fn assign_resources(&self, resources: &[(u64, u64); 4]) {
        let mut bar_lists = [const { vec![] }; 4];
        let devices = self.devices.read();
        for (bdf, dev) in devices.iter() {
            let config = dev.dev.config();
            let header = config.get_header().data.read();
            let mut index = 0;
            while index < 6 {
                let bar_index = index;
                index += 1;
                let (val, mask) = header.get_bar(bar_index);
                let mut mask = mask as u64;
                if val & BAR_MEM64 == BAR_MEM64 {
                    let (_, mask_hi) = header.get_bar(bar_index + 1);
                    mask |= (mask_hi as u64) << 32;
                    index += 1;
                }
                if mask == 0 {
                    continue;
                }
                let bar_list = if val & BAR_IO == BAR_IO {
                    &mut bar_lists[0]
                } else if val & (BAR_MEM64 | BAR_PREFETCHABLE) == BAR_MEM64 | BAR_PREFETCHABLE {
                    &mut bar_lists[3]
                } else if val & (BAR_MEM64 | BAR_PREFETCHABLE) == BAR_MEM64 {
                    unreachable!("{bdf}: BAR {index} is 64-bit but not prefetchable")
                } else if val & BAR_PREFETCHABLE == BAR_PREFETCHABLE {
                    &mut bar_lists[2]
                } else {
                    &mut bar_lists[1]
                };
                bar_list.push((*bdf, dev, bar_index, 1 << mask.trailing_zeros()));
            }
        }
        for bar_list in bar_lists.iter_mut() {
            bar_list.sort_by_key(|(bdf, _, index, size)| (u64::MAX - size, *bdf, *index));
        }
        for (bar_list, (start, end)) in zip(bar_lists, resources) {
            let mut addr = *start;
            for (bdf, dev, index, size) in bar_list {
                let config = dev.dev.config();
                let mut header = config.get_header().data.write();
                let aligned_addr = align_up!(addr, size.trailing_zeros());
                if aligned_addr + size > *end {
                    log::error!(
                        "{bdf}: cannot map BAR {index} into address range {start:#x}..{end:#x}"
                    );
                    continue;
                }
                header.set_bar(index, aligned_addr as u32);
                if aligned_addr > u32::MAX as u64 {
                    header.set_bar(index + 1, (aligned_addr >> 32) as u32);
                }
                addr = aligned_addr + size;
            }
        }
    }

    pub fn reset(&self) -> Result<()> {
        let devices = self.devices.read();
        for (_, dev) in devices.iter() {
            dev.dev.reset()?;
            dev.dev.config().reset();
        }
        Ok(())
    }
}

impl Default for PciSegment {
    fn default() -> Self {
        Self::new()
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
