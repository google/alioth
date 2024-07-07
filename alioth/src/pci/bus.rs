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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bitfield::bitfield;
use parking_lot::{Mutex, RwLock};

use crate::mem::emulated::{Action, Mmio};
use crate::pci::config::{BAR_IO, BAR_MEM64, BAR_PREFETCHABLE};
use crate::pci::host_bridge::HostBridge;
use crate::pci::segment::PciSegment;
use crate::pci::{Bdf, PciDevice, Result};
use crate::{align_up, mem};

pub const CONFIG_ADDRESS: u16 = 0xcf8;
pub const CONFIG_DATA: u16 = 0xcfc;
pub const CONFIG_DATA_MAX: u16 = 0xcff;

bitfield! {
    #[derive(Copy, Clone, Default)]
    struct Address(u32);
    impl Debug;
    enabled, _: 31;
    bus, _: 23, 16;
    dev, _: 15, 11;
    func, _: 10, 8;
    offset, _: 7, 0;
}

impl Address {
    pub fn to_ecam_addr(self) -> u64 {
        let v = self.0 as u64;
        ((v & 0xff_ff00) << 4) | (v & 0xfc)
    }
}

#[derive(Debug)]
pub struct PciIoBus {
    address: AtomicU32,
    segment: Arc<PciSegment>,
}

impl Mmio for PciIoBus {
    fn size(&self) -> u64 {
        8
    }

    fn read(&self, offset: u64, size: u8) -> Result<u64, mem::Error> {
        match offset {
            0 => {
                assert_eq!(size, 4);
                Ok(self.address.load(Ordering::Acquire) as u64)
            }
            4..=7 => {
                let addr = Address(self.address.load(Ordering::Acquire));
                self.segment
                    .read(addr.to_ecam_addr() | (offset & 0b11), size)
            }
            _ => Ok(0),
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        match offset {
            0 => {
                assert_eq!(size, 4);
                self.address.store(val as u32, Ordering::Release);
                Ok(Action::None)
            }
            4..=7 => {
                let addr = Address(self.address.load(Ordering::Acquire));
                self.segment
                    .write(addr.to_ecam_addr() | (offset & 0b11), size, val)
            }
            _ => Ok(Action::None),
        }
    }
}

#[derive(Debug)]
pub struct PciBus {
    pub io_bus: Arc<PciIoBus>,
    pub segment: Arc<PciSegment>,
}

impl PciBus {
    pub fn new() -> Self {
        let devices = if cfg!(target_arch = "x86_64") {
            let bridge = PciDevice::new(
                Arc::new("host_bridge".to_owned()),
                Arc::new(HostBridge::new()),
            );
            HashMap::from([(Bdf(0), bridge)])
        } else {
            HashMap::new()
        };

        let segment = Arc::new(PciSegment {
            devices: RwLock::new(devices),
            #[cfg(target_arch = "x86_64")]
            next_bdf: Mutex::new(8),
            #[cfg(not(target_arch = "x86_64"))]
            next_bdf: Mutex::new(0),
        });
        PciBus {
            io_bus: Arc::new(PciIoBus {
                address: AtomicU32::new(0),
                segment: segment.clone(),
            }),
            segment,
        }
    }

    pub fn reserve(&self, bdf: Option<Bdf>, name: Arc<String>) -> Option<Bdf> {
        self.segment.reserve(bdf, name)
    }

    pub fn add(&self, bdf: Bdf, dev: PciDevice) -> Option<PciDevice> {
        self.segment.add(bdf, dev)
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
        let devices = self.segment.devices.read();
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
                let aligned_addr = align_up!(addr, size);
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
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}
