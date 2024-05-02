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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bitfield::bitfield;
use parking_lot::{Mutex, RwLock};

use crate::mem;
use crate::mem::emulated::Mmio;
use crate::pci::config::PciConfig;
use crate::pci::segment::PciSegment;
use crate::pci::{Bdf, Error, Result};

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
    pub fn to_ecam_addr(self) -> usize {
        let v = self.0 as usize;
        ((v & 0xff_ff00) << 4) | (v & 0xfc)
    }
}

#[derive(Debug)]
pub struct PciIoBus {
    address: AtomicU32,
    segment: Arc<PciSegment>,
}

impl Mmio for PciIoBus {
    fn size(&self) -> usize {
        8
    }

    fn read(&self, offset: usize, size: u8) -> Result<u64, mem::Error> {
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

    fn write(&self, offset: usize, size: u8, val: u64) -> Result<(), mem::Error> {
        match offset {
            0 => {
                assert_eq!(size, 4);
                self.address.store(val as u32, Ordering::Release);
            }
            4..=7 => {
                let addr = Address(self.address.load(Ordering::Acquire));
                self.segment
                    .write(addr.to_ecam_addr() | (offset & 0b11), size, val)?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PciBus {
    pub io_bus: Arc<PciIoBus>,
    pub segment: Arc<PciSegment>,
    last_dev: Mutex<u16>,
}

impl PciBus {
    pub fn new() -> Self {
        let configs = HashMap::new();

        let segment = Arc::new(PciSegment {
            configs: RwLock::new(configs),
        });
        PciBus {
            io_bus: Arc::new(PciIoBus {
                address: AtomicU32::new(0),
                segment: segment.clone(),
            }),
            segment,
            last_dev: Mutex::new(0),
        }
    }

    pub fn add(&self, bdf: Option<Bdf>, config: Arc<dyn PciConfig>) -> Result<Bdf> {
        match bdf {
            Some(bdf) => {
                self.segment.add(bdf, config)?;
                Ok(bdf)
            }
            None => {
                let mut last_dev = self.last_dev.lock();
                for _ in 0..(u16::MAX >> 3) {
                    *last_dev += 8;
                    match self.segment.add(Bdf(*last_dev), config.clone()) {
                        Ok(_) => return Ok(Bdf(*last_dev)),
                        Err(Error::BdfExists(_)) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Err(Error::NoBdfSlots)
            }
        }
    }
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}
