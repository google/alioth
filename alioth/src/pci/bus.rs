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
use crate::pci::host_bridge::HostBridge;
use crate::pci::segment::PciSegment;
use crate::pci::{Bdf, PciDevice, Result};

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

    fn write(&self, offset: u64, size: u8, val: u64) -> Result<(), mem::Error> {
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
}

impl PciBus {
    pub fn new() -> Self {
        let bridge = PciDevice::new(
            Arc::new("host_bridge".to_owned()),
            Arc::new(HostBridge::new()),
        );
        let devices = HashMap::from([(Bdf(0), bridge)]);

        let segment = Arc::new(PciSegment {
            devices: RwLock::new(devices),
            next_bdf: Mutex::new(8),
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
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}
