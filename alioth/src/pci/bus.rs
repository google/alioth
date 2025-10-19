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

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bitfield::bitfield;

use crate::mem;
use crate::mem::emulated::{Action, Mmio};
#[cfg(target_arch = "x86_64")]
use crate::pci::host_bridge::HostBridge;
use crate::pci::segment::PciSegment;
use crate::pci::{Bdf, PciDevice, Result};

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
        let segment = Arc::new(PciSegment::new());

        #[cfg(target_arch = "x86_64")]
        segment.add(
            Bdf::new(0, 0, 0),
            PciDevice::new("host_bridge", Arc::new(HostBridge::new())),
        );

        PciBus {
            io_bus: Arc::new(PciIoBus {
                address: AtomicU32::new(0),
                segment: segment.clone(),
            }),
            segment,
        }
    }

    pub fn reserve(&self, bdf: Option<Bdf>) -> Option<Bdf> {
        self.segment.reserve(bdf)
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
