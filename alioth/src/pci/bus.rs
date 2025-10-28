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

#[cfg(test)]
#[path = "bus_test.rs"]
mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bitfield::bitfield;

use crate::mem;
use crate::mem::emulated::{Action, Mmio};
#[cfg(target_arch = "x86_64")]
use crate::pci::host_bridge::HostBridge;
use crate::pci::segment::PciSegment;
use crate::pci::{Bdf, Pci, Result};

bitfield! {
    #[derive(Copy, Clone, Default)]
    struct Address(u32);
    impl Debug;
    impl new;
    pub bool, enabled, set_enabled: 31;
    pub u8, bus, set_bus: 23, 16;
    pub u8, dev, set_dev: 15, 11;
    pub u8, func, set_func: 10, 8;
    pub u8, offset, set_offset: 7, 0;
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
                if size == 4 {
                    Ok(self.address.load(Ordering::Acquire) as u64)
                } else {
                    Ok(0)
                }
            }
            4..=7 => {
                let addr = Address(self.address.load(Ordering::Acquire));
                if addr.enabled() {
                    let ecam_addr = addr.to_ecam_addr() | (offset & 0b11);
                    self.segment.read(ecam_addr, size)
                } else {
                    Ok(0)
                }
            }
            _ => Ok(0),
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        match offset {
            0 => {
                if size == 4 {
                    self.address.store(val as u32, Ordering::Release);
                }
                Ok(Action::None)
            }
            4..=7 => {
                let addr = Address(self.address.load(Ordering::Acquire));
                if addr.enabled() {
                    let ecam_addr = addr.to_ecam_addr() | (offset & 0b11);
                    self.segment.write(ecam_addr, size, val)
                } else {
                    Ok(Action::None)
                }
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
        segment.add(Bdf::new(0, 0, 0), Arc::new(HostBridge::new()));

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

    pub fn add(&self, bdf: Bdf, dev: Arc<dyn Pci>) -> Option<Arc<dyn Pci>> {
        self.segment.add(bdf, dev)
    }
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}
