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

use bitflags::bitflags;

use crate::mem::emulated::Mmio;
use crate::mem::{self, Action, MemRegion};
use crate::pci::cap::PciCapList;
use crate::pci::config::{
    CommonHeader, DeviceHeader, EmulatedConfig, HeaderType, PciConfig, BAR_MEM64, BAR_PREFETCHABLE,
};
use crate::pci::{self, Pci, PciBar};

bitflags! {
    #[derive(Debug)]
    struct PvPanicByte: u8 {
        const PANICKED = 1 << 0;
        const CRASH_LOADED = 1 << 1;
    }
}

const PVPANIC_VENDOR_ID: u16 = 0x1b36;
const PVPANIC_DEVICE_ID: u16 = 0x0011;

#[derive(Debug)]
struct PvPanicBar<const N: usize>;

impl<const N: usize> Mmio for PvPanicBar<N> {
    fn size(&self) -> usize {
        N
    }

    fn read(&self, _offset: usize, _size: u8) -> mem::Result<u64> {
        Ok(PvPanicByte::all().bits() as u64)
    }

    fn write(&self, _offset: usize, _size: u8, val: u64) -> mem::Result<()> {
        log::info!("pvpanic: {:x?}", PvPanicByte::from_bits_retain(val as u8));
        Err(mem::Error::Action(Action::Shutdown))
    }
}

#[derive(Debug)]
pub struct PvPanic {
    pub config: Arc<EmulatedConfig>,
}

impl PvPanic {
    pub fn new() -> Self {
        const BAR_SIZE: usize = 0x1000;
        let header = DeviceHeader {
            common: CommonHeader {
                vendor: PVPANIC_VENDOR_ID,
                device: PVPANIC_DEVICE_ID,
                revision: 1,
                header_type: HeaderType::Device as u8,
                class: 0x08,
                subclass: 0x80,
                ..Default::default()
            },
            bars: [BAR_MEM64 | BAR_PREFETCHABLE, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        let bar_masks = [!(BAR_SIZE as u32 - 1), 0xffff_ffff, 0, 0, 0, 0];
        let bar0 = PciBar::Mem64(Arc::new(MemRegion::with_emulated(
            Arc::new(PvPanicBar::<BAR_SIZE>),
            mem::MemRegionType::Hidden,
        )));
        let mut bars = PciBar::empty_6();
        bars[0] = bar0;
        let config = EmulatedConfig::new_device(header, bar_masks, bars, PciCapList::new());
        PvPanic {
            config: Arc::new(config),
        }
    }
}

impl Default for PvPanic {
    fn default() -> Self {
        PvPanic::new()
    }
}

impl Pci for PvPanic {
    fn config(&self) -> Arc<dyn PciConfig> {
        self.config.clone()
    }

    fn reset(&self) -> pci::Result<()> {
        Ok(())
    }
}
