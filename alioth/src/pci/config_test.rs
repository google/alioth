// Copyright 2025 Google LLC
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

use crate::mem::emulated::{Action, Mmio};
use crate::mem::{self, IoRegion, MemRegion, MemRegionType};
use crate::pci::PciBar;
use crate::pci::config::{
    BAR_IO, BAR_MEM32, BAR_MEM64, ConfigHeader, DeviceHeader, EmulatedHeader,
};

#[derive(Debug)]
struct TestRange {
    size: u64,
}

impl Mmio for TestRange {
    fn read(&self, _: u64, _: u8) -> mem::Result<u64> {
        Ok(0)
    }

    fn write(&self, _: u64, _: u8, _: u64) -> mem::Result<Action> {
        Ok(Action::None)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[test]
fn test_emulated_header() {
    let header = ConfigHeader::Device(DeviceHeader {
        bars: [BAR_MEM32, 0, BAR_MEM64, 0, 0, BAR_IO],
        ..Default::default()
    });
    let bars = [
        PciBar::Mem(Arc::new(MemRegion::with_emulated(
            Arc::new(TestRange { size: 1 << 10 }),
            MemRegionType::Hidden,
        ))),
        PciBar::Empty,
        PciBar::Mem(Arc::new(MemRegion::with_emulated(
            Arc::new(TestRange { size: 16 << 10 }),
            MemRegionType::Hidden,
        ))),
        PciBar::Empty,
        PciBar::Empty,
        PciBar::Io(Arc::new(IoRegion::new(Arc::new(TestRange { size: 2 })))),
    ];

    let emulated_header = EmulatedHeader::new(header, bars);

    let data = emulated_header.data.read();
    assert_eq!(
        data.bar_masks,
        [0xffff_f000, 0x0, 0xffff_c000, 0xffff_ffff, 0x0, 0xffff_fffc,]
    );
}
