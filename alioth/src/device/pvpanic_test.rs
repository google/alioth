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

use assert_matches::assert_matches;
use rstest::rstest;

use crate::device::pvpanic::{PVPANIC_DEVICE_ID, PVPANIC_VENDOR_ID, PvPanic, PvPanicBar};
use crate::mem::emulated::{Action, Mmio};
use crate::pci::Pci;
use crate::pci::config::{BAR_MEM64, BAR_PREFETCHABLE, CommonHeader, HeaderType, offset_bar};

#[rstest]
#[case(CommonHeader::OFFSET_VENDOR, 2, PVPANIC_VENDOR_ID as u64)]
#[case(CommonHeader::OFFSET_DEVICE, 2, PVPANIC_DEVICE_ID as u64)]
#[case(CommonHeader::OFFSET_REVISION, 1, 1)]
#[case(CommonHeader::OFFSET_HEADER_TYPE, 1, HeaderType::DEVICE.raw() as u64)]
#[case(CommonHeader::OFFSET_CLASS, 1, 0x08)]
#[case(CommonHeader::OFFSET_SUBCLASS, 1, 0x80)]
#[case(offset_bar(0), 4, (BAR_MEM64 | BAR_PREFETCHABLE) as u64)]
#[case(offset_bar(1), 4, 0)]
#[case(offset_bar(2), 4, 0)]
#[case(offset_bar(3), 4, 0)]
#[case(offset_bar(4), 4, 0)]
#[case(offset_bar(5), 4, 0)]
fn test_pvpanic_read_config(#[case] offset: usize, #[case] size: u8, #[case] value: u64) {
    let dev = PvPanic::default();
    assert_matches!(dev.reset(), Ok(_));
    assert_matches!(dev.name(), "pvpanic");

    let config = dev.config();
    assert_eq!(config.read(offset as u64, size).unwrap(), value);
}

#[test]
fn test_pvpanic_bar() {
    let bar = PvPanicBar;

    assert_matches!(bar.read(0, 1), Ok(0b11));
    assert_matches!(bar.write(0, 1, 1), Ok(Action::Shutdown));
}
