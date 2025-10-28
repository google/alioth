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

use assert_matches::assert_matches;
use rstest::rstest;

use crate::device::pvpanic::{PVPANIC_DEVICE_ID, PVPANIC_VENDOR_ID, PvPanic};
use crate::mem::emulated::{Action, Mmio};
use crate::pci::Bdf;
use crate::pci::config::{BAR_MEM_MASK, CommonHeader, offset_bar};
use crate::pci::segment::PciSegment;

#[rstest]
#[case(vec![], None, Some(Bdf::new(0, 0, 0)))]
#[case(vec![Bdf::new(0, 0, 0), Bdf::new(0, 1, 0)], None, Some(Bdf::new(0, 2, 0)))]
#[case(vec![Bdf::new(0, 0, 0)], Some(Bdf::new(0, 0, 0)), None)]
#[case(vec![Bdf::new(0, 0, 0)], Some(Bdf::new(0, 1, 0)), Some(Bdf::new(0, 1, 0)))]
fn test_pci_segment_reserve(
    #[case] devices: Vec<Bdf>,
    #[case] reserve_bdf: Option<Bdf>,
    #[case] expected: Option<Bdf>,
) {
    let segment = PciSegment::default();
    for bdf in devices {
        let test_dev = Arc::new(PvPanic::new());
        assert_matches!(segment.add(bdf, test_dev.clone()), None);
    }

    assert_eq!(segment.reserve(reserve_bdf), expected);

    if let Some(bdf) = expected {
        let test_dev = Arc::new(PvPanic::new());
        assert_matches!(segment.add(bdf, test_dev.clone()), None);
    }
}

#[test]
fn test_pci_segment_mmio() {
    let segment = PciSegment::new();

    assert_eq!(segment.size(), 256 << 20);
    assert_matches!(segment.read(0, 1), Ok(u64::MAX));
    assert_matches!(segment.write(0, 1, 0), Ok(Action::None));

    let base = 8 * (4 << 10);
    let test_dev = Arc::new(PvPanic::new());

    assert_matches!(segment.add(Bdf::new(0, 1, 0), test_dev), None);

    for (offset, expected) in [
        (CommonHeader::OFFSET_VENDOR, PVPANIC_VENDOR_ID),
        (CommonHeader::OFFSET_DEVICE, PVPANIC_DEVICE_ID),
    ] {
        let got = segment.read(offset as u64 + base, 2).unwrap();
        assert_eq!(got, expected as u64);
    }

    assert_matches!(
        segment.write(base + offset_bar(0) as u64, 4, 0xee00_0000),
        Ok(Action::None)
    );
    assert_eq!(
        segment.read(base + offset_bar(0) as u64, 4).unwrap() as u32 & !BAR_MEM_MASK,
        0xee00_0000
    );
}

#[test]
fn test_pci_segment_next_bdf_wrapping() {
    let segment = PciSegment::new();

    for bdf in [Bdf::new(0, 0, 0), Bdf::new(255, 31, 0)] {
        let test_dev = Arc::new(PvPanic::new());
        assert_matches!(segment.add(bdf, test_dev), None);
    }

    *segment.next_bdf.lock() = Bdf::new(255, 31, 0);

    assert_eq!(segment.reserve(None), Some(Bdf::new(0, 1, 0)));
}
