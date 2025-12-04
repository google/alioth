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

use parking_lot::Mutex;
use rstest::{fixture, rstest};

use super::{Action, Mmio, MmioBus};
use crate::mem::Result;

#[derive(Debug)]
struct TestRange {
    size: u64,
    val: Mutex<u64>,
}

impl Mmio for TestRange {
    fn size(&self) -> u64 {
        self.size
    }

    fn read(&self, offset: u64, _size: u8) -> Result<u64> {
        let val = *self.val.lock() >> (offset << 3);
        Ok(val)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> Result<Action> {
        assert_eq!(size.count_ones(), 1);
        assert!(offset.trailing_zeros() >= size.trailing_zeros());
        let v = &mut *self.val.lock();
        let shift = offset << 3;
        *v &= !(((1 << (size << 3)) - 1) << shift);
        *v |= val << shift;
        Ok(Action::None)
    }
}

// Creates a bus containing the following values:
// | 0x01 | 0x23 | 0x67 0x45 | 0xef 0xcd 0xab 0x89
//                           | 0x34 0x12 0xcd 0xab
#[fixture]
fn fixture_mmio_bus() -> MmioBus {
    let mut bus: MmioBus = MmioBus::new();
    for (offset, size, val) in [
        (0x0, 1, 0xffff_ffff_ffff_ff01),
        (0x1, 1, 0xffff_ffff_ffff_ff23),
        (0x2, 2, 0xffff_ffff_ffff_4567),
        (0x4, 4, 0xffff_ffff_89ab_cdef),
        (0xc, 4, 0xffff_ffff_abcd_1234),
    ] {
        bus.add(
            offset,
            Arc::new(TestRange {
                size,
                val: Mutex::new(val),
            }),
        )
        .unwrap();
    }
    bus
}

#[rstest]
#[case(0x0, 1, 0x01)]
#[case(0x0, 2, 0x2301)]
#[case(0x0, 3, 0x672301)]
#[case(0x0, 4, 0x45672301)]
#[case(0x0, 8, 0x89ab_cdef_4567_2301)]
#[case(0x1, 1, 0x23)]
#[case(0x1, 2, 0x6723)]
#[case(0x1, 3, 0x45_6723)]
#[case(0x1, 4, 0xef45_6723)]
#[case(0x1, 8, 0x89_abcd_ef45_6723)]
#[case(0x4, 8, 0x89ab_cdef)]
#[case(0x6, 1, 0xab)]
#[case(0x6, 2, 0x89ab)]
#[case(0x6, 4, 0x89ab)]
#[case(0x8, 1, 0x0)]
#[case(0x8, 4, 0x0)]
#[case(0x8, 5, 0x34_0000_0000)]
#[case(0x8, 8, 0xabcd_1234_0000_0000)]
#[case(0xa, 8, 0x0000_abcd_1234_0000)]
fn test_mmio_bus_read(
    fixture_mmio_bus: MmioBus,
    #[case] addr: u64,
    #[case] size: u8,
    #[case] val: u64,
) {
    assert_eq!(fixture_mmio_bus.read(addr, size).unwrap(), val)
}

#[rstest]
#[case(0x0, 1, 0x3210, 0x89ab_cdef_4567_2310)]
#[case(0x0, 2, 0x3210, 0x89ab_cdef_4567_3210)]
#[case(0x0, 3, 0x763201, 0x89ab_cdef_4576_3201)]
#[case(0x0, 4, 0x10, 0x89ab_cdef_0000_0010)]
#[case(0x0, 8, 0x10, 0x10)]
#[case(0x1, 1, 0x32, 0x89_abcd_ef45_6732)]
#[case(0x1, 2, 0x7632, 0x89_abcd_ef45_7632)]
#[case(0x1, 3, 0x1254_7632, 0x89_abcd_ef54_7632)]
#[case(0x1, 4, 0xfe54_7632, 0x89_abcd_fe54_7632)]
#[case(0x1, 8, 0x0, 0x0)]
#[case(0x4, 8, 0x1234_89ab_cdef, 0x89ab_cdef)]
#[case(0x6, 1, 0xba, 0x1234_0000_0000_89ba)]
#[case(0x6, 2, 0x98ba, 0x1234_0000_0000_98ba)]
#[case(0x6, 4, 0xff_ab98, 0x1234_0000_0000_ab98)]
#[case(0x8, 1, 0xff, 0xabcd_1234_0000_0000)]
#[case(0x8, 4, 0xffff, 0xabcd_1234_0000_0000)]
#[case(0x8, 5, 0xfe_1234_0000, 0xabcd_12fe_0000_0000)]
#[case(0x8, 8, 0x5678_cdfe_1234_0000, 0x5678_cdfe_0000_0000)]
#[case(0xa, 8, 0xcdfe_1234_abcd, 0xcdfe_1234_0000)]
fn test_mmio_bus_write(
    fixture_mmio_bus: MmioBus,
    #[case] addr: u64,
    #[case] size: u8,
    #[case] val: u64,
    #[case] expected: u64,
) {
    assert!(fixture_mmio_bus.write(addr, size, val).is_ok());
    assert_eq!(fixture_mmio_bus.read(addr, 8).unwrap(), expected);
}
