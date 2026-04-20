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
use rstest::rstest;

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

    fn read(&self, offset: u64, size: u8) -> Result<u64> {
        let val = *self.val.lock() >> (offset << 3);
        let mask = u64::MAX >> (64 - (size << 3));
        Ok(val & mask)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> Result<Action> {
        assert_eq!(size.count_ones(), 1);
        let v = &mut *self.val.lock();
        let shift = offset << 3;
        let mask = u64::MAX >> (64 - (size << 3));
        *v &= !(mask << shift);
        *v |= (val & mask) << shift;
        Ok(Action::None)
    }
}

// Creates a bus containing the following values:
// | 0x01 | 0x23 | 0x67 0x45 | 0xef 0xcd 0xab 0x89
//                           | 0x34 0x12 0xcd 0xab
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
#[case(0x0, 2, 0xff01)]
#[case(0x0, 3, 0xff_ff01)]
#[case(0x0, 4, 0xffff_ff01)]
#[case(0x0, 8, 0xffff_ffff_ffff_ff01)]
#[case(0x1, 1, 0x23)]
#[case(0x1, 2, 0xff23)]
#[case(0x1, 3, 0xff_ff23)]
#[case(0x1, 4, 0xffff_ff23)]
#[case(0x1, 8, 0xffff_ffff_ffff_ff23)]
#[case(0x4, 8, 0xffff_ffff_89ab_cdef)]
#[case(0x6, 1, 0xab)]
#[case(0x6, 2, 0x89ab)]
#[case(0x6, 4, 0xffff_89ab)]
#[case(0x8, 1, u64::MAX)]
#[case(0xa, 8, u64::MAX)]
#[case(0xe, 2, 0xabcd)]
fn test_mmio_bus_read(#[case] addr: u64, #[case] size: u8, #[case] val: u64) {
    let mmio_bus = fixture_mmio_bus();
    assert_eq!(
        mmio_bus.read(addr, size).unwrap(),
        val,
        "Read from addr {addr:#x} with size {size} failed"
    )
}

#[rstest]
#[case(0x0, 1, 0x3210, 0xffff_ffff_ffff_ff10)]
#[case(0x0, 2, 0x3210, 0xffff_ffff_ffff_3210)]
#[case(0x0, 4, 0x10, 0xffff_ffff_0000_0010)]
#[case(0x0, 8, 0x10, 0x10)]
#[case(0x1, 1, 0x32, 0xffff_ffff_ffff_ff32)]
#[case(0x1, 2, 0x7632, 0xffff_ffff_ffff_7632)]
#[case(0x1, 4, 0xfe54_7632, 0xffff_ffff_fe54_7632)]
#[case(0x1, 8, 0x0, 0x0)]
#[case(0x4, 8, 0x1234_89ab_cdef, 0x1234_89ab_cdef)]
#[case(0x6, 1, 0xba, 0xffff_ffff_89ba)]
#[case(0x6, 2, 0x98ba, 0xffff_ffff_98ba)]
#[case(0x6, 4, 0xcd_ab98, 0xffff_00cd_ab98)]
#[case(0x8, 1, 0xff, u64::MAX)]
fn test_mmio_bus_write(
    #[case] addr: u64,
    #[case] size: u8,
    #[case] val: u64,
    #[case] expected: u64,
) {
    let mmio_bus = fixture_mmio_bus();
    assert!(mmio_bus.write(addr, size, val).is_ok());
    assert_eq!(mmio_bus.read(addr, 8).unwrap(), expected);
}
