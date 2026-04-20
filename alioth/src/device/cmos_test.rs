// Copyright 2026 Google LLC
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
use chrono::DateTime;

use crate::device::clock::tests::TestClock;
use crate::device::cmos::{Cmos, CmosRegA};
use crate::mem::emulated::Mmio;

#[test]
fn test_cmos() {
    // Nov 7, 2025 at 15:44:58.01 GMT-08:00
    let now = DateTime::from_timestamp_nanos(1_762_559_098_010_000_000);
    let cmos = Cmos::new(TestClock { now });
    assert_eq!(cmos.size(), 2);

    assert_matches!(cmos.write(0x0, 1, 0xb), Ok(_));
    assert_matches!(cmos.read(0x0, 1), Ok(0xb));
    assert_matches!(cmos.read(0x1, 1), Ok(0b110));

    assert_matches!(cmos.write(0x0, 1, 0xd), Ok(_));
    assert_matches!(cmos.read(0x1, 1), Ok(0x80));

    assert_matches!(cmos.write(0x0, 1, 0xa), Ok(_));
    let reg_a = cmos.read(0x1, 1).unwrap();
    assert!(
        !CmosRegA(reg_a as u8).update_in_progress(),
        "CMOS update should be complete"
    );

    let tests = [
        (0x00, 58),
        (0x02, 44),
        (0x04, 23),
        (0x06, 6),
        (0x07, 7),
        (0x08, 11),
        (0x09, 25),
        (0x32, 21),
    ];
    for (reg, expected) in tests {
        assert_matches!(cmos.write(0x0, 1, reg as u64), Ok(_));
        let value = cmos.read(0x1, 1).unwrap();
        assert_eq!(
            value as u32, expected,
            "CMOS register {reg:#02x} should match getter",
        );
    }

    // Reads from unknown registers are ignored.
    assert_matches!(cmos.write(0x0, 1, 0x01), Ok(_));
    assert_matches!(cmos.read(0x1, 1), Ok(0));

    // Writes to all registers are ignored.
    assert_matches!(cmos.write(0x1, 1, 0x0), Ok(_));
}

#[test]
fn test_cmos_upgrade_in_progress() {
    // Nov 27, 2025 at 07:45:00.00 GMT-08:00
    let now = DateTime::from_timestamp_nanos(1_764_258_300_000_000_000);
    let cmos = Cmos::new(TestClock { now });

    assert_matches!(cmos.write(0x0, 1, 0xa), Ok(_));
    let reg_a = cmos.read(0x1, 1).unwrap();
    assert!(
        CmosRegA(reg_a as u8).update_in_progress(),
        "CMOS update should be in progress"
    );
}
