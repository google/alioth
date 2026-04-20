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

use crate::arch::aarch64::layout::PL031_START;
use crate::device::clock::tests::TestClock;
use crate::device::pl031::{
    Pl031, RTC_CR, RTC_DR, RTC_ICR, RTC_IMSC, RTC_LR, RTC_MIS, RTC_MR, RTC_PCELL_ID0,
    RTC_PCELL_ID1, RTC_PCELL_ID2, RTC_PCELL_ID3, RTC_PERIPH_ID0, RTC_PERIPH_ID1, RTC_PERIPH_ID2,
    RTC_PERIPH_ID3, RTC_RIS,
};
use crate::mem::emulated::Mmio;

#[test]
fn test_pl031() {
    // Nov 21, 2025 at 15:16:59 GMT-08:00
    let now = DateTime::from_timestamp_nanos(1_763_767_019_000_000_000);
    let mut pl031 = Pl031::new(PL031_START, TestClock { now });

    assert_eq!(pl031.size(), 0x1000);

    assert_matches!(pl031.write(RTC_DR, 4, 33), Ok(_)); // ignored
    assert_matches!(pl031.read(RTC_DR, 4), Ok(1763767019));

    assert_matches!(pl031.write(RTC_LR, 4, 1763770619), Ok(_));
    pl031.clock.tick();
    assert_matches!(pl031.read(RTC_LR, 4), Ok(1763770619));
    assert_matches!(pl031.read(RTC_DR, 4), Ok(1763770620));

    assert_matches!(pl031.write(RTC_MR, 4, 750), Ok(_));
    assert_matches!(pl031.read(RTC_MR, 4), Ok(750));

    assert_matches!(pl031.write(RTC_CR, 4, 0), Ok(_)); // Write to CR is ignored
    assert_matches!(pl031.read(RTC_CR, 4), Ok(1));

    assert_matches!(pl031.write(RTC_IMSC, 4, 1), Ok(_)); // Unmask interrupt
    assert_matches!(pl031.read(RTC_IMSC, 4), Ok(0)); // Ignored

    assert_matches!(pl031.write(RTC_ICR, 4, 1), Ok(_));
    assert_matches!(pl031.read(RTC_ICR, 4), Ok(0));

    assert_matches!(pl031.read(RTC_RIS, 4), Ok(0));
    assert_matches!(pl031.read(RTC_MIS, 4), Ok(0));

    assert_matches!(pl031.read(RTC_PERIPH_ID0, 4), Ok(0x31));
    assert_matches!(pl031.read(RTC_PERIPH_ID1, 4), Ok(0x10));
    assert_matches!(pl031.read(RTC_PERIPH_ID2, 4), Ok(0x04));
    assert_matches!(pl031.read(RTC_PERIPH_ID3, 4), Ok(0x00));

    assert_matches!(pl031.read(RTC_PCELL_ID0, 4), Ok(0x0d));
    assert_matches!(pl031.read(RTC_PCELL_ID1, 4), Ok(0xf0));
    assert_matches!(pl031.read(RTC_PCELL_ID2, 4), Ok(0x05));
    assert_matches!(pl031.read(RTC_PCELL_ID3, 4), Ok(0xb1));
}
