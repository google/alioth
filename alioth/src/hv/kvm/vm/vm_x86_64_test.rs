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

use rstest::rstest;

use crate::hv::kvm::vm::x86_64::translate_msi_addr;

#[rstest]
#[case(0, 0)]
#[case(0xfee0_0010, 0xfee0_0010)]
#[case(0xfee0_1000, 0xfee0_1000)]
#[case(0x100_fee0_1000, 0x100_fee0_1000)]
#[case(0xfee0_1020, 0x100_fee0_1000)]
fn test_translate_msi_addr(#[case] addr: u64, #[case] expected: u64) {
    let (lo, hi) = translate_msi_addr(addr as u32, (addr >> 32) as u32);
    assert_eq!((lo as u64) | ((hi as u64) << 32), expected);
}
