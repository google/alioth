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

use rstest::rstest;

use crate::blk::qcow2::{Qcow2CmprDesc, Qcow2L1, Qcow2StdDesc};

#[rstest]
#[case(Qcow2L1(0xfe002cd | (1 << 63)), 0xfe00200)]
fn test_l1entry_l2_offset(#[case] entry: Qcow2L1, #[case] offset: u64) {
    assert_eq!(entry.l2_offset(), offset)
}

#[rstest]
#[case(Qcow2StdDesc(0xfe00201), 0xfe00200)]
fn test_std_desc_cluster_offset(#[case] desc: Qcow2StdDesc, #[case] offset: u64) {
    assert_eq!(desc.cluster_offset(), offset)
}

#[rstest]
#[case(Qcow2CmprDesc(0x100210), 0x100210, 0x1f0)]
#[case(Qcow2CmprDesc(0x100200 | (1 << 54)), 0x100200, 0x400)]
fn test_cmpr_desc_offset_size(#[case] desc: Qcow2CmprDesc, #[case] offset: u64, #[case] size: u64) {
    assert_eq!(desc.offset_size(16), (offset, size))
}
