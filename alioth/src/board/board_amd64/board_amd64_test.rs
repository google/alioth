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

use crate::board::CpuTopology;
use crate::board::x86_64::encode_x2apic_id;

#[rstest]
#[case(CpuTopology{smt: false, cores: 1, sockets: 1}, 0, 0)]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 0, 0)]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 1, 2)]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 2, 1)]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 3, 3)]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 4, 8)]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 11, 26)]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 14, 5)]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 23, 27)]
fn test_encode_x2apic(#[case] topology: CpuTopology, #[case] index: u16, #[case] x2apic: u32) {
    assert_eq!(encode_x2apic_id(&topology, index), x2apic)
}
