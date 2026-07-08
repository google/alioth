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

use crate::arch::reg::MpidrEl1;
use crate::board::CpuTopology;
use crate::board::aarch64::encode_mpidr;

#[rstest]
#[case(CpuTopology{smt: false, cores: 1, sockets: 1}, 1, 1)]
#[case(CpuTopology{smt: true, cores: 8, sockets: 1}, 8, 1)]
#[case(CpuTopology{smt: true, cores: 8, sockets: 4}, 45, (1 << 16) | (5 << 8) | 1)]
fn test_encode_mpidr(#[case] topology: CpuTopology, #[case] index: u16, #[case] mpidr: u64) {
    assert_eq!(encode_mpidr(&topology, index), MpidrEl1(mpidr));
}
