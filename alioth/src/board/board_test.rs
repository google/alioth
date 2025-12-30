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

use crate::board::{CpuConfig, CpuTopology, Error};

#[test]
fn test_cpu_topology_fixup() {
    let mut empty = CpuConfig {
        count: 2,
        topology: CpuTopology::default(),
    };
    empty.fixup().unwrap();
    assert_matches!(
        empty,
        CpuConfig {
            count: 2,
            topology: CpuTopology {
                smt: false,
                cores: 2,
                sockets: 1
            }
        }
    );

    let mut invalid = CpuConfig {
        count: 2,
        topology: CpuTopology {
            smt: true,
            cores: 2,
            sockets: 1,
        },
    };
    assert_matches!(invalid.fixup(), Err(Error::InvalidCpuTopology { .. }))
}

#[rstest]
#[case(CpuTopology{smt: false, cores: 1, sockets: 1}, 0, (0, 0, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 0, (0, 0, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 1, (0, 1, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 2, (0, 0, 1))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1}, 3, (0, 1, 1))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 4, (0, 4, 0))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 11, (1, 5, 0))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 14, (0, 2, 1))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2}, 23, (1, 5, 1))]
fn test_cpu_topology_encode_decode(
    #[case] topology: CpuTopology,
    #[case] index: u16,
    #[case] ids: (u8, u16, u8),
) {
    assert_eq!(topology.encode(index), ids);
    let (socket_id, core_id, thread_id) = ids;
    assert_eq!(topology.decode(socket_id, core_id, thread_id), index);
}
