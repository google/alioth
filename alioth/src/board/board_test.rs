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

use crate::board::{CpuSpec, CpuTopology};

#[rstest]
#[case(CpuSpec {
    count: 2,
    topology: CpuTopology {
        smt: false,
        cores: 2,
        sockets: 1,
        ..Default::default()
    },
}, true)]
#[case(CpuSpec {
    count: 2,
    topology: CpuTopology {
        smt: true,
        cores: 2,
        sockets: 1,
        ..Default::default()
    },
}, false)]
fn test_cpu_topology_validate(#[case] spec: CpuSpec, #[case] expected: bool) {
    assert_eq!(spec.validate(), expected);
}

#[rstest]
#[case(CpuTopology{smt: false, cores: 1, sockets: 1, thread_contiguous: false}, 0, (0, 0, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: false}, 0, (0, 0, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: false}, 1, (0, 1, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: false}, 2, (0, 0, 1))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: false}, 3, (0, 1, 1))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: false}, 4, (0, 4, 0))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: false}, 11, (1, 5, 0))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: false}, 14, (0, 2, 1))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: false}, 23, (1, 5, 1))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: true}, 0, (0, 0, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: true}, 1, (0, 0, 1))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: true}, 2, (0, 1, 0))]
#[case(CpuTopology{smt: true, cores: 2, sockets: 1, thread_contiguous: true}, 3, (0, 1, 1))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: true}, 4, (0, 2, 0))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: true}, 11, (0, 5, 1))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: true}, 14, (1, 1, 0))]
#[case(CpuTopology{smt: true, cores: 6, sockets: 2, thread_contiguous: true}, 23, (1, 5, 1))]
fn test_cpu_topology_encode_decode(
    #[case] topology: CpuTopology,
    #[case] index: u16,
    #[case] ids: (u8, u16, u8),
) {
    assert_eq!(topology.encode(index), ids);
    let (socket_id, core_id, thread_id) = ids;
    assert_eq!(topology.decode(socket_id, core_id, thread_id), index);
}
