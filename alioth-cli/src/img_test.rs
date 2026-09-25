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

use std::fs::{self, File};
use std::os::unix::fs::FileExt;

use alioth::blk::qcow2::{QCOW2_MAGIC, Qcow2Hdr};
use alioth::utils::endian::Bu64;
use assert_matches::assert_matches;
use rstest::rstest;
use tempfile::TempDir;
use zerocopy::{FromZeros, IntoBytes};

use crate::img::{Error, convert_qcow2_to_raw};

const COPIED: u64 = 1 << 63;

fn qcow2_hdr(cluster_bits: u32) -> Qcow2Hdr {
    let mut hdr = Qcow2Hdr::new_zeroed();
    hdr.magic = QCOW2_MAGIC;
    hdr.version = 3.into();
    hdr.cluster_bits = cluster_bits.into();
    hdr
}

#[rstest]
#[case(0)]
#[case(8)]
#[case(22)]
#[case(63)]
#[case(64)]
#[case(u32::MAX)]
fn test_convert_qcow2_invalid_cluster_bits(#[case] cluster_bits: u32) {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("input.qcow2");
    let output = dir.path().join("output.raw");

    let mut hdr = qcow2_hdr(cluster_bits);
    hdr.size = (1 << 20).into();
    fs::write(&input, hdr.as_bytes()).unwrap();

    assert_matches!(
        convert_qcow2_to_raw(&input, &output),
        Err(Error::InvalidClusterBits { bits, .. }) if bits == cluster_bits
    );
}

#[rstest]
#[case(9)]
#[case(16)]
#[case(21)]
fn test_convert_qcow2_to_raw(#[case] cluster_bits: u32) {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("input.qcow2");
    let output = dir.path().join("output.raw");

    // Guest cluster 0 is unallocated and guest cluster 1 maps to data_offset.
    let cluster_size = 1u64 << cluster_bits;
    let l1_offset = cluster_size;
    let l2_offset = 2 * cluster_size;
    let data_offset = 3 * cluster_size;

    let mut hdr = qcow2_hdr(cluster_bits);
    hdr.size = (2 * cluster_size).into();
    hdr.l1_size = 1.into();
    hdr.l1_table_offset = l1_offset.into();
    let l1_entry = Bu64::from(l2_offset | COPIED);
    let l2_entry = Bu64::from(data_offset | COPIED);
    let data: Vec<u8> = (0..cluster_size).map(|i| i as u8).collect();

    let f = File::create(&input).unwrap();
    f.write_all_at(hdr.as_bytes(), 0).unwrap();
    f.write_all_at(l1_entry.as_bytes(), l1_offset).unwrap();
    f.write_all_at(l2_entry.as_bytes(), l2_offset + 8).unwrap();
    f.write_all_at(&data, data_offset).unwrap();

    convert_qcow2_to_raw(&input, &output).unwrap();

    let raw = fs::read(&output).unwrap();
    let (cluster0, cluster1) = raw.split_at(cluster_size as usize);
    assert!(cluster0.iter().all(|&b| b == 0));
    assert!(cluster1 == data);
}
