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

use std::fs::File;
use std::io::IoSliceMut;

use alioth::fuse::Fuse;
use alioth::fuse::bindings::{
    FUSE_ROOT_ID, FuseDirent, FuseDirentType, FuseInHeader, FuseOpcode, FuseOpenIn, FuseReadIn,
};
use alioth::fuse::passthrough::Passthrough;
use tempfile::TempDir;
use zerocopy::FromBytes;

const NUM_FILES: usize = 6;
// 24-byte FuseDirent + "file<N>" (5 bytes) padded to 8
const DIRENT_SIZE: usize = 32;

fn hdr(opcode: FuseOpcode) -> FuseInHeader {
    FuseInHeader {
        len: 0,
        opcode,
        unique: 0,
        nodeid: FUSE_ROOT_ID,
        uid: 0,
        gid: 0,
        pid: 0,
        total_extlen: 0,
        padding: 0,
    }
}

fn create_files(dir: &TempDir) -> Vec<String> {
    (0..NUM_FILES)
        .map(|i| {
            let name = format!("file{i}");
            File::create(dir.path().join(&name)).unwrap();
            name
        })
        .collect()
}

/// Parses dirents from a contiguous reply buffer of length `buf.len()`.
fn parse_dirents(mut buf: &[u8]) -> (Vec<String>, Vec<u64>) {
    let mut names = vec![];
    let mut offs = vec![];
    while !buf.is_empty() {
        let (dirent, rest) = FuseDirent::ref_from_prefix(buf).unwrap();
        let namelen = dirent.namelen as usize;
        assert!(namelen > 0);
        assert_eq!(dirent.type_, FuseDirentType::REG);
        let aligned_namelen = (namelen + 7) & !7;
        assert_eq!(
            &rest[namelen..aligned_namelen],
            &[0u8; 8][..aligned_namelen - namelen]
        );
        names.push(String::from_utf8(rest[..namelen].to_vec()).unwrap());
        offs.push(dirent.off);
        buf = &rest[aligned_namelen..];
    }
    (names, offs)
}

fn read_dir(dir: &TempDir, slice_lens: &[usize]) -> (usize, Vec<String>) {
    let mut fs = Passthrough::new(dir.path().into()).unwrap();
    let open = fs
        .open_dir(&hdr(FuseOpcode::OPENDIR), &FuseOpenIn::default())
        .unwrap();

    let mut storage: Vec<Vec<u8>> = slice_lens.iter().map(|&len| vec![0u8; len]).collect();
    let mut slices: Vec<IoSliceMut> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let total = fs
        .read_dir(
            &hdr(FuseOpcode::READDIR),
            &FuseReadIn {
                fh: open.fh,
                ..Default::default()
            },
            &mut slices,
        )
        .unwrap();

    let flat: Vec<u8> = storage.iter().flatten().copied().collect();
    assert!(flat[total..].iter().all(|&b| b == 0));
    let (mut names, offs) = parse_dirents(&flat[..total]);
    assert_eq!(offs, (1..=offs.len() as u64).collect::<Vec<_>>());
    names.sort();
    (total, names)
}

#[test]
fn read_dir_single_buffer_test() {
    let dir = TempDir::new().unwrap();
    let expected = create_files(&dir);
    let (total, names) = read_dir(&dir, &[4096]);
    assert_eq!(total, NUM_FILES * DIRENT_SIZE);
    assert_eq!(names, expected);
}

#[test]
fn read_dir_multiple_buffers_test() {
    let dir = TempDir::new().unwrap();
    let expected = create_files(&dir);
    let (total, names) = read_dir(&dir, &[64, 64, 64]);
    assert_eq!(total, NUM_FILES * DIRENT_SIZE);
    assert_eq!(names, expected);
}

#[test]
fn read_dir_straddles_buffer_boundary_test() {
    // A 40-byte buffer fits one 32-byte dirent and the first 8 bytes of the
    // next dirent, whose remaining 24 bytes spill into the following buffer.
    let dir = TempDir::new().unwrap();
    let expected = create_files(&dir);
    let (total, names) = read_dir(&dir, &[40; NUM_FILES]);
    assert_eq!(total, NUM_FILES * DIRENT_SIZE);
    assert_eq!(names, expected);
}

#[test]
fn read_dir_stops_when_buffers_full_test() {
    let dir = TempDir::new().unwrap();
    let expected = create_files(&dir);
    let (total, names) = read_dir(&dir, &[50, 50, 40]);
    assert_eq!(total, 4 * DIRENT_SIZE);
    assert_eq!(names.len(), 4);
    assert!(names.iter().all(|n| expected.contains(n)));
}
