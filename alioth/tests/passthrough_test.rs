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

/// Parses whole dirents from one buffer, stopping when the remainder is too
/// short for another one. Returns the names, offsets and bytes consumed.
fn parse_dirents(buf: &[u8]) -> (Vec<String>, Vec<u64>, usize) {
    let mut names = vec![];
    let mut offs = vec![];
    let mut off = 0;
    while off + size_of::<FuseDirent>() <= buf.len() {
        let (dirent, rest) = FuseDirent::ref_from_prefix(&buf[off..]).unwrap();
        let namelen = dirent.namelen as usize;
        // zero-initialized buffer tail past the replied data is not a dirent;
        // parsed == total below still catches corruption
        if dirent.type_ != FuseDirentType::REG || namelen == 0 {
            break;
        }
        let aligned_namelen = (namelen + 7) & !7;
        if rest.len() < aligned_namelen {
            break;
        }
        assert_eq!(dirent.type_, FuseDirentType::REG);
        names.push(String::from_utf8(rest[..namelen].to_vec()).unwrap());
        offs.push(dirent.off);
        off += size_of::<FuseDirent>() + aligned_namelen;
    }
    (names, offs, off)
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

    // every replied byte must belong to a whole dirent inside a single buffer
    let mut names = vec![];
    let mut offs = vec![];
    let mut parsed = 0;
    for buf in &storage {
        let (n, o, bytes) = parse_dirents(buf);
        names.extend(n);
        offs.extend(o);
        parsed += bytes;
    }
    assert_eq!(parsed, total);
    assert_eq!(offs, (1..=offs.len() as u64).collect::<Vec<_>>());
    (total, names)
}

fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names
}

#[test]
fn read_dir_single_buffer_test() {
    let dir = TempDir::new().unwrap();
    let mut expected = create_files(&dir);
    expected.sort();
    let (total, names) = read_dir(&dir, &[4096]);
    assert_eq!(total, NUM_FILES * DIRENT_SIZE);
    assert_eq!(sorted(names), expected);
}

#[test]
fn read_dir_multiple_buffers_test() {
    let dir = TempDir::new().unwrap();
    let mut expected = create_files(&dir);
    expected.sort();
    let (total, names) = read_dir(&dir, &[64, 64, 64]);
    assert_eq!(total, NUM_FILES * DIRENT_SIZE);
    assert_eq!(sorted(names), expected);
}

#[test]
fn read_dir_skips_buffer_remainder_test() {
    // a 40-byte buffer fits one dirent; the next dirent must not be split
    // into the trailing 8 bytes but start in the next buffer
    let dir = TempDir::new().unwrap();
    let mut expected = create_files(&dir);
    expected.sort();
    let (total, names) = read_dir(&dir, &[40; NUM_FILES]);
    assert_eq!(total, NUM_FILES * DIRENT_SIZE);
    assert_eq!(sorted(names), expected);
}

#[test]
fn read_dir_stops_when_buffers_full_test() {
    let dir = TempDir::new().unwrap();
    let mut expected = create_files(&dir);
    expected.sort();
    let (total, names) = read_dir(&dir, &[128]);
    assert_eq!(total, 4 * DIRENT_SIZE);
    assert_eq!(names.len(), 4);
    assert!(names.iter().all(|n| expected.contains(n)));
}
