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

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::IoSliceMut;
use std::os::unix;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alioth::fuse::bindings::{
    FUSE_ROOT_ID, FuseCreateIn, FuseDirent, FuseDirentType, FuseInHeader, FuseOpcode, FuseOpenIn,
    FuseReadIn, FuseRenameIn,
};
use alioth::fuse::passthrough::Passthrough;
use alioth::fuse::{Error, Fuse};
use assert_matches::assert_matches;
use rstest::rstest;
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

/// Creates a file for reading and writing, truncating it if it exists.
const CREATE_IN: FuseCreateIn = FuseCreateIn {
    flags: (libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) as u32,
    mode: 0o644,
    umask: 0,
    open_flags: 0,
};

/// A shared directory `share`, and its sibling `outside`, which must not be
/// accessible through `share`.
struct Dirs {
    _tmp: TempDir,
    share: Box<Path>,
    outside: Box<Path>,
}

impl Dirs {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let share: Box<Path> = tmp.path().join("share").into();
        let outside: Box<Path> = tmp.path().join("outside").into();
        fs::create_dir(&share).unwrap();
        fs::create_dir(&outside).unwrap();
        Dirs {
            _tmp: tmp,
            share,
            outside,
        }
    }

    fn passthrough(&self) -> Passthrough {
        Passthrough::new(self.share.clone()).unwrap()
    }
}

fn c_name(name: impl AsRef<OsStr>) -> Vec<u8> {
    let name = CString::new(name.as_ref().as_bytes()).unwrap();
    name.into_bytes_with_nul()
}

#[rstest]
#[case::empty("")]
#[case::dot(".")]
#[case::dot_dot("..")]
#[case::parent("../outside/file")]
#[case::separator("dir/file")]
fn lookup_invalid_name_test(#[case] name: &str) {
    let dirs = Dirs::new();
    fs::create_dir(dirs.share.join("dir")).unwrap();
    File::create(dirs.share.join("dir/file")).unwrap();
    File::create(dirs.outside.join("file")).unwrap();

    let mut fuse = dirs.passthrough();
    let err = fuse
        .lookup(&hdr(FuseOpcode::LOOKUP), &c_name(name))
        .unwrap_err();
    assert_matches!(err, Error::InvalidFileName { .. });
    assert_eq!(err.error_code(), libc::EINVAL);
}

#[rstest]
#[case::hidden(".hidden")]
#[case::dots("...")]
#[case::inner_dots("a..b")]
fn lookup_valid_name_test(#[case] name: &str) {
    let dirs = Dirs::new();
    File::create(dirs.share.join(name)).unwrap();

    let mut fuse = dirs.passthrough();
    let ret = fuse.lookup(&hdr(FuseOpcode::LOOKUP), &c_name(name));
    assert_matches!(ret, Ok(_));
}

#[test]
fn create_outside_test() {
    let dirs = Dirs::new();

    let mut fuse = dirs.passthrough();
    let name = c_name("../outside/file");
    let ret = fuse.create(&hdr(FuseOpcode::CREATE), &CREATE_IN, &name);
    assert_matches!(ret, Err(Error::InvalidFileName { .. }));
    assert!(!dirs.outside.join("file").exists());
}

#[test]
fn unlink_outside_test() {
    let dirs = Dirs::new();
    let file = dirs.outside.join("file");
    File::create(&file).unwrap();

    let mut fuse = dirs.passthrough();
    let ret = fuse.unlink(&hdr(FuseOpcode::UNLINK), &c_name(&file));
    assert_matches!(ret, Err(Error::InvalidFileName { .. }));
    assert!(file.exists());
}

#[test]
fn rmdir_share_test() {
    let dirs = Dirs::new();

    let mut fuse = dirs.passthrough();
    let ret = fuse.rmdir(&hdr(FuseOpcode::RMDIR), &c_name(""));
    assert_matches!(ret, Err(Error::InvalidFileName { .. }));
    assert!(dirs.share.exists());
}

#[rstest]
#[case::from_outside("../outside/file", "file")]
#[case::to_outside("file", "../outside/file")]
fn rename_outside_test(#[case] src: &str, #[case] dst: &str) {
    let dirs = Dirs::new();
    fs::write(dirs.share.join("file"), "share").unwrap();
    fs::write(dirs.outside.join("file"), "outside").unwrap();

    let mut fuse = dirs.passthrough();
    let in_ = FuseRenameIn {
        newdir: FUSE_ROOT_ID,
    };
    let names = [c_name(src), c_name(dst)].concat();
    let ret = fuse.rename(&hdr(FuseOpcode::RENAME), &in_, &names);
    assert_matches!(ret, Err(Error::InvalidFileName { .. }));

    let share = fs::read_to_string(dirs.share.join("file")).unwrap();
    assert_eq!(share, "share");
    let outside = fs::read_to_string(dirs.outside.join("file")).unwrap();
    assert_eq!(outside, "outside");
}

#[rstest]
#[case::file(false)]
#[case::symlink(true)]
fn create_test(#[case] symlink: bool) {
    let dirs = Dirs::new();
    let target = dirs.outside.join("file");
    fs::write(&target, "outside").unwrap();
    let file = dirs.share.join("file");
    if symlink {
        unix::fs::symlink(&target, &file).unwrap();
    }

    let mut fuse = dirs.passthrough();
    let ret = fuse.create(&hdr(FuseOpcode::CREATE), &CREATE_IN, &c_name("file"));
    if symlink {
        assert_eq!(ret.unwrap_err().error_code(), libc::ELOOP);
    } else {
        assert_matches!(ret, Ok(_));
        assert!(file.is_file());
    }
    assert_eq!(fs::read_to_string(target).unwrap(), "outside");
}

#[rstest]
#[case::file(false)]
#[case::symlink(true)]
fn open_test(#[case] symlink: bool) {
    let dirs = Dirs::new();
    let target = dirs.outside.join("file");
    fs::write(&target, "outside").unwrap();
    let file = dirs.share.join("file");
    fs::write(&file, "share").unwrap();

    let mut fuse = dirs.passthrough();
    let entry = fuse
        .lookup(&hdr(FuseOpcode::LOOKUP), &c_name("file"))
        .unwrap();
    if symlink {
        // The file is replaced with a symbolic link after the lookup.
        fs::remove_file(&file).unwrap();
        unix::fs::symlink(&target, &file).unwrap();
    }

    let open_hdr = FuseInHeader {
        nodeid: entry.nodeid,
        ..hdr(FuseOpcode::OPEN)
    };
    let in_ = FuseOpenIn {
        flags: (libc::O_RDWR | libc::O_TRUNC) as u32,
        open_flags: 0,
    };
    let ret = fuse.open(&open_hdr, &in_);
    if symlink {
        assert_eq!(ret.unwrap_err().error_code(), libc::ELOOP);
    } else {
        assert_matches!(ret, Ok(_));
        assert_eq!(fs::read_to_string(file).unwrap(), "");
    }
    assert_eq!(fs::read_to_string(target).unwrap(), "outside");
}
