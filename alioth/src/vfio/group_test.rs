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

use std::io::Write;
use std::sync::Arc;

use assert_matches::assert_matches;

use crate::sys::vfio::{VfioRegionInfo, VfioRegionInfoFlag};
use crate::vfio::device::{Device, Kdev};
use crate::vfio::group::{DevFd, Group};

#[test]
fn test_group_detach_when_not_attached() {
    // Group detach when not attached returns Ok(())
    let tmp_group = tempfile::NamedTempFile::new().unwrap();
    let mut group = Group::new(tmp_group.path()).unwrap();
    assert_matches!(group.detach(), Ok(()));
}

#[test]
fn test_dev_fd_device_impl() {
    let fake_group = tempfile::NamedTempFile::new().unwrap();
    let mut fake_dev = tempfile::NamedTempFile::new().unwrap();

    fake_dev
        .write_all(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        .unwrap();

    let group = Arc::new(Group::new(fake_group.path()).unwrap());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fake_dev.path())
        .unwrap();
    let kdev = Kdev::new(file);
    let dev_fd = DevFd {
        kdev,
        _group: group,
    };
    let region = VfioRegionInfo {
        index: 0,
        size: 8,
        offset: 0,
        flags: VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        ..Default::default()
    };

    let mut buf = [0u8; 4];
    dev_fd.read_region(&region, 2, &mut buf).unwrap();
    assert_eq!(buf, [0x33, 0x44, 0x55, 0x66]);

    dev_fd.write_region(&region, 0, &[0xaa, 0xbb]).unwrap();
    dev_fd.read_region(&region, 0, &mut buf).unwrap();
    assert_eq!(buf, [0xaa, 0xbb, 0x33, 0x44]);
}
