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

use assert_matches::assert_matches;

use crate::sys::vfio::{VfioRegionInfo, VfioRegionInfoFlag};
use crate::vfio::cdev::Cdev;
use crate::vfio::device::Device;

#[test]
fn test_cdev_detach_when_not_attached() {
    // Cdev detach when not attached returns Ok(())
    let tmp_cdev = tempfile::NamedTempFile::new().unwrap();
    let mut cdev = Cdev::new(tmp_cdev.path()).unwrap();
    assert_matches!(cdev.detach_iommu_ioas(), Ok(()));
}

#[test]
fn test_cdev_device_impl() {
    let mut fake = tempfile::NamedTempFile::new().unwrap();
    fake.write_all(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa])
        .unwrap();

    let cdev = Cdev::new(fake.path()).unwrap();
    let region = VfioRegionInfo {
        index: 0,
        size: 8,
        offset: 2,
        flags: VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        ..Default::default()
    };

    let mut buf = [0u8; 4];
    cdev.read_region(&region, 2, &mut buf).unwrap();
    assert_eq!(buf, [0x55, 0x66, 0x77, 0x88]);

    cdev.write_region(&region, 0, &[0xaa, 0xbb]).unwrap();
    cdev.read_region(&region, 0, &mut buf).unwrap();
    assert_eq!(buf, [0xaa, 0xbb, 0x55, 0x66]);
}
