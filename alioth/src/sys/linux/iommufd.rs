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

use crate::ioctl_write_ptr;
use crate::sys::ioctl::ioctl_io;
use crate::sys::vfio::IommuIoasMapFlag;

pub const IOMMUFD_TYPE: u8 = b';';

#[repr(C)]
pub struct IommuIoasMapFile {
    pub size: u32,
    pub flags: IommuIoasMapFlag,
    pub ioas_id: u32,
    pub fd: i32,
    pub start: u64,
    pub length: u64,
    pub iova: u64,
}

ioctl_write_ptr! {
    iommu_ioas_map_file,
    ioctl_io(IOMMUFD_TYPE, 0x8f),
    IommuIoasMapFile
}
