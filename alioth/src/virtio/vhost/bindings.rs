// Copyright 2024 Google LLC
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

use bitflags::bitflags;

pub const VHOST_VIRTIO: u8 = 0xAF;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryRegion {
    pub gpa: u64,
    pub size: u64,
    pub hva: u64,
    pub _padding: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct MemoryMultipleRegion<const N: usize> {
    pub num: u32,
    pub _padding: u32,
    pub regions: [MemoryRegion; N],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VirtqState {
    pub index: u32,
    pub val: u32,
}

pub const VHOST_FILE_UNBIND: i32 = -1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VirtqFile {
    pub index: u32,
    pub fd: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VirtqAddr {
    pub index: u32,
    pub flags: u32,
    pub desc_hva: u64,
    pub used_hva: u64,
    pub avail_hva: u64,
    pub log_guest_addr: u64,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct VhostFeature: u64 {
        const IOTLB_MSG_V2 = 0x1;
        const IOTLB_BATCH = 0x2;
    }
}
