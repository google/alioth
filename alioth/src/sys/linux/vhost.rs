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

use crate::{ioctl_none, ioctl_read, ioctl_write_buf, ioctl_write_ptr};

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

ioctl_read!(vhost_get_features, VHOST_VIRTIO, 0x00, u64);
ioctl_write_ptr!(vhost_set_features, VHOST_VIRTIO, 0x00, u64);
ioctl_none!(vhost_set_owner, VHOST_VIRTIO, 0x01, 0);

ioctl_write_buf!(
    vhost_set_mem_table,
    VHOST_VIRTIO,
    0x03,
    MemoryMultipleRegion
);

ioctl_write_ptr!(vhost_set_virtq_num, VHOST_VIRTIO, 0x10, VirtqState);
ioctl_write_ptr!(vhost_set_virtq_addr, VHOST_VIRTIO, 0x11, VirtqAddr);
ioctl_write_ptr!(vhost_set_virtq_base, VHOST_VIRTIO, 0x12, VirtqState);

ioctl_write_ptr!(vhost_set_virtq_kick, VHOST_VIRTIO, 0x20, VirtqFile);
ioctl_write_ptr!(vhost_set_virtq_call, VHOST_VIRTIO, 0x21, VirtqFile);
ioctl_write_ptr!(vhost_set_virtq_err, VHOST_VIRTIO, 0x22, VirtqFile);

ioctl_write_ptr!(vhost_set_backend_features, VHOST_VIRTIO, 0x25, u64);
ioctl_read!(vhost_get_backend_features, VHOST_VIRTIO, 0x26, u64);

ioctl_write_ptr!(vhost_vsock_set_guest_cid, VHOST_VIRTIO, 0x60, u64);
ioctl_write_ptr!(vhost_vsock_set_running, VHOST_VIRTIO, 0x61, i32);
