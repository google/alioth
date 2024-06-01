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

use crate::{ioctl_none, ioctl_read, ioctl_write_buf, ioctl_write_ptr};

use crate::virtio::vhost::bindings::{
    MemoryMultipleRegion, VirtqAddr, VirtqFile, VirtqState, VHOST_VIRTIO,
};

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
