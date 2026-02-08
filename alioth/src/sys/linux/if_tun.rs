// Copyright 2025 Google LLC
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

use std::ffi::{c_int, c_uint, c_ulong};

use libc::ifreq;

use crate::sys::ioctl::ioctl_iow;
use crate::{bitflags, ioctl_read, ioctl_write_ptr, ioctl_write_val};

ioctl_write_ptr!(tun_set_iff, ioctl_iow::<c_int>(b'T', 202), ifreq);

ioctl_write_val!(tun_set_offload, ioctl_iow::<c_uint>(b'T', 208), TunFeature);

ioctl_read!(tun_get_vnet_hdr_sz, b'T', 215, c_int);

ioctl_write_ptr!(tun_set_vnet_hdr_sz, b'T', 216, c_int);

bitflags! {
    pub struct TunFeature(c_ulong) {
        CSUM = 1 << 0;
        TSO4 = 1 << 1;
        TSO6 = 1 << 2;
        TSO_ECN = 1 << 3;
        UFO = 1 << 4;
        USO4 = 1 << 5;
        USO6 = 1 << 6;
    }
}
