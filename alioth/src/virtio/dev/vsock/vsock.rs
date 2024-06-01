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

mod vhost_vsock;

use bitflags::bitflags;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::impl_mmio_for_zerocopy;

pub use vhost_vsock::{VhostVsock, VhostVsockParam};

#[derive(Debug, Clone, Copy, Default, FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
pub struct VsockConfig {
    pub guest_cid: u32,
    pub guest_cid_hi: u32,
}

impl_mmio_for_zerocopy!(VsockConfig);

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VsockFeature: u64 {
        const STREAM = 1 << 0;
        const SEQPACKET = 1 << 1;
    }
}
