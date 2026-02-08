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

use alioth_macros::Layout;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::utils::endian::{Bu32, Bu64};
use crate::{bitflags, consts};

#[repr(C)]
#[derive(Debug, Clone, Layout, KnownLayout, Immutable, FromBytes, IntoBytes)]
/// Qcow2 Header
///
/// [Specification](https://qemu-project.gitlab.io/qemu/interop/qcow2.html#header)
pub struct Qcow2Hdr {
    pub magic: [u8; 4],
    pub version: Bu32,
    pub backing_file_offset: Bu64,
    pub backing_file_size: Bu32,
    pub cluster_bits: Bu32,
    pub size: Bu64,
    pub crypt_method: Bu32,
    pub l1_size: Bu32,
    pub l1_table_offset: Bu64,
    pub refcount_table_offset: Bu64,
    pub refcount_table_clusters: Bu32,
    pub nb_snapshots: Bu32,
    pub snapshots_offset: Bu64,
    pub incompatible_features: Bu64,
    pub compatible_features: Bu64,
    pub autoclear_features: Bu64,
    pub refcount_order: Bu32,
    pub header_length: Bu32,
    pub compression_type: Qcow2Compression,
    pub padding: [u8; 7],
}

/// Qcow2 Magic Number "QFI\xfb"
pub const QCOW2_MAGIC: [u8; 4] = *b"QFI\xfb";

bitflags! {
    pub struct Qcow2IncompatibleFeatures(u64) {
        DIRTY = 1 << 0;
        CORRUPT = 1 << 1;
        EXTERNAL_DATA = 1 << 2;
        COMPRESSION = 1 << 3;
        EXTERNAL_L2 = 1 << 4;
    }
}

bitflags! {
    pub struct Qcow2CompatibleFeatures(u64) {
        LAZY_REFCOUNTS = 1 << 0;
    }
}

consts! {
    #[derive(Default, Immutable, KnownLayout, FromBytes, IntoBytes)]
    pub struct Qcow2Compression(u8) {
        DEFLATE = 0;
        ZSTD = 1;
    }
}

bitfield! {
    /// QCOW2 L1 Table Entry
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash, KnownLayout, Immutable, FromBytes, IntoBytes)]
    #[repr(transparent)]
    pub struct Qcow2L1(u64);
    impl Debug;
    pub rc1, _: 63;
    pub offset, _: 55, 9;
}

impl Qcow2L1 {
    pub fn l2_offset(&self) -> u64 {
        self.0 & 0xff_ffff_ffff_ff00
    }
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash, KnownLayout, Immutable, FromBytes, IntoBytes)]
    #[repr(transparent)]
    pub struct Qcow2L2(u64);
    impl Debug;
    pub desc, _: 61, 0;
    pub compressed, _: 62;
    pub rc1, _: 63;
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash, KnownLayout, Immutable, FromBytes, IntoBytes)]
    #[repr(transparent)]
    pub struct Qcow2StdDesc(u64);
    impl Debug;
    pub offset, _: 55, 9;
    pub zero, _: 0;
}

impl Qcow2StdDesc {
    pub fn cluster_offset(&self) -> u64 {
        self.0 & 0xff_ffff_ffff_ff00
    }
}

pub const QCOW2_CMPR_SECTOR_SIZE: u64 = 512;

#[derive(Debug)]
pub struct Qcow2CmprDesc(pub u64);

impl Qcow2CmprDesc {
    pub fn offset_size(&self, cluster_bits: u32) -> (u64, u64) {
        let size_bits = cluster_bits - 8;
        let offset_bits = 62 - size_bits;
        let offset = self.0 & ((1 << offset_bits) - 1);
        let sectors = (self.0 >> offset_bits) & ((1 << size_bits) - 1);
        let size = (1 + sectors) * QCOW2_CMPR_SECTOR_SIZE - (offset & (QCOW2_CMPR_SECTOR_SIZE - 1));
        (offset, size)
    }
}

#[cfg(test)]
#[path = "qcow2_test.rs"]
mod tests;
