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

use assert_matches::assert_matches;
use zerocopy::{FromBytes, IntoBytes};

use crate::firmware::ovmf::x86_64::tdx::create_hob;
use crate::firmware::uefi::{
    HobGenericHeader, HobHandoffInfoTable, HobResourceDesc, HobResourceType, HobType,
};
use crate::mem::{MemRegionEntry, MemRegionType};

#[test]
fn test_create_hob() {
    let mut buffer = [0u64; 512];
    let buffer = buffer.as_mut_bytes();
    let hob_phys = 0x100000;
    let mut entries = [
        (
            0x0,
            MemRegionEntry {
                size: 0x40000000,
                type_: MemRegionType::Ram,
            },
        ),
        (
            0xe0000000,
            MemRegionEntry {
                size: 0x10000000,
                type_: MemRegionType::Reserved,
            },
        ),
        (
            0xfec00000,
            MemRegionEntry {
                size: 0x100,
                type_: MemRegionType::Hidden,
            },
        ),
        (
            0xffe00000,
            MemRegionEntry {
                size: 0x200000,
                type_: MemRegionType::Reserved,
            },
        ),
    ];
    let mut accepted = [(0, 0xa0000), (0x100000, 0x2000), (0x102000, 0x1000)];
    create_hob(buffer, hob_phys, &mut entries, &mut accepted).unwrap();
    let (table, remain) = HobHandoffInfoTable::ref_from_prefix(buffer).unwrap();
    assert_matches!(
        table,
        HobHandoffInfoTable {
            hdr: HobGenericHeader {
                r#type: HobType::HANDOFF,
                length: 0x38,
                ..
            },
            version: 9,
            end_of_hob_list: 0x100130,
            ..
        }
    );
    let (resources, remain) = <[HobResourceDesc]>::ref_from_prefix_with_elems(remain, 5).unwrap();
    assert_matches!(
        resources,
        [
            HobResourceDesc {
                hdr: HobGenericHeader {
                    r#type: HobType::RESOURCE_DESCRIPTOR,
                    length: 0x30,
                    ..
                },
                r#type: HobResourceType::SYSTEM_MEMORY,
                address: 0,
                len: 0xa0000,
                ..
            },
            HobResourceDesc {
                hdr: HobGenericHeader {
                    r#type: HobType::RESOURCE_DESCRIPTOR,
                    length: 0x30,
                    ..
                },
                r#type: HobResourceType::MEMORY_UNACCEPTED,
                address: 0xa0000,
                len: 0x60000,
                ..
            },
            HobResourceDesc {
                hdr: HobGenericHeader {
                    r#type: HobType::RESOURCE_DESCRIPTOR,
                    length: 0x30,
                    ..
                },
                r#type: HobResourceType::SYSTEM_MEMORY,
                address: 0x100000,
                len: 0x2000,
                ..
            },
            HobResourceDesc {
                hdr: HobGenericHeader {
                    r#type: HobType::RESOURCE_DESCRIPTOR,
                    length: 0x30,
                    ..
                },
                r#type: HobResourceType::SYSTEM_MEMORY,
                address: 0x102000,
                len: 0x1000,
                ..
            },
            HobResourceDesc {
                hdr: HobGenericHeader {
                    r#type: HobType::RESOURCE_DESCRIPTOR,
                    length: 0x30,
                    ..
                },
                r#type: HobResourceType::MEMORY_UNACCEPTED,
                address: 0x103000,
                len: 0x3fefd000,
                ..
            },
        ]
    );
    let (end, _) = HobGenericHeader::ref_from_prefix(remain).unwrap();
    assert_matches!(
        end,
        HobGenericHeader {
            r#type: HobType::END_OF_HOB_LIST,
            length: 0x8,
            ..
        }
    );
}
