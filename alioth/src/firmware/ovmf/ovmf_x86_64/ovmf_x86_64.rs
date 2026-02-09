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

pub mod sev;

use zerocopy::FromBytes;

pub const GUID_SIZE: usize = 16;

pub const OFFSET_R_LENGTH_GUID_TABLE: usize = 50;
pub const GUID_TABLE_FOOTER: [u8; GUID_SIZE] = [
    0xDE, 0x82, 0xB5, 0x96, 0xB2, 0x1F, 0xF7, 0x45, 0xBA, 0xEA, 0xA3, 0x66, 0xC5, 0x5A, 0x08, 0x2D,
];

pub fn parse_data<'a>(blob: &'a [u8], target: &[u8; GUID_SIZE]) -> Option<&'a [u8]> {
    let offset_table_len = blob.len().checked_sub(OFFSET_R_LENGTH_GUID_TABLE)?;
    // `table_len` is the total length of the table, including the footer
    let (table_len, guid) = u16::read_from_prefix(&blob[offset_table_len..]).ok()?;
    if !guid.starts_with(&GUID_TABLE_FOOTER) {
        return None;
    }
    let body_len = (table_len as usize).checked_sub(size_of::<u16>() + GUID_SIZE)?;
    let offset_table_start = offset_table_len.checked_sub(body_len)?;
    // Every entry in the table has the following structure:
    // - Actual entry content
    // - size_of::<u16>() bytes for the length of the entry
    // - GUID_SIZE bytes for the GUID
    let mut offset_entry_len = offset_table_len.checked_sub(GUID_SIZE + size_of::<u16>())?;
    while offset_entry_len >= offset_table_start {
        let (len_entry, guid) = u16::read_from_prefix(&blob[offset_entry_len..]).ok()?;
        if guid.starts_with(target) {
            let len_content = (len_entry as usize).checked_sub(GUID_SIZE + size_of::<u16>())?;
            let offset_content = offset_entry_len.checked_sub(len_content)?;
            return Some(&blob[offset_content..offset_entry_len]);
        }
        offset_entry_len = offset_entry_len.checked_sub(len_entry as usize)?;
    }
    None
}
