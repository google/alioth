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

use std::fs::{self, File};
use std::io::{self, Read};

use assert_matches::assert_matches;
use rstest::rstest;
use tempfile::TempDir;

use crate::device::fw_cfg::FwCfgContent;

fn create_file_with_content(content: &str) -> io::Result<File> {
    let tmp_dir = TempDir::new()?;

    let file_path = tmp_dir.path().join("test_file");
    fs::write(&file_path, content)?;

    File::open(&file_path)
}

#[rstest]
#[case(FwCfgContent::Bytes(vec![0x01, 0x02, 0x03]), 3)]
#[case(FwCfgContent::default(), 0)]
#[case(FwCfgContent::Slice(b"abcd"), 4)]
#[case(FwCfgContent::Lu32(1234.into()), 4)]
fn test_fw_cfg_content_size(#[case] content: FwCfgContent, #[case] size: u32) {
    assert_matches!(content.size(), Ok(v) if v == size);
}

#[test]
fn test_fw_cfg_content_file_size() {
    let file = create_file_with_content("test content").unwrap();

    let fw_cfg_content = FwCfgContent::File(1, file);
    assert_matches!(fw_cfg_content.size(), Ok(11));
}

#[rstest]
#[case(FwCfgContent::Bytes(vec![0x01, 0x02, 0x03]), 2, Some(0x03))]
#[case(FwCfgContent::default(), 1, None)]
#[case(FwCfgContent::Slice(b"abcd"), 0, Some(b'a'))]
#[case(FwCfgContent::Lu32(0xab_cd_u32.into()), 0, Some(0xcd))]
fn test_fw_cfg_content_read(
    #[case] content: FwCfgContent,
    #[case] offset: u32,
    #[case] byte: Option<u8>,
) {
    assert_eq!(content.read(offset), byte);
}

#[test]
fn test_fw_cfg_content_file_read() {
    let file = create_file_with_content("test content").unwrap();

    let fw_cfg_content = FwCfgContent::File(1, file);
    assert_matches!(fw_cfg_content.read(1), Some(b's'));

    assert_matches!(fw_cfg_content.read(20), None);
}

#[rstest]
#[case(FwCfgContent::Bytes(vec![0x01, 0x02, 0x03]), 2, &[0x03])]
#[case(FwCfgContent::Bytes(vec![0x01, 0x02, 0x03]), 4, &[])]
#[case(FwCfgContent::default(), 1, &[])]
#[case(FwCfgContent::Slice(b"abcd"), 0, &[b'a', b'b', b'c', b'd'])]
#[case(FwCfgContent::Lu32(0xab_cd_u32.into()), 0, &[0xcd, 0xab, 0x00, 0x00])]
#[case(FwCfgContent::Lu32(0xab_cd_u32.into()), 5, &[])]
fn test_fw_cfg_content_access(
    #[case] content: FwCfgContent,
    #[case] offset: u32,
    #[case] result: &[u8],
) {
    let mut buf = vec![0u8; 16];
    let _ = content.access(offset).read(&mut buf);
    assert_eq!(&buf[..result.len()], result);
}

#[test]
fn test_fw_cfg_content_file_access() {
    let file = create_file_with_content("test ").unwrap();

    let fw_cfg_content = FwCfgContent::File(1, file);

    let mut buf = vec![0u8; 16];
    let _ = fw_cfg_content.access(1).read(&mut buf);
    assert_eq!(&buf[..4], [b's', b't', b' ', 0]);

    let mut buf = vec![0u8; 16];
    let _ = fw_cfg_content.access(120).read(&mut buf);
    assert_eq!(&buf[..4], [0, 0, 0, 0]);
}
