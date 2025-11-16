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

use rstest::rstest;

use crate::firmware::dt::PropVal;
use crate::firmware::dt::dtb::StringBlock;

#[test]
fn test_string_block() {
    let mut block = StringBlock::new();
    assert_eq!(block.add("name1"), 0);
    assert_eq!(block.add("name2"), 6);
    assert_eq!(block.add("name1"), 0);
    assert_eq!(block.add("name3"), 12);
    let mut blob = vec![];
    block.write_as_blob(&mut blob);
    assert_eq!(blob, b"name1\0name2\0name3\0\0\0");
}

#[rstest]
#[case(PropVal::Empty, &[])]
#[case(PropVal::PHandle(1), &[0, 0, 0, 1])]
#[case(PropVal::U32(0xabcd_1234), &[0xab, 0xcd, 0x12, 0x34])]
#[case(PropVal::U64(0x4321_8765_09ab_fedc), &[0x43, 0x21, 0x87, 0x65, 0x09, 0xab, 0xfe, 0xdc])]
#[case(PropVal::Str("quantum"), b"quantum\0")]
#[case(PropVal::String("hello world!".to_owned()), b"hello world!\0\0\0\0")]
#[case(PropVal::StringList(vec!["hello".to_owned(), "world".to_owned()]), b"hello\0world\0")]
#[case(PropVal::U32List(vec![1,2,3]), &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3])]
#[case(PropVal::U64List(vec![1,2]), &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2])]
#[case(PropVal::Bytes(c"hello world!".to_bytes_with_nul().to_owned()), b"hello world!\0\0\0\0")]
fn test_prop_val_write_as_blob(#[case] prop: PropVal, #[case] expected: &[u8]) {
    let mut blob = vec![];
    prop.write_as_blob(&mut blob);
    assert_eq!(blob, expected);
    assert_eq!(blob.len() & 0b11, 0);
}
