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

use std::io::Write;

use assert_matches::assert_matches;
use libc::{_SC_PAGESIZE, PROT_NONE, sysconf};
use rstest::rstest;

use crate::fuse::bindings::FuseSetupmappingFlag;
use crate::fuse::{DaxRegion, Error};
use crate::mem::mapped::ArcMemPages;

fn page_size() -> u64 {
    unsafe { sysconf(_SC_PAGESIZE) as u64 }
}

#[rstest]
#[case::first_page(0, 1, true)]
#[case::last_page(1, 1, true)]
#[case::whole_window(0, 2, true)]
#[case::after_window(2, 1, false)]
#[case::across_end(1, 2, false)]
fn dax_range(#[case] offset: u64, #[case] len: u64, #[case] valid: bool) {
    // A DAX window of 2 pages, with `len` pages at page `offset` to map.
    let page = page_size();
    let window = ArcMemPages::from_anonymous(2 * page as usize, Some(PROT_NONE), None).unwrap();
    let (offset, len) = (offset * page, len * page);

    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"alioth").unwrap();
    file.set_len(2 * page).unwrap();

    let ret = window.map(offset, &file, 0, len, FuseSetupmappingFlag::READ);
    if valid {
        assert_matches!(ret, Ok(()));
        let ptr = (window.addr() + offset as usize) as *const [u8; 6];
        assert_eq!(unsafe { ptr.read() }, *b"alioth");
        assert_matches!(window.unmap(offset, len), Ok(()));
    } else {
        assert_matches!(ret, Err(Error::InvalidDaxRange { .. }));
        assert_matches!(
            window.unmap(offset, len),
            Err(Error::InvalidDaxRange { .. })
        );
    }
}

#[test]
fn dax_range_overflow() {
    let page = page_size();
    let window = ArcMemPages::from_anonymous(page as usize, Some(PROT_NONE), None).unwrap();
    assert_matches!(
        window.unmap(u64::MAX, page),
        Err(Error::InvalidDaxRange { .. })
    );
}
