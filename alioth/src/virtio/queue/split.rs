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
use macros::Layout;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(C, align(16))]
#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    pub flag: u16,
    pub next: u16,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DescFlag: u16 {
        const NEXT = 1;
        const WRITE = 2;
        const INDIRECT = 4;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AvailFlag: u16 {
        const NO_INTERRUPT = 1;
    }
}

#[repr(C, align(2))]
#[derive(Debug, Clone, Layout)]
pub struct AvailHeader {
    flags: u16,
    idx: u16,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UsedFlag: u16 {
        const NO_NOTIFY = 1;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Layout)]
pub struct UsedHeader {
    flags: u16,
    idx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct UsedElem {
    id: u32,
    len: u32,
}
