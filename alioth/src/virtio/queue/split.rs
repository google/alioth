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

use std::sync::atomic::Ordering;
use std::sync::Arc;

use bitflags::bitflags;
use macros::Layout;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::mem::mapped::RamBus;
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::{Result, VirtioFeature};

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

#[derive(Debug, Clone, Default)]
struct Register {
    pub size: u16,
    pub _desc: u64,
    pub _avail: u64,
    pub _used: u64,
    pub _feature: VirtioFeature,
}

#[derive(Debug)]
pub struct SplitQueue {
    pub memory: Arc<RamBus>,
    register: Register,
}

impl SplitQueue {
    pub fn new(reg: &Queue, memory: Arc<RamBus>, feature: u64) -> Self {
        let register = if reg.enabled.load(Ordering::Acquire) {
            Register {
                size: reg.size.load(Ordering::Acquire),
                _desc: reg.desc.load(Ordering::Acquire),
                _avail: reg.driver.load(Ordering::Acquire),
                _used: reg.device.load(Ordering::Acquire),
                _feature: VirtioFeature::from_bits_retain(feature),
            }
        } else {
            Register::default()
        };
        Self { memory, register }
    }
}

impl VirtQueue for SplitQueue {
    fn size(&self) -> u16 {
        self.register.size
    }

    fn enable_notification(&self, _val: bool) -> Result<()> {
        todo!()
    }

    fn interrupt_enabled(&self) -> Result<bool> {
        todo!()
    }
}
