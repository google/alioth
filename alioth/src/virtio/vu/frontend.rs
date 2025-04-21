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

use std::sync::Arc;

use bitflags::bitflags;

use crate::errors::BoxTrace;
use crate::mem;
use crate::mem::LayoutChanged;
use crate::mem::mapped::ArcMemPages;
use crate::virtio::vu::bindings::{MemoryRegion, MemorySingleRegion};
use crate::virtio::vu::conn::VuSession;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VuDevFeature: u64 { }
}

#[derive(Debug)]
pub struct UpdateVuMem {
    pub name: Arc<str>,
    pub session: Arc<VuSession>,
}

impl LayoutChanged for UpdateVuMem {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((fd, offset)) = pages.fd() else {
            return Ok(());
        };
        let region = MemorySingleRegion {
            _padding: 0,
            region: MemoryRegion {
                gpa: gpa as _,
                size: pages.size() as _,
                hva: pages.addr() as _,
                mmap_offset: offset,
            },
        };
        let ret = self.session.add_mem_region(&region, fd);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!("{}: add memory region: {:x?}", self.name, region.region);
        Ok(())
    }

    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((_, offset)) = pages.fd() else {
            return Ok(());
        };
        let region = MemorySingleRegion {
            _padding: 0,
            region: MemoryRegion {
                gpa: gpa as _,
                size: pages.size() as _,
                hva: pages.addr() as _,
                mmap_offset: offset,
            },
        };
        let ret = self.session.remove_mem_region(&region);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!("{}: remove memory region: {:x?}", self.name, region.region);
        Ok(())
    }
}
