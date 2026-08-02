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

use std::collections::HashMap;
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::mem::size_of;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::Arc;

use parking_lot::RwLock;
use zerocopy::IntoBytes;

use crate::errors::BoxTrace;
use crate::mem;
use crate::mem::LayoutChanged;
use crate::mem::mapped::ArcMemPages;
use crate::sys::vfio::{VfioDeviceInfo, VfioIrqInfo, VfioIrqSetFlag, VfioRegionInfo};
use crate::vfio::Result;
use crate::vfio::device::Device;
use crate::vfio::user::bindings::{
    VfioUserDmaMap, VfioUserDmaMapFlag, VfioUserDmaUnmap, VfioUserIrqSet, VfioUserRegionAccess,
};
use crate::vfio::user::conn::VfioUserSession;

#[derive(Debug)]
pub struct VfioUserDevice {
    session: Arc<VfioUserSession>,
    region_fds: RwLock<HashMap<u32, Option<OwnedFd>>>,
}

impl VfioUserDevice {
    pub fn new(session: Arc<VfioUserSession>) -> Result<Self> {
        let dev = VfioUserDevice {
            session,
            region_fds: RwLock::new(HashMap::new()),
        };

        Ok(dev)
    }
}

impl Device for VfioUserDevice {
    fn get_info(&self) -> Result<VfioDeviceInfo> {
        let resp = self.session.get_device_info()?;
        Ok(VfioDeviceInfo {
            argsz: size_of::<VfioDeviceInfo>() as u32,
            flags: resp.flags,
            num_irqs: resp.num_irqs,
            num_regions: resp.num_regions,
            cap_offset: 0,
            pad: 0,
        })
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        let (resp, resp_fd) = self.session.get_region_info(index)?;
        let mut fds = self.region_fds.write();
        if let Some(old) = fds.insert(index, resp_fd) {
            fds.insert(index, old);
        }
        Ok(resp)
    }

    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        let resp = self.session.get_irq_info(index)?;
        Ok(resp)
    }

    fn reset(&self) -> Result<()> {
        self.session.reset()?;
        Ok(())
    }

    fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        let mut send_fds = vec![];
        let mut fd_indices = vec![];
        for fd in eventfds {
            if let Some(f) = fd {
                fd_indices.push(send_fds.len() as i32);
                send_fds.push(*f);
            } else {
                fd_indices.push(-1);
            }
        }

        let irq_set = VfioUserIrqSet {
            argsz: (size_of::<VfioUserIrqSet>() + fd_indices.as_bytes().len()) as u32,
            flags: VfioIrqSetFlag::DATA_EVENTFD | VfioIrqSetFlag::ACTION_TRIGGER,
            index,
            start,
            count: eventfds.len() as u32,
        };

        self.session
            .set_irqs(&irq_set, fd_indices.as_bytes(), &send_fds)?;
        Ok(())
    }

    fn disable_irq(&self, index: u32) -> Result<()> {
        let irq_set = VfioUserIrqSet {
            argsz: size_of::<VfioUserIrqSet>() as u32,
            flags: VfioIrqSetFlag::DATA_NONE | VfioIrqSetFlag::ACTION_TRIGGER,
            index,
            start: 0,
            count: 0,
        };
        self.session.set_irqs(&irq_set, &[], &[])?;
        Ok(())
    }

    fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        let req = VfioUserRegionAccess {
            offset,
            region: region.index,
            count: buf.len() as u32,
        };
        self.session.read_region(&req, buf)?;
        Ok(())
    }

    fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        let req = VfioUserRegionAccess {
            offset,
            region: region.index,
            count: buf.len() as u32,
        };
        self.session.write_region(req, buf)?;
        Ok(())
    }

    fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>> {
        if let Some(Some(fd)) = &self.region_fds.read().get(&index) {
            Ok(Some(fd.try_clone()?))
        } else {
            Ok(None)
        }
    }

    fn get_dma_buf_fd(&self, _index: u32, _offset: u64, _size: usize) -> Result<OwnedFd> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "dma-buf is not supported in vfio-user",
        )
        .into())
    }
}

#[derive(Debug)]
pub struct UpdateVfioUserMapping {
    session: Arc<VfioUserSession>,
}

impl UpdateVfioUserMapping {
    pub fn new(session: Arc<VfioUserSession>) -> Self {
        UpdateVfioUserMapping { session }
    }
}

impl LayoutChanged for UpdateVfioUserMapping {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((fd, offset)) = pages.fd() else {
            log::warn!("No fd for pages at gpa {gpa:#x}, skipping mapping");
            return Ok(());
        };
        let map = VfioUserDmaMap {
            argsz: size_of::<VfioUserDmaMap>() as u32,
            flags: VfioUserDmaMapFlag::READ | VfioUserDmaMapFlag::WRITE,
            offset,
            addr: gpa,
            size: pages.size(),
        };
        let ret = self.session.dma_map(&map, fd);
        ret.box_trace(mem::error::ChangeLayout)?;
        Ok(())
    }

    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        if pages.fd().is_none() {
            log::warn!("No fd for pages at gpa {gpa:#x}, skipping unmapping");
            return Ok(());
        };
        let unmap = VfioUserDmaUnmap {
            argsz: size_of::<VfioUserDmaUnmap>() as u32,
            flags: 0,
            addr: gpa,
            size: pages.size(),
        };
        let ret = self.session.dma_unmap(&unmap);
        ret.box_trace(mem::error::ChangeLayout)?;
        Ok(())
    }

    fn dev_mem_added(
        &self,
        gpa: u64,
        pages: &ArcMemPages,
        _: Option<BorrowedFd>,
    ) -> mem::Result<()> {
        self.ram_added(gpa, pages)
    }

    fn dev_mem_removed(
        &self,
        gpa: u64,
        pages: &ArcMemPages,
        _: Option<BorrowedFd>,
    ) -> mem::Result<()> {
        self.ram_removed(gpa, pages)
    }
}

#[cfg(test)]
#[path = "device_test.rs"]
mod tests;
