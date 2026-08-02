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

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use snafu::ResultExt;

use crate::sys::vfio::{
    VfioDeviceInfo, VfioIommu, VfioIrqInfo, VfioRegionInfo, vfio_group_get_device_fd,
    vfio_group_set_container, vfio_group_unset_container,
};
use crate::vfio::container::Container;
use crate::vfio::device::{Device, Kdev};
use crate::vfio::{Result, error};

#[derive(Debug)]
pub struct Group {
    container: Option<Arc<Container>>,
    fd: File,
}

impl Group {
    pub fn new(path: &Path) -> Result<Self> {
        let fd = File::open(path).context(error::AccessDevice { path })?;
        Ok(Group {
            fd,
            container: None,
        })
    }

    pub fn attach(&mut self, container: Arc<Container>, iommu: VfioIommu) -> Result<()> {
        unsafe { vfio_group_set_container(&self.fd, &container.fd().as_raw_fd()) }?;
        container.set_iommu(iommu)?;
        self.container.replace(container);
        Ok(())
    }

    pub fn detach(&mut self) -> Result<()> {
        if self.container.is_none() {
            return Ok(());
        }
        unsafe { vfio_group_unset_container(&self.fd) }?;
        self.container = None;
        Ok(())
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Err(e) = self.detach() {
            log::error!(
                "Group-{}: detaching from container: {e:?}",
                self.fd.as_raw_fd()
            );
        }
    }
}

#[derive(Debug)]
pub struct DevFd {
    kdev: Kdev,
    _group: Arc<Group>,
}

impl DevFd {
    pub fn new(group: Arc<Group>, id: &str) -> Result<Self> {
        let id_c = CString::new(id).unwrap();
        let fd = unsafe { vfio_group_get_device_fd(&group.fd, id_c.as_ptr()) }?;
        let file = unsafe { File::from_raw_fd(fd) };
        let kdev = Kdev::new(file);
        Ok(DevFd {
            kdev,
            _group: group,
        })
    }
}

impl Device for DevFd {
    fn get_info(&self) -> Result<VfioDeviceInfo> {
        self.kdev.get_info()
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        self.kdev.get_region_info(index)
    }

    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        self.kdev.get_irq_info(index)
    }

    fn reset(&self) -> Result<()> {
        self.kdev.reset()
    }

    fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        self.kdev.set_irq_eventfd(index, start, eventfds)
    }

    fn disable_irq(&self, index: u32) -> Result<()> {
        self.kdev.disable_irq(index)
    }

    fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.kdev.read_region(region, offset, buf)
    }

    fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        self.kdev.write_region(region, offset, buf)
    }

    fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>> {
        self.kdev.get_region_mmap_fd(index)
    }

    fn get_dma_buf_fd(&self, index: u32, offset: u64, size: usize) -> Result<OwnedFd> {
        self.kdev.get_dma_buf_fd(index, offset, size)
    }
}
