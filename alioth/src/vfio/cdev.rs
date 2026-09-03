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

use std::fmt::Debug;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use snafu::ResultExt;

use crate::sys::vfio::{
    VfioDeviceAttachIommufdPt, VfioDeviceBindIommufd, VfioDeviceDetachIommufdPt, VfioDeviceInfo,
    VfioIrqInfo, VfioRegionInfo, vfio_device_attach_iommufd_pt, vfio_device_bind_iommufd,
    vfio_device_detach_iommufd_pt,
};
use crate::vfio::device::{Device, Kdev};
use crate::vfio::iommu::Ioas;
use crate::vfio::{Result, error};

#[derive(Debug)]
pub struct Cdev {
    kdev: Kdev,
    ioas: Option<Arc<Ioas>>,
}

impl Cdev {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .context(error::AccessDevice {
                path: path.as_ref(),
            })?;
        Ok(Cdev {
            kdev: Kdev::new(fd),
            ioas: None,
        })
    }
}

impl Cdev {
    pub fn attach_iommu_ioas(&mut self, ioas: Arc<Ioas>) -> Result<()> {
        let bind = VfioDeviceBindIommufd {
            argsz: size_of::<VfioDeviceBindIommufd>() as u32,
            iommufd: ioas.iommu.fd.as_raw_fd(),
            ..Default::default()
        };
        unsafe { vfio_device_bind_iommufd(&self.kdev, &bind) }?;
        let attach = VfioDeviceAttachIommufdPt {
            argsz: size_of::<VfioDeviceAttachIommufdPt>() as u32,
            pt_id: ioas.id,
            ..Default::default()
        };
        unsafe { vfio_device_attach_iommufd_pt(&self.kdev, &attach) }?;
        self.ioas.replace(ioas);
        Ok(())
    }

    pub fn detach_iommu_ioas(&mut self) -> Result<()> {
        if self.ioas.is_none() {
            return Ok(());
        }
        let detach = VfioDeviceDetachIommufdPt {
            argsz: size_of::<VfioDeviceDetachIommufdPt>() as u32,
            flags: 0,
        };
        unsafe { vfio_device_detach_iommufd_pt(&self.kdev, &detach) }?;
        self.ioas = None;
        Ok(())
    }
}

impl Device for Cdev {
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

impl Drop for Cdev {
    fn drop(&mut self) {
        if let Err(e) = self.detach_iommu_ioas() {
            log::error!(
                "Cdev-{}: detaching ioas: {e:?}",
                self.kdev.as_fd().as_raw_fd()
            )
        }
    }
}

#[cfg(test)]
#[path = "cdev_test.rs"]
mod tests;
