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

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use snafu::ResultExt;

use crate::errors::BoxTrace;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{self, LayoutChanged};
use crate::sys::vfio::{
    VfioDmaMapFlag, VfioDmaUnmapFlag, VfioIommu, VfioIommuType1DmaMap, VfioIommuType1DmaUnmap,
};
use crate::vfio::ioctls::{vfio_iommu_map_dma, vfio_iommu_unmap_dma, vfio_set_iommu};
use crate::vfio::{Result, error};

#[derive(Debug)]
pub struct Container {
    fd: File,
    iommu: Mutex<Option<VfioIommu>>,
}

impl Container {
    pub fn new(vfio_dev: impl AsRef<Path>) -> Result<Self> {
        let fd = File::open(&vfio_dev).context(error::AccessDevice {
            path: vfio_dev.as_ref(),
        })?;
        Ok(Container {
            fd,
            iommu: Mutex::new(None),
        })
    }

    pub fn fd(&self) -> &File {
        &self.fd
    }

    pub fn set_iommu(&self, iommu: VfioIommu) -> Result<()> {
        let current = &mut *self.iommu.lock();
        if let Some(current_iommu) = current {
            if *current_iommu == iommu {
                Ok(())
            } else {
                error::SetContainerIommu {
                    current: *current_iommu,
                    new: iommu,
                }
                .fail()
            }
        } else {
            unsafe { vfio_set_iommu(&self.fd, iommu) }?;
            current.replace(iommu);
            Ok(())
        }
    }

    fn map(&self, hva: usize, iova: u64, size: u64) -> Result<()> {
        let flags = VfioDmaMapFlag::READ | VfioDmaMapFlag::WRITE;
        let dma_map = VfioIommuType1DmaMap {
            argsz: size_of::<VfioIommuType1DmaMap>() as u32,
            flags,
            vaddr: hva as u64,
            iova,
            size,
        };
        unsafe { vfio_iommu_map_dma(&self.fd, &dma_map) }?;
        log::debug!(
            "container-{}: mapped: {iova:#018x} -> {hva:#018x}, size = {size:#x}",
            self.fd.as_raw_fd()
        );
        Ok(())
    }

    fn unmap(&self, iova: u64, size: u64) -> Result<()> {
        let mut dma_unmap = VfioIommuType1DmaUnmap {
            argsz: size_of::<VfioIommuType1DmaUnmap>() as u32,
            flags: VfioDmaUnmapFlag::empty(),
            iova,
            size,
        };
        unsafe { vfio_iommu_unmap_dma(&self.fd, &mut dma_unmap) }?;
        log::debug!(
            "container-{}: unmapped: {iova:#018x}, size = {size:#x}",
            self.fd.as_raw_fd(),
        );
        Ok(())
    }
}

#[derive(Debug)]
pub struct UpdateContainerMapping {
    pub container: Arc<Container>,
}

impl LayoutChanged for UpdateContainerMapping {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let ret = self.container.map(pages.addr(), gpa, pages.size());
        ret.box_trace(mem::error::ChangeLayout)?;
        Ok(())
    }

    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let ret = self.container.unmap(gpa, pages.size());
        ret.box_trace(mem::error::ChangeLayout)?;
        Ok(())
    }
}
