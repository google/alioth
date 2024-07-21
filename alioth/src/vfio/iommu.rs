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

use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use snafu::ResultExt;

use crate::vfio::bindings::{
    IommuDestroy, IommuIoasAlloc, IommuIoasMap, IommuIoasMapFlag, IommuIoasUnmap,
};
use crate::vfio::ioctls::{iommu_destroy, iommu_ioas_alloc, iommu_ioas_map, iommu_ioas_unmap};
use crate::vfio::{error, Result};

#[derive(Debug)]
pub struct Iommu {
    pub(super) fd: File,
}

impl Iommu {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .context(error::AccessDevice {
                path: path.as_ref(),
            })?;
        Ok(Iommu { fd })
    }
}

#[derive(Debug)]
pub struct Ioas<I = Arc<Iommu>>
where
    I: Deref<Target = Iommu>,
{
    pub(super) iommu: I,
    pub(super) id: u32,
}

impl<I> Drop for Ioas<I>
where
    I: Deref<Target = Iommu>,
{
    fn drop(&mut self) {
        if let Err(e) = self.reset() {
            log::error!("Removing mappings from ioas id {:#x}: {e}", self.id)
        }
        let destroy = IommuDestroy {
            size: size_of::<IommuDestroy>() as u32,
            id: self.id,
        };
        let ret = unsafe { iommu_destroy(&self.iommu.fd, &destroy) };
        if let Err(e) = ret {
            log::error!("Destroying ioas id {:#x}: {e}", self.id)
        }
    }
}

impl<I> Ioas<I>
where
    I: Deref<Target = Iommu>,
{
    pub fn alloc_on(iommu: I) -> Result<Self> {
        let mut alloc: IommuIoasAlloc = IommuIoasAlloc {
            size: size_of::<IommuIoasAlloc>() as u32,
            ..Default::default()
        };
        unsafe { iommu_ioas_alloc(&iommu.fd, &mut alloc) }?;
        Ok(Ioas {
            iommu,
            id: alloc.out_ioas_id,
        })
    }

    pub fn map(&self, user_va: usize, iova: u64, len: u64) -> Result<()> {
        let flags =
            IommuIoasMapFlag::READABLE | IommuIoasMapFlag::WRITEABLE | IommuIoasMapFlag::FIXED_IOVA;
        let ioas_map = IommuIoasMap {
            size: size_of::<IommuIoasMap>() as u32,
            flags,
            ioas_id: self.id,
            user_va: user_va as u64,
            length: len,
            iova,
            ..Default::default()
        };
        unsafe { iommu_ioas_map(&self.iommu.fd, &ioas_map) }?;
        Ok(())
    }

    pub fn unmap(&self, iova: u64, len: u64) -> Result<()> {
        let ioas_unmap = IommuIoasUnmap {
            size: size_of::<IommuIoasUnmap>() as u32,
            ioas_id: self.id,
            iova,
            length: len,
        };
        unsafe { iommu_ioas_unmap(&self.iommu.fd, &ioas_unmap) }?;
        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        self.unmap(0, u64::MAX)
    }
}
