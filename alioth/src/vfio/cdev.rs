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
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use snafu::ResultExt;

use crate::sys::vfio::{
    VfioDeviceAttachIommufdPt, VfioDeviceBindIommufd, VfioDeviceDetachIommufdPt,
};
use crate::vfio::device::Device;
use crate::vfio::ioctls::{
    vfio_device_attach_iommufd_pt, vfio_device_bind_iommufd, vfio_device_detach_iommufd_pt,
};
use crate::vfio::iommu::Ioas;
use crate::vfio::{Result, error};

#[derive(Debug)]
pub struct Cdev {
    fd: File,
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
        Ok(Cdev { fd, ioas: None })
    }
}

impl Cdev {
    pub fn attach_iommu_ioas(&mut self, ioas: Arc<Ioas>) -> Result<()> {
        let bind = VfioDeviceBindIommufd {
            argsz: size_of::<VfioDeviceBindIommufd>() as u32,
            iommufd: ioas.iommu.fd.as_raw_fd(),
            ..Default::default()
        };
        unsafe { vfio_device_bind_iommufd(&self.fd, &bind) }?;
        let attach = VfioDeviceAttachIommufdPt {
            argsz: size_of::<VfioDeviceAttachIommufdPt>() as u32,
            pt_id: ioas.id,
            ..Default::default()
        };
        unsafe { vfio_device_attach_iommufd_pt(&self.fd, &attach) }?;
        self.ioas.replace(ioas);
        Ok(())
    }

    pub fn detach_iommu_ioas(&mut self) -> Result<()> {
        if self.ioas.is_none() {
            return Ok(());
        };
        let detach = VfioDeviceDetachIommufdPt {
            argsz: size_of::<VfioDeviceDetachIommufdPt>() as u32,
            flags: 0,
        };
        unsafe { vfio_device_detach_iommufd_pt(&self.fd, &detach) }?;
        self.ioas = None;
        Ok(())
    }
}

impl Device for Cdev {
    fn fd(&self) -> &File {
        &self.fd
    }
}

impl Drop for Cdev {
    fn drop(&mut self) {
        if let Err(e) = self.detach_iommu_ioas() {
            log::error!("Cdev-{}: detaching ioas: {e:?}", self.fd.as_raw_fd())
        }
    }
}
