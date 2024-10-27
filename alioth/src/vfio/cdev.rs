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
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

use snafu::ResultExt;

use crate::mem;
use crate::vfio::bindings::{
    VfioDeviceAttachIommufdPt, VfioDeviceBindIommufd, VfioDeviceDetachIommufdPt, VfioDeviceInfo,
    VfioIrqInfo, VfioIrqSet, VfioRegionInfo,
};
use crate::vfio::ioctls::{
    vfio_device_attach_iommufd_pt, vfio_device_bind_iommufd, vfio_device_detach_iommufd_pt,
    vfio_device_get_info, vfio_device_get_irq_info, vfio_device_get_region_info, vfio_device_reset,
    vfio_device_set_irqs,
};
use crate::vfio::iommu::Ioas;
use crate::vfio::{error, Result};

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

    pub fn get_info(&self) -> Result<VfioDeviceInfo> {
        let mut device_info = VfioDeviceInfo {
            argsz: size_of::<VfioDeviceInfo>() as u32,
            ..Default::default()
        };
        unsafe { vfio_device_get_info(&self.fd, &mut device_info) }?;
        Ok(device_info)
    }

    pub fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        let mut region_config = VfioRegionInfo {
            argsz: size_of::<VfioRegionInfo>() as u32,
            index,
            ..Default::default()
        };
        unsafe { vfio_device_get_region_info(&self.fd, &mut region_config) }?;
        Ok(region_config)
    }

    pub fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        let mut irq_info = VfioIrqInfo {
            argsz: size_of::<VfioIrqInfo>() as u32,
            index,
            ..Default::default()
        };
        unsafe { vfio_device_get_irq_info(&self.fd, &mut irq_info) }?;
        Ok(irq_info)
    }

    pub fn set_irqs<const N: usize>(&self, irq: &VfioIrqSet<N>) -> Result<()> {
        unsafe { vfio_device_set_irqs(&self.fd, irq) }?;
        Ok(())
    }

    pub fn fd(&self) -> &File {
        &self.fd
    }

    pub fn reset(&self) -> Result<()> {
        unsafe { vfio_device_reset(&self.fd) }?;
        Ok(())
    }

    pub fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let mut bytes = [0u8; 8];
        let Some(buf) = bytes.get_mut(0..size as usize) else {
            log::error!(
                "Cdev-{}: invalid read: offset = {offset:#x}, size = {size:#x}",
                self.fd.as_raw_fd()
            );
            return Ok(0);
        };
        self.fd.read_exact_at(buf, offset)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    pub fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<()> {
        let bytes = val.to_ne_bytes();
        let Some(buf) = bytes.get(..size as usize) else {
            log::error!(
                "Cdev-{}: invalid write: offset = {offset:#x}, size = {size:#x}, val = {val:#x}",
                self.fd.as_raw_fd()
            );
            return Ok(());
        };
        self.fd.write_all_at(buf, offset)?;
        Ok(())
    }
}

impl Drop for Cdev {
    fn drop(&mut self) {
        if let Err(e) = self.detach_iommu_ioas() {
            log::error!("Cdev-{}: detaching ioas: {e:?}", self.fd.as_raw_fd())
        }
    }
}
