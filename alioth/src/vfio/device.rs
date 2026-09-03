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
use std::fs::File;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;

use crate::errors::BoxTrace;
use crate::mem;
use crate::sys::vfio::{
    DeviceFeature, VfioDeviceFeature, VfioDeviceFeatureDmaBuf, VfioDeviceFeatureFlag,
    VfioDeviceInfo, VfioIrqInfo, VfioIrqSet, VfioIrqSetData, VfioIrqSetFlag, VfioRegionDmaRange,
    VfioRegionInfo, VfioRegionInfoFlag, vfio_device_feature, vfio_device_get_info,
    vfio_device_get_irq_info, vfio_device_get_region_info, vfio_device_reset, vfio_device_set_irqs,
};
use crate::vfio::Result;

pub trait Device: Debug + Send + Sync + 'static {
    fn get_info(&self) -> Result<VfioDeviceInfo>;
    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo>;
    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo>;
    fn reset(&self) -> Result<()>;

    fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()>;

    fn disable_irq(&self, index: u32) -> Result<()>;

    fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()>;

    fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>>;

    fn get_dma_buf_fd(&self, index: u32, offset: u64, size: usize) -> Result<OwnedFd>;

    // Helper methods for single-value read/write
    fn read(&self, region: &VfioRegionInfo, offset: u64, size: u8) -> mem::Result<u64> {
        let mut bytes = [0u8; 8];
        let Some(buf) = bytes.get_mut(0..size as usize) else {
            log::error!(
                "vfio: invalid read: index = {}, offset = {offset:#x}, size = {size:#x}",
                region.index
            );
            return Ok(0);
        };
        self.read_region(region, offset, buf)
            .box_trace(crate::mem::error::Mmio)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn write(&self, region: &VfioRegionInfo, offset: u64, size: u8, val: u64) -> mem::Result<()> {
        let bytes = val.to_ne_bytes();
        let Some(buf) = bytes.get(..size as usize) else {
            log::error!(
                "vfio: invalid write: index = {}, offset = {offset:#x}, size = {size:#x}, val = {val:#x}",
                region.index
            );
            return Ok(());
        };
        self.write_region(region, offset, buf)
            .box_trace(crate::mem::error::Mmio)?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Kdev {
    fd: File,
}

impl AsFd for Kdev {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Kdev {
    pub fn new(fd: File) -> Self {
        Self { fd }
    }
}

impl Kdev {
    pub fn get_info(&self) -> Result<VfioDeviceInfo> {
        let mut info = VfioDeviceInfo {
            argsz: size_of::<VfioDeviceInfo>() as u32,
            ..Default::default()
        };
        unsafe { vfio_device_get_info(&self.fd, &mut info) }?;
        Ok(info)
    }

    pub fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        let mut region = VfioRegionInfo {
            argsz: size_of::<VfioRegionInfo>() as u32,
            index,
            ..Default::default()
        };
        unsafe { vfio_device_get_region_info(&self.fd, &mut region) }?;
        Ok(region)
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

    pub fn reset(&self) -> Result<()> {
        unsafe { vfio_device_reset(&self.fd) }?;
        Ok(())
    }

    pub fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        let mut raw_fds = [-1; 2048];
        for (raw_fd, eventfd) in raw_fds.iter_mut().zip(eventfds) {
            *raw_fd = eventfd.map(|fd| fd.as_raw_fd()).unwrap_or(-1);
        }
        let irq_set = VfioIrqSet {
            argsz: (size_of::<VfioIrqSet<0>>() + eventfds.len() * size_of::<i32>()) as u32,
            flags: VfioIrqSetFlag::DATA_EVENTFD | VfioIrqSetFlag::ACTION_TRIGGER,
            index,
            start,
            count: eventfds.len() as u32,
            data: VfioIrqSetData { eventfds: raw_fds },
        };
        unsafe { vfio_device_set_irqs(&self.fd, &irq_set) }?;
        Ok(())
    }

    pub fn disable_irq(&self, index: u32) -> Result<()> {
        let irq_set = VfioIrqSet {
            argsz: size_of::<VfioIrqSet<0>>() as u32,
            flags: VfioIrqSetFlag::DATA_NONE | VfioIrqSetFlag::ACTION_TRIGGER,
            index,
            start: 0,
            count: 0,
            data: VfioIrqSetData { eventfds: [] },
        };
        unsafe { vfio_device_set_irqs(&self.fd, &irq_set) }?;
        Ok(())
    }

    pub fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.fd.read_exact_at(buf, region.offset + offset)?;
        Ok(())
    }

    pub fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        self.fd.write_all_at(buf, region.offset + offset)?;
        Ok(())
    }

    pub fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>> {
        let region_info = self.get_region_info(index)?;
        if region_info.flags.contains(VfioRegionInfoFlag::MMAP) {
            Ok(Some(self.fd.try_clone()?.into()))
        } else {
            Ok(None)
        }
    }

    pub fn get_dma_buf_fd(&self, index: u32, offset: u64, size: usize) -> Result<OwnedFd> {
        let req = VfioDeviceFeature {
            argsz: size_of::<VfioDeviceFeature<VfioDeviceFeatureDmaBuf<1>>>() as u32,
            flags: VfioDeviceFeatureFlag::new(DeviceFeature::DMA_BUF, true, false, false),
            data: VfioDeviceFeatureDmaBuf {
                region_index: index,
                open_flags: (libc::O_RDWR | libc::O_CLOEXEC) as u32,
                flags: 0,
                nr_ranges: 1,
                dma_ranges: [VfioRegionDmaRange {
                    offset,
                    length: size as u64,
                }],
            },
        };
        let fd = unsafe { vfio_device_feature(&self.fd, &req) }?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(test)]
#[path = "device_test.rs"]
pub(crate) mod tests;
