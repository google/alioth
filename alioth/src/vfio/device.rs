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
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

use crate::mem;
use crate::sys::vfio::{
    VfioDeviceInfo, VfioIrqInfo, VfioIrqSet, VfioIrqSetData, VfioIrqSetFlag, VfioPciIrq,
    VfioRegionInfo,
};
use crate::vfio::Result;
use crate::vfio::ioctls::{
    vfio_device_get_info, vfio_device_get_irq_info, vfio_device_get_region_info, vfio_device_reset,
    vfio_device_set_irqs,
};

pub trait Device: Debug + Send + Sync + 'static {
    fn fd(&self) -> &File;

    fn get_info(&self) -> Result<VfioDeviceInfo> {
        let mut device_info = VfioDeviceInfo {
            argsz: size_of::<VfioDeviceInfo>() as u32,
            ..Default::default()
        };
        unsafe { vfio_device_get_info(self.fd(), &mut device_info) }?;
        Ok(device_info)
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        let mut region_config = VfioRegionInfo {
            argsz: size_of::<VfioRegionInfo>() as u32,
            index,
            ..Default::default()
        };
        unsafe { vfio_device_get_region_info(self.fd(), &mut region_config) }?;
        Ok(region_config)
    }

    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        let mut irq_info = VfioIrqInfo {
            argsz: size_of::<VfioIrqInfo>() as u32,
            index,
            ..Default::default()
        };
        unsafe { vfio_device_get_irq_info(self.fd(), &mut irq_info) }?;
        Ok(irq_info)
    }

    fn set_irqs<const N: usize>(&self, irq: &VfioIrqSet<N>) -> Result<()> {
        unsafe { vfio_device_set_irqs(self.fd(), irq) }?;
        Ok(())
    }

    fn disable_all_irqs(&self, index: VfioPciIrq) -> Result<()> {
        let vfio_irq_disable_all = VfioIrqSet {
            argsz: size_of::<VfioIrqSet<0>>() as u32,
            flags: VfioIrqSetFlag::DATA_NONE | VfioIrqSetFlag::ACTION_TRIGGER,
            index: index.raw(),
            start: 0,
            count: 0,
            data: VfioIrqSetData { eventfds: [] },
        };
        self.set_irqs(&vfio_irq_disable_all)
    }

    fn reset(&self) -> Result<()> {
        unsafe { vfio_device_reset(self.fd()) }?;
        Ok(())
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let mut bytes = [0u8; 8];
        let Some(buf) = bytes.get_mut(0..size as usize) else {
            log::error!(
                "vfio-{}: invalid read: offset = {offset:#x}, size = {size:#x}",
                self.fd().as_raw_fd()
            );
            return Ok(0);
        };
        self.fd().read_exact_at(buf, offset)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<()> {
        let bytes = val.to_ne_bytes();
        let Some(buf) = bytes.get(..size as usize) else {
            log::error!(
                "vfio-{}: invalid write: offset = {offset:#x}, size = {size:#x}, val = {val:#x}",
                self.fd().as_raw_fd()
            );
            return Ok(());
        };
        self.fd().write_all_at(buf, offset)?;
        Ok(())
    }
}
