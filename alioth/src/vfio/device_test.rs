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
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_matches::assert_matches;
use parking_lot::{Mutex, RwLock};

use crate::sys::vfio::{
    VfioDeviceInfo, VfioDeviceInfoFlag, VfioIrqInfo, VfioPciRegion, VfioRegionInfo,
    VfioRegionInfoFlag,
};
use crate::vfio::Result;
use crate::vfio::device::Device;

pub type RegionMap = RwLock<HashMap<u32, (VfioRegionInfo, Vec<u8>)>>;
pub type IrqMap = RwLock<HashMap<u32, VfioIrqInfo>>;
pub type MmapFdMap = RwLock<HashMap<u32, OwnedFd>>;
pub type IrqEventFdList = Mutex<Vec<(u32, u32, Vec<Option<RawFd>>)>>;

#[derive(Debug)]
pub struct MockVfioDevice {
    pub info: VfioDeviceInfo,
    pub regions: RegionMap,
    pub irqs: IrqMap,
    pub mmap_fds: MmapFdMap,
    pub resets: AtomicUsize,
    pub irq_eventfds: IrqEventFdList,
    pub disabled_irqs: Mutex<Vec<u32>>,
}

impl Default for MockVfioDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl MockVfioDevice {
    pub fn new() -> Self {
        let dev = Self {
            info: VfioDeviceInfo {
                argsz: std::mem::size_of::<VfioDeviceInfo>() as u32,
                flags: VfioDeviceInfoFlag::RESET,
                ..Default::default()
            },
            regions: RwLock::new(HashMap::new()),
            irqs: RwLock::new(HashMap::new()),
            mmap_fds: RwLock::new(HashMap::new()),
            resets: AtomicUsize::new(0),
            irq_eventfds: Mutex::new(Vec::new()),
            disabled_irqs: Mutex::new(Vec::new()),
        };
        for index in 0..=5 {
            dev.add_bar(index, 0, VfioRegionInfoFlag::empty(), 0);
        }
        dev
    }

    pub fn add_region(
        &self,
        index: u32,
        size: u64,
        flags: VfioRegionInfoFlag,
        offset: u64,
        data: Vec<u8>,
    ) -> VfioRegionInfo {
        let info = VfioRegionInfo {
            argsz: std::mem::size_of::<VfioRegionInfo>() as u32,
            flags,
            index,
            cap_offset: 0,
            size,
            offset,
        };
        self.regions.write().insert(index, (info.clone(), data));
        info
    }

    pub fn add_bar(
        &self,
        index: u32,
        size: u64,
        flags: VfioRegionInfoFlag,
        offset: u64,
    ) -> VfioRegionInfo {
        self.add_region(index, size, flags, offset, vec![0u8; size as usize])
    }

    pub fn add_config(&self, config: Vec<u8>) -> VfioRegionInfo {
        self.add_region(
            VfioPciRegion::CONFIG.raw(),
            config.len() as u64,
            VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
            0,
            config,
        )
    }
}

impl Device for MockVfioDevice {
    fn get_info(&self) -> Result<VfioDeviceInfo> {
        Ok(self.info.clone())
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        let regions = self.regions.read();
        let (info, _) = regions
            .get(&index)
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?;
        Ok(info.clone())
    }

    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        let irqs = self.irqs.read();
        let info = irqs
            .get(&index)
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?;
        Ok(info.clone())
    }

    fn reset(&self) -> Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        let raw_fds = eventfds
            .iter()
            .map(|fd| fd.as_ref().map(|f| f.as_raw_fd()))
            .collect();
        self.irq_eventfds.lock().push((index, start, raw_fds));
        Ok(())
    }

    fn disable_irq(&self, index: u32) -> Result<()> {
        self.disabled_irqs.lock().push(index);
        Ok(())
    }

    fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        let regions = self.regions.read();
        let (_, data) = regions
            .get(&region.index)
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?;
        let offset = offset as usize;
        let end = offset + buf.len();
        if end > data.len() {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
        }
        buf.copy_from_slice(&data[offset..end]);
        Ok(())
    }

    fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        let mut regions = self.regions.write();
        let (_, data) = regions
            .get_mut(&region.index)
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?;
        let offset = offset as usize;
        let end = offset + buf.len();
        if end > data.len() {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
        }
        data[offset..end].copy_from_slice(buf);
        Ok(())
    }

    fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>> {
        let mmap_fds = self.mmap_fds.read();
        if let Some(fd) = mmap_fds.get(&index) {
            let cloned = fd.try_clone()?;
            Ok(Some(cloned))
        } else {
            Ok(None)
        }
    }

    fn get_dma_buf_fd(&self, _index: u32, _offset: u64, _size: usize) -> Result<OwnedFd> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
    }
}

impl Device for Arc<MockVfioDevice> {
    fn get_info(&self) -> Result<VfioDeviceInfo> {
        (**self).get_info()
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        (**self).get_region_info(index)
    }

    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        (**self).get_irq_info(index)
    }

    fn reset(&self) -> Result<()> {
        (**self).reset()
    }

    fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        (**self).set_irq_eventfd(index, start, eventfds)
    }

    fn disable_irq(&self, index: u32) -> Result<()> {
        (**self).disable_irq(index)
    }

    fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_region(region, offset, buf)
    }

    fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        (**self).write_region(region, offset, buf)
    }

    fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>> {
        (**self).get_region_mmap_fd(index)
    }

    fn get_dma_buf_fd(&self, index: u32, offset: u64, size: usize) -> Result<OwnedFd> {
        (**self).get_dma_buf_fd(index, offset, size)
    }
}

#[test]
fn test_device_read_write_helpers() {
    let dev = MockVfioDevice::new();
    let region = dev.add_bar(
        0,
        64,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0,
    );

    // 1-byte read/write
    assert_matches!(dev.write(&region, 0, 1, 0xab), Ok(()));
    assert_matches!(dev.read(&region, 0, 1), Ok(0xab));

    // 2-byte read/write
    assert_matches!(dev.write(&region, 2, 2, 0x1234), Ok(()));
    assert_matches!(dev.read(&region, 2, 2), Ok(0x1234));

    // 4-byte read/write
    assert_matches!(dev.write(&region, 4, 4, 0xdead_beef), Ok(()));
    assert_matches!(dev.read(&region, 4, 4), Ok(0xdead_beef));

    // 8-byte read/write
    assert_matches!(dev.write(&region, 8, 8, 0x0123_4567_89ab_cdef), Ok(()));
    assert_matches!(dev.read(&region, 8, 8), Ok(0x0123_4567_89ab_cdef));

    // Invalid size (> 8 bytes)
    assert_matches!(dev.write(&region, 0, 16, 0), Ok(()));
    assert_matches!(dev.read(&region, 0, 16), Ok(0));

    // Read/write out of bounds
    assert_matches!(dev.write(&region, 64, 1, 0xab), Err(_));
    assert_matches!(dev.read(&region, 64, 1), Err(_));
}
