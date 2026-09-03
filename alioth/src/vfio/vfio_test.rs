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

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use assert_matches::assert_matches;
use parking_lot::Mutex;

use crate::mem::LayoutChanged;
use crate::mem::mapped::ArcMemPages;
use crate::sys::vfio::{
    VfioDeviceInfo, VfioIommu, VfioIrqInfo, VfioRegionInfo, VfioRegionInfoFlag,
};
use crate::vfio::cdev::Cdev;
use crate::vfio::container::{Container, UpdateContainerMapping};
use crate::vfio::device::{Device, VfioIoDevice};
use crate::vfio::group::Group;
use crate::vfio::iommu::{Iommu, UpdateIommuIoas};
use crate::vfio::{Error, Result, VfioCdevSpec, VfioContainerSpec, VfioGroupSpec, VfioIoasSpec};

#[derive(Debug, Default)]
struct MemoryDevice {
    data: Mutex<Vec<u8>>,
}

impl Device for MemoryDevice {
    fn get_info(&self) -> Result<VfioDeviceInfo> {
        Ok(VfioDeviceInfo::default())
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        Ok(VfioRegionInfo {
            index,
            size: self.data.lock().len() as u64,
            ..Default::default()
        })
    }

    fn get_irq_info(&self, _index: u32) -> Result<VfioIrqInfo> {
        Ok(VfioIrqInfo::default())
    }

    fn reset(&self) -> Result<()> {
        Ok(())
    }

    fn set_irq_eventfd(
        &self,
        _index: u32,
        _start: u32,
        _eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        Ok(())
    }

    fn disable_irq(&self, _index: u32) -> Result<()> {
        Ok(())
    }

    fn read_region(&self, _region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        let data = self.data.lock();
        let offset = offset as usize;
        buf.copy_from_slice(&data[offset..offset + buf.len()]);
        Ok(())
    }

    fn write_region(&self, _region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        let mut data = self.data.lock();
        let offset = offset as usize;
        data[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn get_region_mmap_fd(&self, _index: u32) -> Result<Option<OwnedFd>> {
        Ok(None)
    }

    fn get_dma_buf_fd(&self, _index: u32, _offset: u64, _size: usize) -> Result<OwnedFd> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
    }
}

#[test]
fn test_device_read_write_helpers() {
    let dev = MemoryDevice {
        data: Mutex::new(vec![0u8; 64]),
    };
    let region = VfioRegionInfo {
        index: 0,
        size: 64,
        ..Default::default()
    };

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
}

#[test]
fn test_vfio_io_device_file_access() {
    let mut tmp = tempfile::tempfile().unwrap();
    use std::io::Write;
    tmp.write_all(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        .unwrap();

    let io_dev = VfioIoDevice::new(tmp).unwrap();
    assert!(io_dev.fd().metadata().is_ok());

    let region = VfioRegionInfo {
        index: 0,
        size: 8,
        offset: 0,
        flags: VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        ..Default::default()
    };

    let mut buf = [0u8; 4];
    io_dev.read_region(&region, 2, &mut buf).unwrap();
    assert_eq!(buf, [0x33, 0x44, 0x55, 0x66]);

    io_dev.write_region(&region, 0, &[0xaa, 0xbb]).unwrap();
    io_dev.read_region(&region, 0, &mut buf).unwrap();
    assert_eq!(buf, [0xaa, 0xbb, 0x33, 0x44]);
}

#[test]
fn test_vfio_specs_deserialization() {
    // VfioCdevSpec
    let cdev_aco = "path=/dev/vfio/devices/vfio0,ioas=my_ioas";
    let cdev_spec: VfioCdevSpec = serde_aco::from_arg(cdev_aco).unwrap();
    assert_eq!(cdev_spec.path.to_str().unwrap(), "/dev/vfio/devices/vfio0");
    assert_eq!(cdev_spec.ioas.as_deref(), Some("my_ioas"));

    // VfioIoasSpec
    let ioas_aco = "name=ioas0,dev_iommu=/dev/iommu";
    let ioas_spec: VfioIoasSpec = serde_aco::from_arg(ioas_aco).unwrap();
    assert_eq!(&*ioas_spec.name, "ioas0");
    assert_eq!(ioas_spec.dev_iommu.unwrap().to_str().unwrap(), "/dev/iommu");

    // VfioGroupSpec
    let group_aco = "path=/dev/vfio/12,devices=0000:06:0d.0,container=c0";
    let group_spec: VfioGroupSpec = serde_aco::from_arg(group_aco).unwrap();
    assert_eq!(group_spec.path.to_str().unwrap(), "/dev/vfio/12");
    assert_eq!(group_spec.devices.len(), 1);
    assert_eq!(&*group_spec.devices[0], "0000:06:0d.0");
    assert_eq!(group_spec.container.as_deref(), Some("c0"));

    // VfioContainerSpec
    let container_aco = "name=c0,dev_vfio=/dev/vfio/vfio";
    let container_spec: VfioContainerSpec = serde_aco::from_arg(container_aco).unwrap();
    assert_eq!(&*container_spec.name, "c0");
    assert_eq!(
        container_spec.dev_vfio.unwrap().to_str().unwrap(),
        "/dev/vfio/vfio"
    );
}

#[test]
fn test_container_and_group_errors_and_drop() {
    // Non-existent path returns AccessDevice
    assert_matches!(
        Container::new("/nonexistent/path/vfio"),
        Err(Error::AccessDevice { .. })
    );
    assert_matches!(
        Group::new(Path::new("/nonexistent/path/group")),
        Err(Error::AccessDevice { .. })
    );
    assert_matches!(
        Cdev::new("/nonexistent/path/cdev"),
        Err(Error::AccessDevice { .. })
    );
    assert_matches!(
        Iommu::new("/nonexistent/path/iommu"),
        Err(Error::AccessDevice { .. })
    );

    // Group detach when not attached returns Ok(())
    let tmp_group = tempfile::NamedTempFile::new().unwrap();
    let mut group = Group::new(tmp_group.path()).unwrap();
    assert_matches!(group.detach(), Ok(()));

    // Cdev detach when not attached returns Ok(())
    let tmp_cdev = tempfile::NamedTempFile::new().unwrap();
    let mut cdev = Cdev::new(tmp_cdev.path()).unwrap();
    assert_matches!(cdev.detach_iommu_ioas(), Ok(()));
}

#[test]
fn test_container_set_iommu_mismatch() {
    let tmp_file = tempfile::NamedTempFile::new().unwrap();
    let container = Container::new(tmp_file.path()).unwrap();
    // Simulate container already having TYPE1
    *container.iommu.lock() = Some(VfioIommu::TYPE1);

    // Setting same IOMMU returns Ok(())
    assert_matches!(container.set_iommu(VfioIommu::TYPE1), Ok(()));

    // Setting different IOMMU returns SetContainerIommu error
    assert_matches!(
        container.set_iommu(VfioIommu::TYPE1_V2),
        Err(Error::SetContainerIommu {
            current: VfioIommu::TYPE1,
            new: VfioIommu::TYPE1_V2,
            ..
        })
    );
}

#[test]
fn test_layout_changed_callbacks() {
    let arc_anon = ArcMemPages::from_anonymous(0x2000, None, None).unwrap();

    // UpdateContainerMapping dev_mem callbacks without real vfio fd return ioctl error
    let container =
        Arc::new(Container::new(tempfile::NamedTempFile::new().unwrap().path()).unwrap());
    let container_updater = UpdateContainerMapping { container };
    assert_matches!(
        container_updater.dev_mem_added(0x1000, &arc_anon, None),
        Err(_)
    );
    assert_matches!(
        container_updater.dev_mem_removed(0x1000, &arc_anon, None),
        Err(_)
    );

    // UpdateIommuIoas dev_mem callbacks without real iommu fd return ioctl error
    let iommu = Arc::new(Iommu::new(tempfile::NamedTempFile::new().unwrap().path()).unwrap());
    // Create Ioas with dummy id 0
    let ioas = Arc::new(crate::vfio::iommu::Ioas { iommu, id: 0 });
    let iommu_updater = UpdateIommuIoas { ioas };
    assert_matches!(iommu_updater.dev_mem_added(0x1000, &arc_anon, None), Err(_));
    assert_matches!(
        iommu_updater.dev_mem_removed(0x1000, &arc_anon, None),
        Err(_)
    );
}

#[test]
fn test_cdev_and_dev_fd_device_impl() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(tmp.path())
        .unwrap();
    file.write_all(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        .unwrap();

    let cdev = Cdev::new(tmp.path()).unwrap();
    let region = VfioRegionInfo {
        index: 0,
        size: 8,
        offset: 0,
        flags: VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        ..Default::default()
    };

    let mut buf = [0u8; 4];
    cdev.read_region(&region, 2, &mut buf).unwrap();
    assert_eq!(buf, [0x33, 0x44, 0x55, 0x66]);

    cdev.write_region(&region, 0, &[0xaa, 0xbb]).unwrap();
    cdev.read_region(&region, 0, &mut buf).unwrap();
    assert_eq!(buf, [0xaa, 0xbb, 0x33, 0x44]);

    assert_matches!(cdev.get_info(), Err(_));
    assert_matches!(cdev.get_region_info(0), Err(_));
    assert_matches!(cdev.get_irq_info(0), Err(_));
    assert_matches!(cdev.reset(), Err(_));
    assert_matches!(cdev.set_irq_eventfd(0, 0, &[None]), Err(_));
    assert_matches!(cdev.disable_irq(0), Err(_));
    assert_matches!(cdev.get_region_mmap_fd(0), Err(_));
    assert_matches!(cdev.get_dma_buf_fd(0, 0, 0x1000), Err(_));

    // Test DevFd
    let group = Arc::new(Group::new(tmp.path()).unwrap());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .unwrap();
    let io_dev = VfioIoDevice::new(file).unwrap();
    let dev_fd = crate::vfio::group::DevFd {
        io_dev,
        _group: group,
    };
    assert_matches!(dev_fd.get_info(), Err(_));
    assert_matches!(dev_fd.get_region_info(0), Err(_));
    assert_matches!(dev_fd.get_irq_info(0), Err(_));
    assert_matches!(dev_fd.reset(), Err(_));
    assert_matches!(dev_fd.set_irq_eventfd(0, 0, &[None]), Err(_));
    assert_matches!(dev_fd.disable_irq(0), Err(_));
    assert_matches!(dev_fd.read_region(&region, 0, &mut buf), Ok(()));
    assert_matches!(dev_fd.write_region(&region, 0, &[0x11, 0x22]), Ok(()));
    assert_matches!(dev_fd.get_region_mmap_fd(0), Err(_));
    assert_matches!(dev_fd.get_dma_buf_fd(0, 0, 0x1000), Err(_));
}

#[test]
fn test_ioas_methods() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let iommu = Arc::new(Iommu::new(tmp.path()).unwrap());
    let ioas = crate::vfio::iommu::Ioas { iommu, id: 1 };

    assert_matches!(ioas.map(0x1000, 0x2000, 0x1000), Err(_));
    assert_matches!(ioas.unmap(0x2000, 0x1000), Err(_));
    assert_matches!(ioas.reset(), Err(_));
}
