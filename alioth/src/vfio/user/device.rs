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

use std::array;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::IoSlice;
use std::mem::size_of;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::Arc;

use parking_lot::RwLock;
use zerocopy::{FromBytes, IntoBytes};

use crate::mem;
use crate::mem::LayoutChanged;
use crate::mem::mapped::ArcMemPages;
use crate::sys::vfio::{
    VfioDeviceInfo, VfioDeviceInfoFlag, VfioIrqInfo, VfioIrqSetFlag, VfioRegionInfo,
};
use crate::vfio::device::Device;
use crate::vfio::{Result, error};

use super::bindings::*;
use super::conn::VfioUserSession;

#[derive(Debug)]
pub struct VfioUserDevice {
    session: Arc<VfioUserSession>,
    num_regions: u32,
    num_irqs: u32,
    flags: VfioDeviceInfoFlag,
    region_fds: RwLock<HashMap<u32, Option<OwnedFd>>>,
}

impl VfioUserDevice {
    pub fn new(session: Arc<VfioUserSession>) -> Result<Self> {
        let req = VfioUserDeviceInfo {
            argsz: size_of::<VfioUserDeviceInfo>() as u32,
            ..Default::default()
        };
        let mut resp = VfioUserDeviceInfo::default();
        let mut resp_fds = vec![];
        session.transact(
            VfioUserCmd::DEVICE_GET_INFO,
            &[IoSlice::new(req.as_bytes())],
            &[],
            resp.as_mut_bytes(),
            &mut resp_fds,
        )?;

        let num_regions = resp.num_regions;
        let num_irqs = resp.num_irqs;
        let flags = resp.flags;

        let dev = VfioUserDevice {
            session,
            num_regions,
            num_irqs,
            flags,
            region_fds: RwLock::new(HashMap::new()),
        };

        Ok(dev)
    }
}

impl Device for VfioUserDevice {
    fn get_info(&self) -> Result<VfioDeviceInfo> {
        Ok(VfioDeviceInfo {
            argsz: size_of::<VfioDeviceInfo>() as u32,
            flags: self.flags,
            num_regions: self.num_regions,
            num_irqs: self.num_irqs,
            cap_offset: 0,
            pad: 0,
        })
    }

    fn get_region_info(&self, index: u32) -> Result<VfioRegionInfo> {
        let req = VfioRegionInfo {
            argsz: size_of::<VfioRegionInfo>() as u32,
            index,
            ..Default::default()
        };
        let mut resp = VfioRegionInfo::default();
        let mut resp_fd = None;

        self.session.transact(
            VfioUserCmd::DEVICE_GET_REGION_INFO,
            &[IoSlice::new(req.as_bytes())],
            &[],
            resp.as_mut_bytes(),
            array::from_mut(&mut resp_fd),
        )?;
        let mut fds = self.region_fds.write();
        if let Some(old) = fds.insert(index, resp_fd) {
            fds.insert(index, old);
        }
        Ok(resp)
    }

    fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        let req = VfioIrqInfo {
            argsz: size_of::<VfioIrqInfo>() as u32,
            index,
            ..Default::default()
        };
        let mut resp = VfioIrqInfo::default();
        let mut resp_fds = vec![];
        self.session.transact(
            VfioUserCmd::DEVICE_GET_IRQ_INFO,
            &[IoSlice::new(req.as_bytes())],
            &[],
            resp.as_mut_bytes(),
            &mut resp_fds,
        )?;

        Ok(VfioIrqInfo {
            argsz: size_of::<VfioIrqInfo>() as u32,
            flags: resp.flags,
            index: resp.index,
            count: resp.count,
        })
    }

    fn reset(&self) -> Result<()> {
        let mut resp_fds = vec![];
        self.session
            .transact(VfioUserCmd::DEVICE_RESET, &[], &[], &mut [], &mut resp_fds)?;
        Ok(())
    }

    fn set_irq_eventfd(
        &self,
        index: u32,
        start: u32,
        eventfds: &[Option<BorrowedFd<'_>>],
    ) -> Result<()> {
        let mut send_fds = vec![];
        let mut fd_indices = vec![];
        for fd in eventfds {
            if let Some(f) = fd {
                fd_indices.push(send_fds.len() as i32);
                send_fds.push(*f);
            } else {
                fd_indices.push(-1);
            }
        }

        let irq_set = VfioUserIrqSet {
            argsz: (size_of::<VfioUserIrqSet>() + fd_indices.len() * size_of::<i32>()) as u32,
            flags: VfioIrqSetFlag::DATA_EVENTFD | VfioIrqSetFlag::ACTION_TRIGGER,
            index,
            start,
            count: eventfds.len() as u32,
        };

        let req_slices = [
            IoSlice::new(irq_set.as_bytes()),
            IoSlice::new(fd_indices.as_bytes()),
        ];

        let mut resp_fds = vec![];
        self.session.transact(
            VfioUserCmd::DEVICE_SET_IRQS,
            &req_slices,
            &send_fds,
            &mut [],
            &mut resp_fds,
        )?;
        Ok(())
    }

    fn disable_irq(&self, index: u32) -> Result<()> {
        let irq_set = VfioUserIrqSet {
            argsz: size_of::<VfioUserIrqSet>() as u32,
            flags: VfioIrqSetFlag::DATA_NONE | VfioIrqSetFlag::ACTION_TRIGGER,
            index,
            start: 0,
            count: 0,
        };
        let mut resp_fds = vec![];
        self.session.transact(
            VfioUserCmd::DEVICE_SET_IRQS,
            &[IoSlice::new(irq_set.as_bytes())],
            &[],
            &mut [],
            &mut resp_fds,
        )?;
        Ok(())
    }

    fn read_region(&self, region: &VfioRegionInfo, offset: u64, buf: &mut [u8]) -> Result<()> {
        let req = VfioUserRegionAccess {
            offset,
            region: region.index,
            count: buf.len() as u32,
        };
        let needed_size = size_of::<VfioUserRegionAccess>() + buf.len();
        let mut stack_buf = [0u8; 128];
        let mut heap_buf;
        let resp_buf = if needed_size <= 128 {
            &mut stack_buf[..needed_size]
        } else {
            heap_buf = vec![0u8; needed_size];
            &mut heap_buf[..]
        };

        let mut resp_fds = vec![];
        self.session.transact(
            VfioUserCmd::REGION_READ,
            &[IoSlice::new(req.as_bytes())],
            &[],
            resp_buf,
            &mut resp_fds,
        )?;
        let Ok((resp, _)) = VfioUserRegionAccess::read_from_prefix(&resp_buf[..]) else {
            return error::VfioUser {
                msg: "failed to parse read region response".to_string(),
            }
            .fail();
        };
        let count = resp.count;
        if count != buf.len() as u32 {
            return error::VfioUser {
                msg: format!(
                    "read region truncated: expected {}, got {}",
                    buf.len(),
                    count
                ),
            }
            .fail();
        }
        buf.copy_from_slice(&resp_buf[size_of::<VfioUserRegionAccess>()..]);
        Ok(())
    }

    fn write_region(&self, region: &VfioRegionInfo, offset: u64, buf: &[u8]) -> Result<()> {
        let req = VfioUserRegionAccess {
            offset,
            region: region.index,
            count: buf.len() as u32,
        };
        let req_slices = [IoSlice::new(req.as_bytes()), IoSlice::new(buf)];
        let mut resp = VfioUserRegionAccess::default();
        let mut resp_fds = vec![];
        self.session.transact(
            VfioUserCmd::REGION_WRITE,
            &req_slices,
            &[],
            resp.as_mut_bytes(),
            &mut resp_fds,
        )?;
        let written = resp.count;
        if written != buf.len() as u32 {
            return error::VfioUser {
                msg: format!(
                    "write region truncated: expected {}, got {}",
                    buf.len(),
                    written
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn get_region_mmap_fd(&self, index: u32) -> Result<Option<OwnedFd>> {
        if let Some(Some(fd)) = &self.region_fds.read().get(&index) {
            Ok(Some(fd.try_clone()?))
        } else {
            Ok(None)
        }
    }

    fn get_dma_buf_fd(&self, _index: u32, _offset: u64, _size: usize) -> Result<OwnedFd> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dma-buf is not supported in vfio-user",
        )
        .into())
    }
}

#[derive(Debug)]
pub struct UpdateVfioUserMapping {
    session: Arc<VfioUserSession>,
}

impl UpdateVfioUserMapping {
    pub fn new(session: Arc<VfioUserSession>) -> Self {
        UpdateVfioUserMapping { session }
    }
}

impl LayoutChanged for UpdateVfioUserMapping {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        self.session.dma_map(gpa, pages)
    }

    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        self.session.dma_unmap(gpa, pages)
    }

    fn dev_mem_added(
        &self,
        gpa: u64,
        pages: &ArcMemPages,
        _: Option<BorrowedFd>,
    ) -> mem::Result<()> {
        if pages.fd().is_none() {
            log::warn!(
                "vfio-user: dev_mem_added: no fd for pages at gpa {:#x}, skipping mapping",
                gpa
            );
            return Ok(());
        }
        self.session.dma_map(gpa, pages)
    }

    fn dev_mem_removed(
        &self,
        gpa: u64,
        pages: &ArcMemPages,
        _: Option<BorrowedFd>,
    ) -> mem::Result<()> {
        if pages.fd().is_none() {
            return Ok(());
        }
        self.ram_removed(gpa, pages)
    }
}
