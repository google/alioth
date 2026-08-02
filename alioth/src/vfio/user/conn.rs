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
use std::io::{IoSlice, IoSliceMut};
use std::mem::size_of;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use parking_lot::Mutex;
use zerocopy::IntoBytes;

use crate::sys::vfio::{VfioIrqInfo, VfioRegionInfo};
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::vfio::user::bindings::{
    VfioUserCmd, VfioUserDeviceInfo, VfioUserDmaMap, VfioUserDmaUnmap, VfioUserHeader,
    VfioUserHeaderFlag, VfioUserIrqSet, VfioUserMessageType, VfioUserRegionAccess, VfioUserVersion,
};
use crate::vfio::user::{Result, error};

#[derive(Debug)]
struct Session {
    stream: UnixStream,
    next_msg_id: u16,
}

#[derive(Debug)]
pub struct VfioUserSession {
    session: Mutex<Session>,
}

impl VfioUserSession {
    pub fn new(stream: UnixStream) -> Self {
        VfioUserSession {
            session: Mutex::new(Session {
                stream,
                next_msg_id: 0,
            }),
        }
    }

    fn transact(
        &self,
        cmd: VfioUserCmd,
        req_bufs: (&[u8], &[u8]),
        req_fds: &[BorrowedFd<'_>],
        resp_bufs: (&mut [u8], &mut [u8]),
        resp_fds: &mut [Option<OwnedFd>],
    ) -> Result<VfioUserHeader> {
        let mut session = self.session.lock();
        let msg_id = session.next_msg_id;
        session.next_msg_id = msg_id.wrapping_add(1);
        let stream = &mut session.stream;

        let (req, data) = req_bufs;
        let total_req_size = size_of::<VfioUserHeader>() + req.len() + data.len();

        let header = VfioUserHeader {
            msg_id,
            cmd,
            msg_size: total_req_size as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::COMMAND, false, false),
            error_no: 0,
        };
        let send_slices = [
            IoSlice::new(header.as_bytes()),
            IoSlice::new(req),
            IoSlice::new(data),
        ];
        let done = send_msg_with_fds(stream, &send_slices, req_fds)?;
        if done != total_req_size {
            return error::PartialWrite {
                want: total_req_size,
                done,
            }
            .fail();
        }

        let mut reply_header = VfioUserHeader::default();
        let (resp, data) = resp_bufs;
        let mut reply_header_slice = [
            IoSliceMut::new(reply_header.as_mut_bytes()),
            IoSliceMut::new(resp),
            IoSliceMut::new(data),
        ];
        let bytes_read = recv_msg_with_fds(stream, &mut reply_header_slice, resp_fds)?;
        if bytes_read < size_of::<VfioUserHeader>() + resp.len() {
            return error::PartialRead {
                want: size_of::<VfioUserHeader>() + resp.len(),
                done: bytes_read,
            }
            .fail();
        }
        if reply_header.msg_size != bytes_read as u32 {
            return error::PartialRead {
                want: reply_header.msg_size as usize,
                done: bytes_read,
            }
            .fail();
        }
        if reply_header.msg_id != msg_id {
            return error::MsgId {
                want: msg_id,
                got: reply_header.msg_id,
            }
            .fail();
        }
        if reply_header.cmd != cmd {
            return error::Response {
                want: cmd,
                got: reply_header.cmd,
            }
            .fail();
        }
        if reply_header.flags.ty() != VfioUserMessageType::REPLY {
            return error::HeaderFlag {
                flags: reply_header.flags,
            }
            .fail();
        }
        if reply_header.flags.error() {
            return error::ServerErr {
                cmd,
                code: reply_header.error_no,
            }
            .fail();
        }

        Ok(reply_header)
    }

    pub fn negotiate_version(&self) -> Result<()> {
        let version_hdr = VfioUserVersion { major: 0, minor: 2 };
        let caps_str = "{\"capabilities\":{\"max_fds\":32,\"max_data_xfer_size\":1048576}}\0";
        let caps_bytes = caps_str.as_bytes();

        let mut resp = VfioUserVersion::default();
        let mut resp_buf = vec![0u8; 8192];

        let reply = self.transact(
            VfioUserCmd::VERSION,
            (version_hdr.as_bytes(), caps_bytes),
            &[],
            (resp.as_mut_bytes(), resp_buf.as_mut_slice()),
            &mut [],
        )?;

        let server_major = resp.major;
        let server_minor = resp.minor;
        log::debug!("vfio-user server version: {server_major}.{server_minor}");
        if server_major != 0 {
            return error::Version {
                major: server_major,
                minor: server_minor,
            }
            .fail();
        }

        let caps_reply_size =
            reply.msg_size as usize - size_of::<VfioUserHeader>() - size_of::<VfioUserVersion>();
        if caps_reply_size > 0 {
            let caps_reply = &resp_buf[..caps_reply_size];
            log::debug!(
                "vfio-user server capabilities: {}",
                String::from_utf8_lossy(caps_reply)
            );
        }

        Ok(())
    }

    pub fn dma_map(&self, req: &VfioUserDmaMap, fd: BorrowedFd) -> Result<()> {
        self.transact(
            VfioUserCmd::DMA_MAP,
            (req.as_bytes(), &[]),
            &[fd],
            (&mut [], &mut []),
            &mut [],
        )?;
        Ok(())
    }

    pub fn dma_unmap(&self, req: &VfioUserDmaUnmap) -> Result<()> {
        let mut resp = VfioUserDmaUnmap::default();
        self.transact(
            VfioUserCmd::DMA_UNMAP,
            (req.as_bytes(), &[]),
            &[],
            (resp.as_mut_bytes(), &mut []),
            &mut [],
        )?;
        Ok(())
    }

    pub fn get_device_info(&self) -> Result<VfioUserDeviceInfo> {
        let req = VfioUserDeviceInfo {
            argsz: size_of::<VfioUserDeviceInfo>() as u32,
            ..Default::default()
        };
        let mut resp = VfioUserDeviceInfo::default();
        self.transact(
            VfioUserCmd::DEVICE_GET_INFO,
            (req.as_bytes(), &[]),
            &[],
            (resp.as_mut_bytes(), &mut []),
            &mut [],
        )?;
        Ok(resp)
    }

    pub fn get_region_info(&self, index: u32) -> Result<(VfioRegionInfo, Option<OwnedFd>)> {
        let req = VfioRegionInfo {
            argsz: size_of::<VfioRegionInfo>() as u32,
            index,
            ..Default::default()
        };
        let mut resp = VfioRegionInfo::default();
        let mut resp_fd = None;

        self.transact(
            VfioUserCmd::DEVICE_GET_REGION_INFO,
            (req.as_bytes(), &[]),
            &[],
            (resp.as_mut_bytes(), &mut []),
            array::from_mut(&mut resp_fd),
        )?;

        Ok((resp, resp_fd))
    }

    pub fn get_irq_info(&self, index: u32) -> Result<VfioIrqInfo> {
        let req = VfioIrqInfo {
            argsz: size_of::<VfioIrqInfo>() as u32,
            index,
            ..Default::default()
        };
        let mut resp = VfioIrqInfo::default();

        self.transact(
            VfioUserCmd::DEVICE_GET_IRQ_INFO,
            (req.as_bytes(), &[]),
            &[],
            (resp.as_mut_bytes(), &mut []),
            &mut [],
        )?;

        Ok(resp)
    }

    pub fn reset(&self) -> Result<()> {
        self.transact(
            VfioUserCmd::DEVICE_RESET,
            (&[], &[]),
            &[],
            (&mut [], &mut []),
            &mut [],
        )?;
        Ok(())
    }

    pub fn set_irqs(&self, req: &VfioUserIrqSet, data: &[u8], fds: &[BorrowedFd]) -> Result<()> {
        self.transact(
            VfioUserCmd::DEVICE_SET_IRQS,
            (req.as_bytes(), data),
            fds,
            (&mut [], &mut []),
            &mut [],
        )?;
        Ok(())
    }

    pub fn read_region(&self, req: &VfioUserRegionAccess, buf: &mut [u8]) -> Result<()> {
        let mut resp = VfioUserRegionAccess::default();
        self.transact(
            VfioUserCmd::REGION_READ,
            (req.as_bytes(), &[]),
            &[],
            (resp.as_mut_bytes(), buf),
            &mut [],
        )?;
        if resp.count != buf.len() as u32 {
            return error::PartialRead {
                want: buf.len(),
                done: resp.count as usize,
            }
            .fail();
        }

        Ok(())
    }

    pub fn write_region(&self, req: VfioUserRegionAccess, buf: &[u8]) -> Result<()> {
        let mut resp = VfioUserRegionAccess::default();
        self.transact(
            VfioUserCmd::REGION_WRITE,
            (req.as_bytes(), buf),
            &[],
            (resp.as_mut_bytes(), &mut []),
            &mut [],
        )?;
        if resp.count != buf.len() as u32 {
            return error::PartialWrite {
                want: buf.len(),
                done: resp.count as usize,
            }
            .fail();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "conn_test.rs"]
mod tests;
