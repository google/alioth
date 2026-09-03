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

use std::io::{IoSlice, IoSliceMut};
use std::mem::size_of;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU16, Ordering};

use parking_lot::Mutex;
use zerocopy::{FromBytes, IntoBytes};

use crate::errors::BoxTrace;
use crate::mem;
use crate::mem::mapped::ArcMemPages;
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::vfio::{Result, error};

use super::bindings::*;

#[derive(Debug)]
pub struct VfioUserSession {
    stream: Mutex<UnixStream>,
    next_msg_id: AtomicU16,
}

impl VfioUserSession {
    pub fn new(stream: UnixStream) -> Self {
        VfioUserSession {
            stream: Mutex::new(stream),
            next_msg_id: AtomicU16::new(0),
        }
    }

    fn alloc_msg_id(&self) -> u16 {
        self.next_msg_id.fetch_add(1, Ordering::AcqRel)
    }

    pub fn transact(
        &self,
        cmd: VfioUserCmd,
        req_slices: &[IoSlice<'_>],
        req_fds: &[BorrowedFd<'_>],
        resp_buf: &mut [u8],
        resp_fds: &mut [Option<OwnedFd>],
    ) -> Result<VfioUserHeader> {
        let msg_id = self.alloc_msg_id();
        let mut stream = self.stream.lock();

        let req_payload_size: usize = req_slices.iter().map(|s| s.len()).sum();
        let total_req_size = size_of::<VfioUserHeader>() + req_payload_size;

        let header = VfioUserHeader {
            msg_id,
            cmd,
            msg_size: total_req_size as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::COMMAND, false, false),
            error_no: 0,
        };

        let mut send_slices = Vec::with_capacity(req_slices.len() + 1);
        send_slices.push(IoSlice::new(header.as_bytes()));
        send_slices.extend_from_slice(req_slices);

        send_msg_with_fds(&stream, &send_slices, req_fds)?;

        let mut reply_header = VfioUserHeader::default();
        let mut reply_header_slice = [IoSliceMut::new(reply_header.as_mut_bytes())];

        let bytes_read = recv_msg_with_fds(&stream, &mut reply_header_slice, resp_fds)?;
        let header_size = size_of::<VfioUserHeader>();
        if bytes_read < header_size {
            use std::io::Read;
            stream.read_exact(&mut reply_header.as_mut_bytes()[bytes_read..header_size])?;
        }

        let reply_msg_id = reply_header.msg_id;
        let reply_flags = reply_header.flags;
        let reply_error_no = reply_header.error_no;
        let reply_msg_size = reply_header.msg_size;

        if reply_msg_id != msg_id {
            return error::VfioUser {
                msg: format!("msg_id mismatch: expected {}, got {}", msg_id, reply_msg_id),
            }
            .fail();
        }
        if reply_flags.ty() != VfioUserMessageType::REPLY {
            return error::VfioUser {
                msg: format!(
                    "unexpected message flags: {:?} (expected reply type)",
                    reply_flags
                ),
            }
            .fail();
        }

        if reply_flags.error() {
            return Err(std::io::Error::from_raw_os_error(reply_error_no as i32).into());
        }

        if (reply_msg_size as usize) < header_size {
            return error::VfioUser {
                msg: format!(
                    "invalid reply message size: {} (must be at least {})",
                    reply_msg_size, header_size
                ),
            }
            .fail();
        }
        let payload_size = reply_msg_size as usize - header_size;
        if payload_size > 0 {
            if resp_buf.len() < payload_size {
                return error::VfioUser {
                    msg: format!(
                        "response buffer too small: need {}, got {}",
                        payload_size,
                        resp_buf.len()
                    ),
                }
                .fail();
            }
            let read_buf = &mut resp_buf[..payload_size];
            use std::io::Read;
            stream.read_exact(read_buf)?;
        }

        Ok(reply_header)
    }

    pub fn negotiate_version(&self) -> Result<()> {
        let version_hdr = VfioUserVersion { major: 0, minor: 2 };
        let caps_str = "{\"capabilities\":{\"max_fds\":32,\"max_data_xfer_size\":1048576}}\0";
        let caps_bytes = caps_str.as_bytes();

        let req_slices = [
            IoSlice::new(version_hdr.as_bytes()),
            IoSlice::new(caps_bytes),
        ];

        let mut resp_buf = vec![0u8; 8192];
        let mut resp_fds = vec![];

        let reply = self.transact(
            VfioUserCmd::VERSION,
            &req_slices,
            &[],
            &mut resp_buf,
            &mut resp_fds,
        )?;

        let payload_size = reply.msg_size as usize - size_of::<VfioUserHeader>();
        if payload_size < size_of::<VfioUserVersion>() {
            return error::VfioUser {
                msg: format!("version reply payload too small: {}", payload_size),
            }
            .fail();
        }

        let Ok((version_reply, _)) = VfioUserVersion::read_from_prefix(&resp_buf[..payload_size])
        else {
            return error::VfioUser {
                msg: "failed to parse version reply".to_string(),
            }
            .fail();
        };
        let server_major = version_reply.major;
        let server_minor = version_reply.minor;
        log::debug!(
            "vfio-user server version: {}.{}",
            server_major,
            server_minor
        );
        if server_major != 0 {
            return error::VfioUser {
                msg: format!("unsupported server major version: {}", server_major),
            }
            .fail();
        }

        let caps_reply_size = payload_size - size_of::<VfioUserVersion>();
        if caps_reply_size > 0 {
            let caps_reply = &resp_buf[size_of::<VfioUserVersion>()..payload_size];
            log::debug!(
                "vfio-user server capabilities: {}",
                String::from_utf8_lossy(caps_reply)
            );
        }

        Ok(())
    }

    pub fn dma_map(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((fd, offset)) = pages.fd() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Memory is not backed by an FD",
            )
            .into());
        };

        let map = VfioUserDmaMap {
            argsz: size_of::<VfioUserDmaMap>() as u32,
            flags: VfioUserDmaMapFlag::READ | VfioUserDmaMapFlag::WRITE,
            offset,
            addr: gpa,
            size: pages.size(),
        };

        let mut resp_fds = vec![];
        let ret = self.transact(
            VfioUserCmd::DMA_MAP,
            &[IoSlice::new(map.as_bytes())],
            &[fd],
            &mut [],
            &mut resp_fds,
        );

        ret.box_trace(mem::error::ChangeLayout)?;
        Ok(())
    }

    pub fn dma_unmap(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let unmap = VfioUserDmaUnmap {
            argsz: size_of::<VfioUserDmaUnmap>() as u32,
            flags: 0,
            addr: gpa,
            size: pages.size(),
        };

        let mut resp = VfioUserDmaUnmap::default();
        let mut resp_fds = vec![];
        let ret = self.transact(
            VfioUserCmd::DMA_UNMAP,
            &[IoSlice::new(unmap.as_bytes())],
            &[],
            resp.as_mut_bytes(),
            &mut resp_fds,
        );

        ret.box_trace(mem::error::ChangeLayout)?;
        Ok(())
    }
}
