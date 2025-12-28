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
use std::io::{self, ErrorKind};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;

use bitflags::bitflags;
use mio::event::Event;
use mio::Registry;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::impl_mmio_for_zerocopy;
use crate::mem::mapped::RamBus;
use crate::virtio::dev::{DevParam, Virtio};
use crate::virtio::queue::handlers::handle_desc;
use crate::virtio::queue::{Descriptor, VirtQueue};
use crate::virtio::{DeviceId, IrqSender, Result};

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub const VIRTIO_BLK_T_GET_LIFETIME: u32 = 10;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;
pub const VIRTIO_BLK_T_SECURE_ERASE: u32 = 14;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const VIRTIO_BLK_ID_SIZE: usize = 20;

const SECTOR_SIZE: usize = 1 << 9;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BlockFeature: u64 {
        const SIZE_MAX = 1 << 1;
        const SEG_MAX = 1 << 2;
        const GEOMETRY = 1 << 4;
        const RO = 1 << 5;
        const BLK_SIZE = 1 << 6;
        const FLUSH = 1 << 9;
        const TOPOLOGY = 1 << 10;
        const CONFIG_WCE = 1 << 11;
        const MQ = 1 << 12;
        const DISCARD = 1 << 13;
        const WRITE_ZEROS = 1 << 14;
        const LIFETIME = 1 << 15;
        const SECURE_ERASE = 1 << 16;
    }
}

#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
pub struct BlockConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,

    // geometry
    cylinders: u16,
    heads: u8,
    sectors: u8,

    blk_size: u32,

    // topology
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,

    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
    _unused1: [u8; 3],
    max_secure_erase_sectors: u32,
    max_secure_erase_seg: u32,
    secure_erase_sector_alignment: u32,
}
impl_mmio_for_zerocopy!(BlockConfig);

pub struct BlockParam {
    pub path: PathBuf,
}

impl DevParam for BlockParam {
    type Device = Block;

    fn build(self, name: Arc<String>) -> Result<Block> {
        Block::new(self, name)
    }
}

#[derive(Debug)]
pub struct Block {
    name: Arc<String>,
    config: Arc<BlockConfig>,
    disk: File,
    feature: BlockFeature,
}

impl Block {
    pub fn new(param: BlockParam, name: Arc<String>) -> Result<Self> {
        let disk = OpenOptions::new().read(true).write(true).open(param.path)?;
        let len = disk.metadata()?.len();
        let config = BlockConfig {
            capacity: len / SECTOR_SIZE as u64,
            num_queues: 1,
            ..Default::default()
        };
        let config = Arc::new(config);
        Ok(Block {
            name,
            disk,
            config,
            feature: BlockFeature::FLUSH,
        })
    }

    fn handle_req_queue(&self, desc: &mut Descriptor) -> io::Result<usize> {
        let disk = &self.disk;
        let Some(buf0) = desc.readable.first() else {
            return Err(ErrorKind::InvalidData.into());
        };
        let hdr_clone;
        let header = match BlockReqHeader::ref_from(buf0) {
            Some(h) => h,
            None => match FromBytes::read_from(buf0) {
                Some(h) => {
                    hdr_clone = h;
                    &hdr_clone
                }
                None => return Err(ErrorKind::InvalidData.into()),
            },
        };
        let offset = header.sector * SECTOR_SIZE as u64;
        let w_len = match header.type_ {
            VIRTIO_BLK_T_IN => {
                let Some(buf1) = desc.writable.first_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let l = buf1.len();
                let status = match disk.read_exact_at(buf1, offset) {
                    Ok(()) => VIRTIO_BLK_S_OK,
                    Err(e) => {
                        log::error!("{}: read {l} bytes from offset {offset:#x}: {e}", self.name);
                        VIRTIO_BLK_S_IOERR
                    }
                };
                let Some(buf2) = desc.writable.get_mut(1) else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let Some(status_byte) = buf2.first_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                *status_byte = status;
                l + 1
            }
            VIRTIO_BLK_T_OUT => {
                let Some(buf1) = desc.readable.get(1) else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let l = buf1.len();
                let status = match disk.write_all_at(buf1, offset) {
                    Ok(()) => VIRTIO_BLK_S_OK,
                    Err(e) => {
                        log::error!("{}: write {l} bytes to offset {offset:#x}: {e}", self.name);
                        VIRTIO_BLK_S_IOERR
                    }
                };
                let Some(buf2) = desc.writable.first_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let Some(status_byte) = buf2.first_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                *status_byte = status;
                1
            }
            VIRTIO_BLK_T_FLUSH => {
                // TODO flush the file
                let Some(w_buf) = desc.writable.last_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let Some(status_byte) = w_buf.get_mut(0) else {
                    return Err(ErrorKind::InvalidData.into());
                };
                *status_byte = VIRTIO_BLK_S_OK;
                1
            }
            VIRTIO_BLK_T_GET_ID => {
                let Some(buf1) = desc.writable.first_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let len = std::cmp::min(self.name.len(), buf1.len());
                buf1[0..len].copy_from_slice(&self.name.as_bytes()[0..len]);
                let Some(buf2) = desc.writable.get_mut(1) else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let Some(status_byte) = buf2.first_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                *status_byte = VIRTIO_BLK_S_OK;
                1 + len
            }
            _ => {
                log::error!("unimplemented op: {}", header.type_);
                let Some(w_buf) = desc.writable.last_mut() else {
                    return Err(ErrorKind::InvalidData.into());
                };
                let Some(w_byte) = w_buf.get_mut(0) else {
                    return Err(ErrorKind::InvalidData.into());
                };
                *w_byte = VIRTIO_BLK_S_UNSUPP;
                1
            }
        };
        Ok(w_len)
    }
}

impl Virtio for Block {
    type Config = BlockConfig;

    fn reset(&mut self, _registry: &Registry) {}

    fn device_id() -> DeviceId {
        DeviceId::Block
    }

    fn num_queues(&self) -> u16 {
        self.config.num_queues
    }

    fn config(&self) -> Arc<BlockConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u64 {
        self.feature.bits()
    }

    fn activate(&mut self, _registry: &Registry, _feature: u64, _memory: &RamBus) -> Result<()> {
        Ok(())
    }

    fn handle_event(
        &mut self,
        _event: &Event,
        _queues: &[impl VirtQueue],
        _irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        Ok(())
    }

    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        let Some(queue) = queues.get(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        handle_desc(&self.name, index, queue, irq_sender, |desc| {
            self.handle_req_queue(desc)
        })
    }
}

#[repr(C)]
#[derive(Debug, FromZeroes, FromBytes)]
pub struct BlockReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}
