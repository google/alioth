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
use std::io::{IoSlice, IoSliceMut, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use bitflags::bitflags;
#[cfg(target_os = "linux")]
use io_uring::cqueue::Entry as Cqe;
#[cfg(target_os = "linux")]
use io_uring::opcode;
#[cfg(target_os = "linux")]
use io_uring::types::Fd;
use mio::Registry;
use mio::event::Event;
use serde::Deserialize;
use serde_aco::Help;
use snafu::ResultExt;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::hv::IoeventFd;
use crate::mem::mapped::RamBus;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{DevParam, Virtio, WakeEvent};
use crate::virtio::queue::{DescChain, QueueReg, Status as QStatus, VirtQueue};
use crate::virtio::worker::WorkerApi;
#[cfg(target_os = "linux")]
use crate::virtio::worker::io_uring::{ActiveIoUring, BufferAction, IoUring, VirtioIoUring};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, IrqSender, Result, error};
use crate::{c_enum, impl_mmio_for_zerocopy};

c_enum! {
    #[derive(FromBytes)]
    pub struct RequestType(u32);
    {
        IN = 0;
        OUT = 1;
        FLUSH = 4;
        GET_ID = 8;
        GET_LIFETIME = 10;
        DISCARD = 11;
        WRITE_ZEROES = 13;
        SECURE_ERASE = 14;
    }
}

c_enum! {
    #[derive(FromBytes)]
    pub struct Status(u8);
    {
        OK = 0;
        IOERR = 1;
        UNSUPP = 2;
    }
}

#[repr(C)]
#[derive(Debug, FromBytes)]
pub struct Request {
    type_: RequestType,
    reserved: u32,
    sector: u64,
}

pub const VIRTIO_BLK_ID_SIZE: usize = 20;

const SECTOR_SIZE: usize = 1 << 9;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BlockFeature: u128 {
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

#[derive(Debug, Default, FromZeros, Immutable, IntoBytes)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct BlkFileParam {
    /// Path to a raw-formatted disk image.
    pub path: Box<Path>,
    /// Set the device as readonly. [default: false]
    #[serde(default)]
    pub readonly: bool,
    /// System API for asynchronous IO.
    #[serde(default)]
    pub api: WorkerApi,
}

impl DevParam for BlkFileParam {
    type Device = Block;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Block> {
        Block::new(self, name)
    }
}

enum BlkRequest<'d, 'm> {
    Done {
        written: u32,
    },
    In {
        data: &'d mut IoSliceMut<'m>,
        offset: u64,
        status: &'d mut u8,
    },
    Out {
        data: &'d IoSlice<'m>,
        offset: u64,
        status: &'d mut u8,
    },
    Flush {
        status: &'d mut u8,
    },
}

#[derive(Debug)]
pub struct Block {
    name: Arc<str>,
    config: Arc<BlockConfig>,
    disk: File,
    feature: BlockFeature,
    api: WorkerApi,
}

impl Block {
    pub fn new(param: BlkFileParam, name: impl Into<Arc<str>>) -> Result<Self> {
        let access_disk = error::AccessFile {
            path: param.path.as_ref(),
        };
        let disk = OpenOptions::new()
            .read(true)
            .write(!param.readonly)
            .open(&param.path)
            .context(access_disk)?;
        let len = disk.metadata().context(access_disk)?.len();
        let config = BlockConfig {
            capacity: len / SECTOR_SIZE as u64,
            num_queues: 1,
            ..Default::default()
        };
        let config = Arc::new(config);
        let mut feature = BlockFeature::FLUSH;
        if param.readonly {
            feature |= BlockFeature::RO;
        }
        Ok(Block {
            name: name.into(),
            disk,
            config,
            feature,
            api: param.api,
        })
    }

    fn handle_desc<'d, 'm>(&self, desc: &'d mut DescChain<'m>) -> Result<BlkRequest<'d, 'm>> {
        let [hdr, data_out @ ..] = &desc.readable[..] else {
            return error::InvalidBuffer.fail();
        };
        let Ok(request) = Request::read_from_bytes(hdr) else {
            return error::InvalidBuffer.fail();
        };
        let [data_in @ .., status_buf] = &mut desc.writable[..] else {
            return error::InvalidBuffer.fail();
        };
        let [status] = &mut status_buf[..] else {
            return error::InvalidBuffer.fail();
        };
        let offset = request.sector * SECTOR_SIZE as u64;
        match request.type_ {
            RequestType::IN => {
                let [data] = data_in else {
                    return error::InvalidBuffer.fail();
                };
                Ok(BlkRequest::In {
                    data,
                    offset,
                    status,
                })
            }
            RequestType::OUT => {
                if self.feature.contains(BlockFeature::RO) {
                    log::error!("{}: attempt to write to a read-only device", self.name);
                    *status = Status::IOERR.into();
                    return Ok(BlkRequest::Done { written: 1 });
                }
                let [data] = data_out else {
                    return error::InvalidBuffer.fail();
                };
                Ok(BlkRequest::Out {
                    data,
                    offset,
                    status,
                })
            }
            RequestType::FLUSH => Ok(BlkRequest::Flush { status }),
            RequestType::GET_ID => {
                let mut name_bytes = self.name.as_bytes();
                let count = name_bytes.read_vectored(data_in)? as u32;
                *status = Status::OK.into();
                Ok(BlkRequest::Done { written: 1 + count })
            }
            unknown => {
                log::error!("{}: unimplemented op: {unknown:#x?}", self.name);
                *status = Status::UNSUPP.into();
                Ok(BlkRequest::Done { written: 1 })
            }
        }
    }
}

impl Virtio for Block {
    type Config = BlockConfig;
    type Feature = BlockFeature;

    fn id(&self) -> DeviceId {
        DeviceId::Block
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_queues(&self) -> u16 {
        self.config.num_queues
    }

    fn config(&self) -> Arc<BlockConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u128 {
        self.feature.bits() | FEATURE_BUILT_IN
    }

    fn spawn_worker<S, E>(
        self,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        match self.api {
            #[cfg(target_os = "linux")]
            WorkerApi::IoUring => IoUring::spawn_worker(self, event_rx, memory, queue_regs),
            WorkerApi::Mio => Mio::spawn_worker(self, event_rx, memory, queue_regs),
        }
    }
}

impl VirtioMio for Block {
    fn reset(&mut self, _registry: &Registry) {}

    fn activate<'m, Q, S, E>(
        &mut self,
        _feature: u128,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        Ok(())
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        _event: &Event,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        Ok(())
    }

    fn handle_queue<'m, Q, S, E>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let Some(Some(queue)) = active_mio.queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        let mut disk = &self.disk;
        queue.handle_desc(index, active_mio.irq_sender, |chain| {
            let written_len = match Block::handle_desc(self, chain) {
                Err(e) => {
                    log::error!("{}: handle descriptor: {e}", self.name);
                    0
                }
                Ok(BlkRequest::Done { written }) => written,
                Ok(BlkRequest::In {
                    data,
                    offset,
                    status,
                }) => match disk.read_exact_at(data, offset) {
                    Ok(_) => {
                        *status = Status::OK.into();
                        data.len() as u32 + 1
                    }
                    Err(e) => {
                        log::error!("{}: read: {e}", self.name);
                        *status = Status::IOERR.into();
                        1
                    }
                },
                Ok(BlkRequest::Out {
                    data,
                    offset,
                    status,
                }) => {
                    match disk.write_all_at(data, offset) {
                        Ok(_) => *status = Status::OK.into(),
                        Err(e) => {
                            log::error!("{}: write: {e}", self.name);
                            *status = Status::IOERR.into();
                        }
                    }
                    1
                }
                Ok(BlkRequest::Flush { status }) => {
                    match disk.flush() {
                        Ok(_) => *status = Status::OK.into(),
                        Err(e) => {
                            log::error!("{}: flush: {e}", self.name);
                            *status = Status::IOERR.into();
                        }
                    }
                    1
                }
            };
            Ok(QStatus::Done { len: written_len })
        })
    }
}

#[cfg(target_os = "linux")]
impl VirtioIoUring for Block {
    fn activate<'m, Q, S, E>(
        &mut self,
        _feature: u128,
        _ring: &mut ActiveIoUring<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        S: IrqSender,
        Q: VirtQueue<'m>,
        E: IoeventFd,
    {
        Ok(())
    }

    fn handle_desc(&mut self, _q_index: u16, chain: &mut DescChain) -> Result<BufferAction> {
        let fd = Fd(self.disk.as_raw_fd());
        let action = match Block::handle_desc(self, chain)? {
            BlkRequest::Done { written } => BufferAction::Written(written),
            BlkRequest::In { data, offset, .. } => {
                let read = opcode::Read::new(fd, data.as_mut_ptr(), data.len() as u32)
                    .offset(offset)
                    .build();
                BufferAction::Sqe(read)
            }
            BlkRequest::Out { data, offset, .. } => {
                let write = opcode::Write::new(fd, data.as_ptr(), data.len() as u32)
                    .offset(offset)
                    .build();
                BufferAction::Sqe(write)
            }
            BlkRequest::Flush { .. } => {
                let flush = opcode::Fsync::new(fd).build();
                BufferAction::Sqe(flush)
            }
        };
        Ok(action)
    }

    fn complete_desc(&mut self, q_index: u16, chain: &mut DescChain, cqe: &Cqe) -> Result<u32> {
        let result = cqe.result();
        let status_code = if result >= 0 {
            Status::OK
        } else {
            let err = std::io::Error::from_raw_os_error(-result);
            log::error!("{}: queue-{q_index} io error: {err}", self.name,);
            Status::IOERR
        };
        match Block::handle_desc(self, chain)? {
            BlkRequest::Done { .. } => unreachable!(),
            BlkRequest::Flush { status } => {
                *status = status_code.into();
                Ok(1)
            }
            BlkRequest::In { data, status, .. } => {
                *status = status_code.into();
                Ok(data.len() as u32 + 1)
            }
            BlkRequest::Out { status, .. } => {
                *status = status_code.into();
                Ok(1)
            }
        }
    }
}
