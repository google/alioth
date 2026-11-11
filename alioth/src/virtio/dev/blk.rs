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
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::slice;
use std::sync::Arc;
use std::thread::JoinHandle;

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

use crate::sync::notifier::Notifier;
use crate::virtio::dev::{DevSpec, Virtio, WorkerParam};
use crate::virtio::queue::{DescChain, Status as QStatus, VirtQueue};
use crate::virtio::worker::WorkerApi;
#[cfg(target_os = "linux")]
use crate::virtio::worker::io_uring::{ActiveIoUring, BufferAction, IoUring, VirtioIoUring};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, IrqSender, Result, error};
use crate::{bitflags, consts, impl_mmio_for_zerocopy};

consts! {
    pub struct RequestType(u32) {
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

consts! {
    pub struct Status(u8) {
        OK = 0;
        IOERR = 1;
        UNSUPP = 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, IntoBytes)]
pub struct Request {
    type_: RequestType,
    reserved: u32,
    sector: u64,
}

pub const VIRTIO_BLK_ID_SIZE: usize = 20;

const SECTOR_SIZE: usize = 1 << 9;

bitflags! {
    pub struct BlockFeature(u128) {
        SIZE_MAX = 1 << 1;
        SEG_MAX = 1 << 2;
        GEOMETRY = 1 << 4;
        RO = 1 << 5;
        BLK_SIZE = 1 << 6;
        FLUSH = 1 << 9;
        TOPOLOGY = 1 << 10;
        CONFIG_WCE = 1 << 11;
        MQ = 1 << 12;
        DISCARD = 1 << 13;
        WRITE_ZEROS = 1 << 14;
        LIFETIME = 1 << 15;
        SECURE_ERASE = 1 << 16;
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
pub struct BlkFileSpec {
    /// Path to a raw-formatted disk image.
    pub path: Box<Path>,
    /// Set the device as readonly. [default: false]
    #[serde(default)]
    pub readonly: bool,
    /// System API for asynchronous IO.
    #[serde(default)]
    pub api: WorkerApi,
}

impl DevSpec for BlkFileSpec {
    type Device = Block;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Block> {
        Block::new(self, name)
    }
}

#[derive(Debug)]
enum BlkRequest<'d, 'm> {
    Done {
        written: u32,
    },
    In {
        data: &'d mut [IoSliceMut<'m>],
        offset: u64,
        status: &'d mut u8,
    },
    Out {
        data: &'d [IoSlice<'m>],
        offset: u64,
        status: &'d mut u8,
    },
    Flush {
        status: &'d mut u8,
    },
}

fn consume_header(readable: &mut Vec<IoSlice<'_>>) -> Result<Request> {
    let mut hdr_bytes = [0u8; size_of::<Request>()];
    let mut filled = 0;
    let mut drain_count = 0;
    for buf in readable.iter_mut() {
        let need = hdr_bytes.len() - filled;
        if buf.len() <= need {
            hdr_bytes[filled..filled + buf.len()].copy_from_slice(buf);
            filled += buf.len();
            drain_count += 1;
            if filled == hdr_bytes.len() {
                break;
            }
        } else {
            hdr_bytes[filled..].copy_from_slice(&buf[..need]);
            buf.advance(need);
            filled = hdr_bytes.len();
            break;
        }
    }
    if filled < hdr_bytes.len() {
        return error::InvalidBuffer.fail();
    }
    readable.drain(..drain_count);
    readable.retain(|buf| !buf.is_empty());
    Request::read_from_bytes(&hdr_bytes).map_err(|_| error::InvalidBuffer.build())
}

/// Moves the 1-byte status at the end of the device-writable buffers into a
/// slice of its own.
fn isolate_status<'m>(writable: &mut Vec<IoSliceMut<'m>>) -> Result<()> {
    writable.retain(|buf| !buf.is_empty());
    let Some(last_len) = writable.last().map(|buf| buf.len()) else {
        return error::InvalidBuffer.fail();
    };
    if last_len > 1 {
        let mut last = writable.pop().unwrap();
        let ptr = last.as_mut_ptr();
        // SAFETY: `last` uniquely borrows `last_len` valid mutable bytes for `'m`
        // at `ptr`, and `last_len >= 2`. Consuming `last` and splitting at
        // `last_len - 1` yields two disjoint mutable slices in the same buffer.
        let (data_tail, status_slice) = unsafe {
            (
                IoSliceMut::new(slice::from_raw_parts_mut(ptr, last_len - 1)),
                IoSliceMut::new(slice::from_raw_parts_mut(ptr.add(last_len - 1), 1)),
            )
        };
        writable.push(data_tail);
        writable.push(status_slice);
    }
    Ok(())
}

/// Splits the device-writable buffers, after [`isolate_status`], into the data
/// and the status byte.
fn split_status<'d, 'm>(
    writable: &'d mut [IoSliceMut<'m>],
) -> Result<(&'d mut [IoSliceMut<'m>], &'d mut u8)> {
    let [data_in @ .., status_buf] = writable else {
        return error::InvalidBuffer.fail();
    };
    let [status] = &mut status_buf[..] else {
        return error::InvalidBuffer.fail();
    };
    Ok((data_in, status))
}

/// Returns the disk offset of `sector`, if the `data_len` bytes from there are
/// within `capacity` sectors.
fn sector_offset(sector: u64, data_len: usize, capacity: u64) -> Option<u64> {
    let offset = sector.checked_mul(SECTOR_SIZE as u64)?;
    let end = offset.checked_add(data_len as u64)?;
    // A driver MUST NOT read or write beyond the capacity (VirtIO spec 1.4,
    // Sec 5.2.6.1). Checking it also keeps a guest from extending the disk
    // image file.
    if end > capacity.saturating_mul(SECTOR_SIZE as u64) {
        return None;
    }
    Some(offset)
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
    pub fn new(spec: BlkFileSpec, name: impl Into<Arc<str>>) -> Result<Self> {
        let access_disk = error::AccessFile {
            path: spec.path.as_ref(),
        };
        let disk = OpenOptions::new()
            .read(true)
            .write(!spec.readonly)
            .open(&spec.path)
            .context(access_disk)?;

        let ctx_lock = error::LockFile {
            path: spec.path.as_ref(),
        };
        if spec.readonly {
            disk.try_lock_shared().context(ctx_lock)
        } else {
            disk.try_lock().context(ctx_lock)
        }?;

        let len = disk.metadata().context(access_disk)?.len();
        let config = BlockConfig {
            capacity: len / SECTOR_SIZE as u64,
            num_queues: 1,
            ..Default::default()
        };
        let config = Arc::new(config);
        let mut feature = BlockFeature::FLUSH;
        if spec.readonly {
            feature |= BlockFeature::RO;
        }
        Ok(Block {
            name: name.into(),
            disk,
            config,
            feature,
            api: spec.api,
        })
    }

    fn handle_desc<'d, 'm>(&self, desc: &'d mut DescChain<'m>) -> Result<BlkRequest<'d, 'm>> {
        let request = consume_header(&mut desc.readable)?;
        isolate_status(&mut desc.writable)?;
        if request.type_ == RequestType::FLUSH {
            // A driver SHOULD NOT include any data in a FLUSH request (VirtIO
            // spec 1.4, Sec 5.2.6.1). Drop it, so that it is neither checked
            // nor taken as transferred when the flush completes.
            desc.readable.clear();
            let status_index = desc.writable.len() - 1;
            desc.writable.drain(..status_index);
        }
        let (data_in, status) = split_status(&mut desc.writable)?;
        let data_out = &desc.readable[..];
        match request.type_ {
            RequestType::IN => {
                if !data_out.is_empty() {
                    return error::InvalidBuffer.fail();
                }
                let Some(total_len) = data_in
                    .iter()
                    .try_fold(0usize, |acc, buf| acc.checked_add(buf.len()))
                    .filter(|&len| len <= i32::MAX as usize)
                else {
                    return error::InvalidBuffer.fail();
                };
                let Some(offset) = sector_offset(request.sector, total_len, self.config.capacity)
                else {
                    log::error!(
                        "{}: invalid read sector {:#x}, len {total_len}",
                        self.name,
                        request.sector
                    );
                    *status = Status::IOERR.into();
                    return Ok(BlkRequest::Done { written: 1 });
                };
                if data_in.is_empty() {
                    *status = Status::OK.into();
                    return Ok(BlkRequest::Done { written: 1 });
                }
                Ok(BlkRequest::In {
                    data: data_in,
                    offset,
                    status,
                })
            }
            RequestType::OUT => {
                if !data_in.is_empty() {
                    return error::InvalidBuffer.fail();
                }
                let Some(total_len) = data_out
                    .iter()
                    .try_fold(0usize, |acc, buf| acc.checked_add(buf.len()))
                    .filter(|&len| len <= i32::MAX as usize)
                else {
                    return error::InvalidBuffer.fail();
                };
                if self.feature.contains(BlockFeature::RO) {
                    log::error!("{}: attempt to write to a read-only device", self.name);
                    *status = Status::IOERR.into();
                    return Ok(BlkRequest::Done { written: 1 });
                }
                let Some(offset) = sector_offset(request.sector, total_len, self.config.capacity)
                else {
                    log::error!(
                        "{}: invalid write sector {:#x}, len {total_len}",
                        self.name,
                        request.sector
                    );
                    *status = Status::IOERR.into();
                    return Ok(BlkRequest::Done { written: 1 });
                };
                if data_out.is_empty() {
                    *status = Status::OK.into();
                    return Ok(BlkRequest::Done { written: 1 });
                }
                Ok(BlkRequest::Out {
                    data: data_out,
                    offset,
                    status,
                })
            }
            RequestType::FLUSH => Ok(BlkRequest::Flush { status }),
            RequestType::GET_ID => {
                if !data_out.is_empty() {
                    return error::InvalidBuffer.fail();
                }
                let mut id = [0u8; VIRTIO_BLK_ID_SIZE];
                let len = self.name.len().min(VIRTIO_BLK_ID_SIZE);
                id[..len].copy_from_slice(&self.name.as_bytes()[..len]);
                let count = (&id[..]).read_vectored(data_in)? as u32;
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

    fn read_at(&self, data: &mut [IoSliceMut<'_>], mut offset: u64) -> IoResult<u32> {
        let mut total = 0u32;
        for buf in data {
            self.disk.read_exact_at(buf, offset)?;
            offset = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| IoError::from(ErrorKind::InvalidInput))?;
            total += buf.len() as u32;
        }
        Ok(total)
    }

    fn write_at(&self, data: &[IoSlice<'_>], mut offset: u64) -> IoResult<()> {
        for buf in data {
            self.disk.write_all_at(buf, offset)?;
            offset = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| IoError::from(ErrorKind::InvalidInput))?;
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    fn complete_io(&self, q_index: u16, chain: &mut DescChain, result: i32) -> Result<u32> {
        let (data_in, status) = split_status(&mut chain.writable)?;
        if result < 0 {
            let err = IoError::from_raw_os_error(result.saturating_neg());
            log::error!("{}: queue-{q_index} io error: {err}", self.name);
            *status = Status::IOERR.into();
            return Ok(1);
        }
        let transferred = result as usize;
        let in_len: usize = data_in.iter().map(|buf| buf.len()).sum();
        let out_len: usize = chain.readable.iter().map(|buf| buf.len()).sum();
        if in_len > 0 {
            if transferred != in_len {
                log::error!(
                    "{}: queue-{q_index} short read: {transferred} of {in_len} bytes",
                    self.name
                );
                *status = Status::IOERR.into();
                Ok(1)
            } else {
                *status = Status::OK.into();
                Ok(in_len as u32 + 1)
            }
        } else if out_len > 0 {
            if transferred != out_len {
                log::error!(
                    "{}: queue-{q_index} short write: {transferred} of {out_len} bytes",
                    self.name
                );
                *status = Status::IOERR.into();
            } else {
                *status = Status::OK.into();
            }
            Ok(1)
        } else {
            *status = Status::OK.into();
            Ok(1)
        }
    }
}

impl Virtio for Block {
    type Config = BlockConfig;
    type Feature = BlockFeature;

    fn id(&self) -> DeviceId {
        DeviceId::BLOCK
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

    fn spawn_worker<S>(self, param: WorkerParam<S>) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
    {
        match self.api {
            #[cfg(target_os = "linux")]
            WorkerApi::IoUring => IoUring::spawn_worker(self, param),
            WorkerApi::Mio => Mio::spawn_worker(self, param),
        }
    }
}

impl VirtioMio for Block {
    fn reset(&mut self, _registry: &Registry) {}

    fn activate<Q, S>(
        &mut self,
        _feature: u128,
        _active_mio: &mut ActiveMio<'_, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue,
        S: IrqSender,
    {
        Ok(())
    }

    fn handle_event<'a, Q, S>(
        &mut self,
        _event: &Event,
        _active_mio: &mut ActiveMio<'_, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue,
        S: IrqSender,
    {
        Ok(())
    }

    fn handle_queue<Q, S>(&mut self, index: u16, active_mio: &mut ActiveMio<'_, Q, S>) -> Result<()>
    where
        Q: VirtQueue,
        S: IrqSender,
    {
        let Some(Some(queue)) = active_mio.queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        let mut disk = &self.disk;
        queue.handle_desc(index, active_mio.irq_sender, |chain| {
            let written_len = match Block::handle_desc(self, chain)? {
                BlkRequest::Done { written } => written,
                BlkRequest::In {
                    data,
                    offset,
                    status,
                } => match self.read_at(data, offset) {
                    Ok(total) => {
                        *status = Status::OK.into();
                        total + 1
                    }
                    Err(e) => {
                        log::error!("{}: read: {e}", self.name);
                        *status = Status::IOERR.into();
                        1
                    }
                },
                BlkRequest::Out {
                    data,
                    offset,
                    status,
                } => {
                    match self.write_at(data, offset) {
                        Ok(()) => *status = Status::OK.into(),
                        Err(e) => {
                            log::error!("{}: write: {e}", self.name);
                            *status = Status::IOERR.into();
                        }
                    }
                    1
                }
                BlkRequest::Flush { status } => {
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
    fn activate<Q, S>(&mut self, _feature: u128, _ring: &mut ActiveIoUring<'_, Q, S>) -> Result<()>
    where
        S: IrqSender,
        Q: VirtQueue,
    {
        Ok(())
    }

    fn handle_desc(&mut self, _q_index: u16, chain: &mut DescChain) -> Result<BufferAction> {
        let fd = Fd(self.disk.as_raw_fd());
        let action = match Block::handle_desc(self, chain)? {
            BlkRequest::Done { written } => BufferAction::Written(written),
            BlkRequest::In { data, offset, .. } => {
                let read = opcode::Readv::new(fd, data.as_ptr().cast(), data.len() as u32)
                    .offset(offset)
                    .build();
                BufferAction::Sqe(read)
            }
            BlkRequest::Out { data, offset, .. } => {
                let write = opcode::Writev::new(fd, data.as_ptr().cast(), data.len() as u32)
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
        self.complete_io(q_index, chain, cqe.result())
    }
}

#[cfg(test)]
#[path = "blk_test.rs"]
mod tests;
