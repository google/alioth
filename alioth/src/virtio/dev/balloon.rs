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
use std::io::{IoSlice, IoSliceMut};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use alioth_macros::Layout;
use bitflags::bitflags;
use libc::{_SC_PAGESIZE, sysconf};
use mio::Registry;
use mio::event::Event;
use parking_lot::RwLock;
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::hv::IoeventFd;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{Ram, RamBus};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{DevParam, DeviceId, Virtio, WakeEvent};
use crate::virtio::queue::{QueueReg, Status, VirtQueue};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{FEATURE_BUILT_IN, IrqSender, Result};
use crate::{c_enum, ffi, impl_mmio_for_zerocopy, mem};

#[repr(C, align(8))]
#[derive(Debug, Clone, Default, FromBytes, IntoBytes, Immutable, Layout)]
pub struct BalloonConfig {
    num_pages: u32,
    actual: u32,
    free_page_hint_cmd_id: u32,
    poison_val: u32,
}

impl_mmio_for_zerocopy!(BalloonConfig);

#[derive(Debug)]
pub struct BalloonConfigMmio {
    name: Arc<str>,
    config: RwLock<BalloonConfig>,
}

impl Mmio for BalloonConfigMmio {
    fn size(&self) -> u64 {
        size_of::<BalloonConfig>() as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let config = self.config.read();
        Mmio::read(&*config, offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let config = &mut *self.config.write();
        match (offset as usize, size as usize) {
            BalloonConfig::LAYOUT_ACTUAL => {
                config.actual = val as u32;
                log::info!(
                    "{}: update: num_pages = {:#x}, actual = {val:#x}",
                    self.name,
                    config.num_pages,
                );
                Ok(Action::None)
            }
            _ => Mmio::write(config, offset, size, val),
        }
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BalloonFeature: u128 {
        const MUST_TELL_HOST = 1 << 0;
        const STATS_VQ = 1 << 1;
        const DEFLATE_ON_OOM = 1 << 2;
        const FREE_PAGE_HINT = 1 << 3;
        const PAGE_POISON = 1 << 4;
        const PAGE_REPORTING = 1 << 5;
    }
}

c_enum! {
    pub struct BalloonStats(u16);
    {
        SWAP_IN = 0;
        SWAP_OUT = 1;
        MAJFLT = 2;
        MINFLT = 3;
        MEMFREE = 4;
        MEMTOT = 5;
        AVAIL = 6;
        CACHES = 7;
        HTLB_PGALLOC = 8;
        HTLB_PGFAIL = 9;
    }
}

#[derive(Debug, Clone, Copy)]
enum BalloonQueue {
    Inflate,
    Deflate,
    Stats,
    FreePage,
    Reporting,
    NotExist,
}

#[derive(Debug)]
pub struct Balloon {
    name: Arc<str>,
    config: Arc<BalloonConfigMmio>,
    feature: BalloonFeature,
    queues: [BalloonQueue; 5],
}

impl Balloon {
    pub fn new(param: BalloonParam, name: impl Into<Arc<str>>) -> Result<Self> {
        if unsafe { sysconf(_SC_PAGESIZE) } != 1 << 12 {
            let err = std::io::ErrorKind::Unsupported;
            Err(std::io::Error::from(err))?;
        }
        let config = BalloonConfig {
            num_pages: 0,
            ..Default::default()
        };
        let mut feature = BalloonFeature::all();
        if !param.free_page_reporting {
            feature.remove(BalloonFeature::PAGE_REPORTING);
        };
        let name = name.into();
        Ok(Balloon {
            name: name.clone(),
            config: Arc::new(BalloonConfigMmio {
                config: RwLock::new(config),
                name,
            }),
            feature,
            queues: [BalloonQueue::NotExist; 5],
        })
    }

    fn inflate(&self, desc: &[IoSlice], ram: &Ram) {
        for buf in desc {
            for bytes in buf.chunks(size_of::<u32>()) {
                let Ok(page_num) = u32::read_from_bytes(bytes) else {
                    log::error!(
                        "{}: inflate: invalid page_num bytes: {bytes:02x?}",
                        self.name
                    );
                    continue;
                };
                let gpa = (page_num as u64) << 12;
                if let Err(e) = ram.madvise(gpa, 1 << 12, libc::MADV_DONTNEED) {
                    log::error!("{}: inflate at GPA {gpa:#x}: {e:?}", self.name);
                } else {
                    log::trace!("{}: freed GPA {gpa:#x}", self.name);
                }
            }
        }
    }

    fn free_reporting(&self, desc: &mut [IoSliceMut]) {
        for buf in desc.iter_mut() {
            let addr = buf.as_mut_ptr();
            let len = buf.len();
            let ret = ffi!(unsafe { libc::madvise(addr as _, len, libc::MADV_DONTNEED) });
            if let Err(e) = ret {
                log::error!("freeing pages: {addr:p} {len:#x}: {e:?}");
            } else {
                log::trace!("freed pages: {addr:p} {len:#x}");
            }
        }
    }
}

impl Virtio for Balloon {
    type Config = BalloonConfigMmio;
    type Feature = BalloonFeature;

    fn id(&self) -> DeviceId {
        DeviceId::Balloon
    }

    fn name(&self) -> &str {
        &self.name
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
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }

    fn num_queues(&self) -> u16 {
        self.queues.len() as u16
    }

    fn config(&self) -> Arc<BalloonConfigMmio> {
        self.config.clone()
    }

    fn feature(&self) -> u128 {
        FEATURE_BUILT_IN | self.feature.bits()
    }
}

impl VirtioMio for Balloon {
    fn activate<'m, Q, S, E>(
        &mut self,
        feature: u128,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let feature = BalloonFeature::from_bits_retain(feature);
        self.queues[0] = BalloonQueue::Inflate;
        self.queues[1] = BalloonQueue::Deflate;
        let mut index = 2;
        if feature.contains(BalloonFeature::STATS_VQ) {
            self.queues[index] = BalloonQueue::Stats;
            index += 1;
        }
        if feature.contains(BalloonFeature::FREE_PAGE_HINT) {
            self.queues[index] = BalloonQueue::FreePage;
            index += 1;
        }
        if feature.contains(BalloonFeature::PAGE_REPORTING) {
            self.queues[index] = BalloonQueue::Reporting;
        }
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
        let Some(&ballon_q) = self.queues.get(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        match ballon_q {
            BalloonQueue::Stats => {
                log::info!("{}: VQ_STATES available", self.name);
                return Ok(());
            }
            BalloonQueue::FreePage => {
                log::info!("{}: VQ_FREE_PAGE available", self.name);
                return Ok(());
            }
            _ => {}
        };
        queue.handle_desc(index, active_mio.irq_sender, |chain| {
            match ballon_q {
                BalloonQueue::Inflate => self.inflate(&chain.readable, active_mio.mem),
                BalloonQueue::Deflate => {
                    log::info!("{}: VQ_DEFLATE available", self.name);
                }
                BalloonQueue::Reporting => self.free_reporting(&mut chain.writable),
                BalloonQueue::Stats | BalloonQueue::FreePage => todo!(),
                BalloonQueue::NotExist => log::error!("{}: invalid queue index {index}", self.name),
            }
            Ok(Status::Done { len: 0 })
        })
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

    fn reset(&mut self, _registry: &Registry) {
        self.queues = [BalloonQueue::NotExist; 5];
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Help)]
pub struct BalloonParam {
    /// Enable free page reporting. [default: false]
    #[serde(default)]
    pub free_page_reporting: bool,
}

impl DevParam for BalloonParam {
    type Device = Balloon;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        Balloon::new(self, name)
    }
}
