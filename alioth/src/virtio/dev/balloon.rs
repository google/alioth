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
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::JoinHandle;

use bitflags::bitflags;
use libc::{sysconf, _SC_PAGESIZE};
use macros::Layout;
use mio::event::Event;
use mio::Registry;
use parking_lot::RwLock;
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::hv::IoeventFd;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{Ram, RamBus};
use crate::virtio::dev::{DevParam, DeviceId, Virtio, WakeEvent};
use crate::virtio::queue::handlers::handle_desc;
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::worker::Waker;
use crate::virtio::{IrqSender, Result, FEATURE_BUILT_IN};
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
    pub struct BalloonFeature: u64 {
        const MUST_TELL_HOST = 1 << 0;
        const STATS_VQ = 1 << 1;
        const DEFLATE_ON_OOM = 1 << 2;
        const FREE_PAGE_HINT = 1 << 3;
        const PAGE_POISON = 1 << 4;
        const REPORTING = 1 << 5;
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

const VQ_INFLATE: u16 = 0;
const VQ_DEFLATE: u16 = 1;
const VQ_STATES: u16 = 2;
const VQ_FREE_PAGE: u16 = 3;
const VQ_REPORTING: u16 = 4;

#[derive(Debug)]
pub struct Balloon {
    name: Arc<str>,
    config: Arc<BalloonConfigMmio>,
}

impl Balloon {
    pub fn new(_param: BalloonParam, name: impl Into<Arc<str>>) -> Result<Self> {
        if unsafe { sysconf(_SC_PAGESIZE) } != 1 << 12 {
            let err = std::io::ErrorKind::Unsupported;
            Err(std::io::Error::from(err))?;
        }
        let config = BalloonConfig {
            num_pages: 0,
            ..Default::default()
        };
        let name = name.into();
        Ok(Balloon {
            name: name.clone(),
            config: Arc::new(BalloonConfigMmio {
                config: RwLock::new(config),
                name,
            }),
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
    const DEVICE_ID: DeviceId = DeviceId::Balloon;

    type Config = BalloonConfigMmio;
    type Feature = BalloonFeature;

    fn name(&self) -> &str {
        &self.name
    }

    fn spawn_worker<S, E>(
        self,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
        fds: Arc<[(E, bool)]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs, fds)
    }

    fn num_queues(&self) -> u16 {
        5
    }

    fn config(&self) -> Arc<BalloonConfigMmio> {
        self.config.clone()
    }

    fn feature(&self) -> u64 {
        FEATURE_BUILT_IN | BalloonFeature::all().bits()
    }
}

impl VirtioMio for Balloon {
    fn activate<'a, 'm, Q: VirtQueue<'m>, S: IrqSender>(
        &mut self,
        _feature: u64,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S>,
    ) -> Result<()> {
        Ok(())
    }

    fn handle_queue<'a, 'm, Q: VirtQueue<'m>, S: IrqSender>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'a, 'm, Q, S>,
    ) -> Result<()> {
        let Some(Some(queue)) = active_mio.queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        match index {
            VQ_STATES => {
                log::info!("{}: VQ_STATES avaibale", self.name);
                return Ok(());
            }
            VQ_FREE_PAGE => {
                log::info!("{}: VQ_FREE_PAGE avaibale", self.name);
                return Ok(());
            }
            _ => {}
        };
        handle_desc(&self.name, index, queue, active_mio.irq_sender, |desc| {
            match index {
                VQ_INFLATE => self.inflate(&desc.readable, active_mio.mem),
                VQ_DEFLATE => {
                    log::info!("{}: VQ_DEFLATE available", self.name);
                }
                VQ_REPORTING => self.free_reporting(&mut desc.writable),
                _ => log::error!("{}: invalid queue index {index}", self.name),
            }
            Ok(Some(0))
        })
    }

    fn handle_event<'a, 'm, Q: VirtQueue<'m>, S: IrqSender>(
        &mut self,
        _event: &Event,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S>,
    ) -> Result<()> {
        Ok(())
    }

    fn reset(&mut self, _registry: &Registry) {}
}

#[derive(Debug, Clone, Deserialize, Help, Default)]
pub struct BalloonParam {}

impl DevParam for BalloonParam {
    type Device = Balloon;
    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        Balloon::new(self, name)
    }
}
