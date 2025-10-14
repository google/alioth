// Copyright 2025 Google LLC
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

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use bitflags::bitflags;
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use zerocopy::IntoBytes;

use crate::errors::BoxTrace;
use crate::hv::IoeventFd;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::mem::{LayoutChanged, MemRegion};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{DevParam, Virtio, WakeEvent};
use crate::virtio::queue::{QueueReg, VirtQueue};
use crate::virtio::vu::bindings::{
    DeviceConfig, MemoryRegion, MemorySingleRegion, VirtqAddr, VirtqState, VuFeature,
};
use crate::virtio::vu::conn::{VuChannel, VuSession};
use crate::virtio::vu::error as vu_error;
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DevStatus, DeviceId, IrqSender, Result, VirtioFeature, error};
use crate::{ffi, mem};

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VuDevFeature: u128 { }
}

#[derive(Debug)]
pub struct UpdateVuMem {
    pub name: Arc<str>,
    pub session: Arc<VuSession>,
}

impl LayoutChanged for UpdateVuMem {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((fd, offset)) = pages.fd() else {
            return Ok(());
        };
        let region = MemorySingleRegion {
            _padding: 0,
            region: MemoryRegion {
                gpa: gpa as _,
                size: pages.size() as _,
                hva: pages.addr() as _,
                mmap_offset: offset,
            },
        };
        let ret = self.session.add_mem_region(&region, fd);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!("{}: add memory region: {:x?}", self.name, region.region);
        Ok(())
    }

    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> mem::Result<()> {
        let Some((_, offset)) = pages.fd() else {
            return Ok(());
        };
        let region = MemorySingleRegion {
            _padding: 0,
            region: MemoryRegion {
                gpa: gpa as _,
                size: pages.size() as _,
                hva: pages.addr() as _,
                mmap_offset: offset,
            },
        };
        let ret = self.session.remove_mem_region(&region);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!("{}: remove memory region: {:x?}", self.name, region.region);
        Ok(())
    }
}

#[derive(Debug)]
pub struct VuDevConfig {
    session: Arc<VuSession>,
}

impl Mmio for VuDevConfig {
    fn size(&self) -> u64 {
        256
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let req = DeviceConfig {
            offset: offset as u32,
            size: size as u32,
            flags: 0,
        };
        let mut ret = 0u64;
        let buf = &mut ret.as_mut_bytes()[..size as usize];
        self.session
            .get_config(&req, buf)
            .box_trace(mem::error::Mmio)?;
        Ok(ret)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let req = DeviceConfig {
            offset: offset as u32,
            size: size as u32,
            flags: 0,
        };
        let buf = &val.as_bytes()[..size as usize];
        self.session
            .set_config(&req, buf)
            .box_trace(mem::error::Mmio)?;
        Ok(Action::None)
    }
}

#[derive(Debug)]
pub struct VuFrontend {
    name: Arc<str>,
    session: Arc<VuSession>,
    channel: Option<VuChannel>,
    id: DeviceId,
    vu_feature: VuFeature,
    device_feature: u64,
    num_queues: u16,
    err_fds: Box<[OwnedFd]>,
}

impl VuFrontend {
    pub fn new<P>(
        name: impl Into<Arc<str>>,
        socket: P,
        id: DeviceId,
        extra_feat: VuFeature,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let name = name.into();
        let session = Arc::new(VuSession::new(socket)?);

        let device_feature = session.get_features()?;
        let feat = VirtioFeature::from_bits_retain(device_feature as u128);
        log::trace!("{name}: get device feature: {feat:x?}");
        let need_feat = VirtioFeature::VHOST_PROTOCOL | VirtioFeature::VERSION_1;
        if !feat.contains(need_feat) {
            return vu_error::DeviceFeature {
                feature: need_feat.bits(),
            }
            .fail()?;
        }

        let protocol_feat = VuFeature::from_bits_retain(session.get_protocol_features()?);
        log::trace!("{name}: get protocol feature: {protocol_feat:x?}");
        let need_feat =
            VuFeature::MQ | VuFeature::REPLY_ACK | VuFeature::CONFIGURE_MEM_SLOTS | extra_feat;
        if !protocol_feat.contains(need_feat) {
            return vu_error::ProtocolFeature {
                feature: need_feat & !protocol_feat,
            }
            .fail()?;
        }

        let mut vu_feature = need_feat;
        if protocol_feat.contains(VuFeature::STATUS) {
            vu_feature |= VuFeature::STATUS
        };
        session.set_protocol_features(&vu_feature.bits())?;
        log::trace!("{name}: set protocol feature: {vu_feature:x?}");

        let num_queues = session.get_queue_num()? as u16;
        log::trace!("{name}: get queue number: {num_queues}");

        let channel = if vu_feature.contains(VuFeature::BACKEND_REQ) {
            Some(session.create_channel()?)
        } else {
            None
        };

        let mut err_fds = vec![];
        for index in 0..num_queues {
            let raw_fd = ffi!(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            session.set_virtq_err(&(index as u64), fd.as_fd())?;
            log::trace!("{name}: queue-{index}: set error fd: {}", fd.as_raw_fd());
            err_fds.push(fd);
        }

        session.set_owner()?;
        log::trace!("{name}: set owner");

        Ok(VuFrontend {
            name,
            session,
            channel,
            id,
            vu_feature,
            device_feature,
            num_queues,
            err_fds: err_fds.into(),
        })
    }

    pub fn session(&self) -> &VuSession {
        &self.session
    }

    pub fn channel(&self) -> Option<&VuChannel> {
        self.channel.as_ref()
    }
}

impl Virtio for VuFrontend {
    type Config = VuDevConfig;
    type Feature = VuDevFeature;

    fn id(&self) -> DeviceId {
        self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_queues(&self) -> u16 {
        self.num_queues
    }

    fn config(&self) -> Arc<Self::Config> {
        assert!(self.vu_feature.contains(VuFeature::CONFIG));
        Arc::new(VuDevConfig {
            session: self.session.clone(),
        })
    }

    fn feature(&self) -> u128 {
        self.device_feature as u128
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

    fn ioeventfd_offloaded(&self, q_index: u16) -> Result<bool> {
        if q_index < self.num_queues {
            Ok(true)
        } else {
            error::InvalidQueueIndex { index: q_index }.fail()
        }
    }

    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }

    fn mem_change_callback(&self) -> Option<Box<dyn LayoutChanged>> {
        Some(Box::new(UpdateVuMem {
            name: self.name.clone(),
            session: self.session.clone(),
        }))
    }
}

impl VirtioMio for VuFrontend {
    fn activate<'m, Q, S, E>(
        &mut self,
        feature: u128,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let name = &*self.name;
        self.session
            .set_features(&((feature | VirtioFeature::VHOST_PROTOCOL.bits()) as u64))?;
        log::trace!("{name}: set driver feature: {feature:x?}");

        for (index, fd) in active_mio.ioeventfds.iter().enumerate() {
            self.session.set_virtq_kick(&(index as u64), fd.as_fd())?;
            let raw_fd = fd.as_fd().as_raw_fd();
            log::trace!("{name}: queue-{index}: set kick fd: {raw_fd}");
        }

        for (index, queue) in active_mio.queues.iter().enumerate() {
            let Some(queue) = queue else {
                log::trace!("{name}: queue-{index} is disabled");
                continue;
            };
            let reg = queue.reg();

            let _ = active_mio.irq_sender.queue_irqfd(index as _, |fd| {
                self.session.set_virtq_call(&(index as u64), fd)?;
                log::trace!("{name}: queue-{index}: set call fd: {}", fd.as_raw_fd());
                Ok(())
            });

            let virtq_num = VirtqState {
                index: index as _,
                val: reg.size.load(Ordering::Acquire) as _,
            };
            self.session.set_virtq_num(&virtq_num)?;
            log::trace!("{name}: queue-{index}: set size: {}", virtq_num.val);

            let virtq_base = VirtqState {
                index: index as _,
                val: 0,
            };
            self.session.set_virtq_base(&virtq_base)?;
            log::trace!("{name}: queue-{index}: set base: {}", virtq_base.val);

            let mem = active_mio.mem;
            let virtq_addr = VirtqAddr {
                index: index as _,
                flags: 0,
                desc_hva: mem.translate(reg.desc.load(Ordering::Acquire) as _)? as _,
                used_hva: mem.translate(reg.device.load(Ordering::Acquire) as _)? as _,
                avail_hva: mem.translate(reg.driver.load(Ordering::Acquire) as _)? as _,
                log_guest_addr: 0,
            };
            self.session.set_virtq_addr(&virtq_addr)?;
            log::trace!("{name}: queue-{index}: set addr: {virtq_addr:x?}");

            let virtq_enable = VirtqState {
                index: index as _,
                val: 1,
            };
            self.session.set_virtq_enable(&virtq_enable)?;
            log::trace!("{name}: queue-{index}: set enabled: {}", virtq_enable.val);
        }

        for (index, fd) in self.err_fds.iter().enumerate() {
            active_mio.poll.registry().register(
                &mut SourceFd(&fd.as_raw_fd()),
                Token(index),
                Interest::READABLE,
            )?;
        }

        if self.vu_feature.contains(VuFeature::STATUS) {
            let dev_status = DevStatus::from_bits_retain(0xf);
            self.session.set_status(&(dev_status.bits() as u64))?;
            log::trace!("{name}: set status: {dev_status:x?}");
        }
        Ok(())
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        _: &Event,
        _: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        unreachable!()
    }

    fn handle_queue<'m, Q, S, E>(
        &mut self,
        index: u16,
        _: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        unreachable!(
            "{}: queue {index} notification should go to vhost-user backend",
            self.name
        )
    }

    fn reset(&mut self, registry: &Registry) {
        let name = &*self.name;
        for index in 0..self.num_queues {
            let disable = VirtqState {
                index: index as _,
                val: 0,
            };
            if let Err(e) = self.session.set_virtq_enable(&disable) {
                log::error!("{name}: failed to disable queue-{index}: {e:?}")
            }
        }
        if self.vu_feature.contains(VuFeature::STATUS)
            && let Err(e) = self.session.set_status(&0)
        {
            log::error!("{name}: failed to reset device status: {e:?}");
        }
        for (index, fd) in self.err_fds.iter().enumerate() {
            if let Err(e) = registry.deregister(&mut SourceFd(&fd.as_raw_fd())) {
                log::error!("{name}: queue-{index}: failed to deregister error fd: {e:?}");
            }
        }
        if let Some(channel) = &self.channel {
            let channel_fd = channel.conn.as_fd();
            if let Err(e) = registry.deregister(&mut SourceFd(&channel_fd.as_raw_fd())) {
                log::error!("{name}: failed to deregister backend channel fd: {e:?}")
            }
        }
    }
}

pub struct VuFrontendParam {
    pub socket: PathBuf,
    pub id: DeviceId,
}

impl DevParam for VuFrontendParam {
    type Device = VuFrontend;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        VuFrontend::new(name, self.socket, self.id, VuFeature::CONFIG)
    }

    fn needs_mem_shared_fd(&self) -> bool {
        true
    }
}
