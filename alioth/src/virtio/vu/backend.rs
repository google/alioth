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

use std::cmp::min;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::iter::zip;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use alioth_macros::trace_error;
use snafu::Snafu;
use zerocopy::IntoBytes;

use crate::errors::DebugTrace;
use crate::hv::IoeventFd;
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::virtio::dev::{StartParam, VirtioDevice, WakeEvent};
use crate::virtio::vu::Error as VuError;
use crate::virtio::vu::bindings::{
    MAX_CONFIG_SIZE, MemoryRegion, MemorySingleRegion, Message, VirtqAddr, VirtqState, VuFeature,
    VuFrontMsg,
};
use crate::virtio::vu::conn::{VuChannel, VuSession};
use crate::virtio::{self, DevStatus, IrqSender, VirtioFeature};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Failed to access guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("vhost-user protocol error"), context(false))]
    Vu {
        source: Box<crate::virtio::vu::Error>,
    },
    #[snafu(display("failed to parse the payload of {req:?}"))]
    Parse { req: VuFrontMsg },
    #[snafu(display("frontend requested invalid queue index: {index}"))]
    InvalidQueue { index: u16 },
    #[snafu(display("{req:?} did not contain an FD"))]
    MissingFd { req: VuFrontMsg },
    #[snafu(display("frontend did not set size for queue {index}"))]
    MissingSize { index: u16 },
    #[snafu(display("frontend did not set addresses for queue {index}"))]
    MissingAddr { index: u16 },
    #[snafu(display("frontend did not set ioeventfd for queue {index}"))]
    MissingIoeventfd { index: u16 },
    #[snafu(display("cannot convert frontend HVA {hva:#x} to GPA"))]
    Convert { hva: u64 },
    #[snafu(display("invalid message {req:?} with payload size {size}"))]
    InvalidMsg { req: VuFrontMsg, size: u32 },
    #[snafu(display("Cannot change memory layout at runtime"))]
    ChangeMemoryLayout,
    #[snafu(display("Failed to send backend request channel to device"))]
    SendChannel,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct VuIrqSender {
    queues: Box<[Option<File>]>,
}

impl VuIrqSender {
    fn signal_irqfd(&self, mut fd: &File) {
        if let Err(e) = fd.write(1u64.as_bytes()) {
            log::error!("failed to signal irqfd: {e:?}");
        }
    }
}

impl IrqSender for VuIrqSender {
    fn config_irq(&self) {
        // TODO: investigate VHOST_USER_BACKEND_CONFIG_CHANGE_MSG
        log::error!("config irqfd is not available");
    }

    fn queue_irq(&self, idx: u16) {
        let Some(queue) = self.queues.get(idx as usize) else {
            log::error!("invalid queue index: {idx}");
            return;
        };
        let Some(fd) = queue.as_ref() else {
            log::error!("queue-{idx} irqfd is not available");
            return;
        };
        self.signal_irqfd(fd);
    }

    fn config_irqfd<F, T>(&self, _: F) -> virtio::Result<T>
    where
        F: FnOnce(BorrowedFd) -> virtio::Result<T>,
    {
        unreachable!()
    }

    fn queue_irqfd<F, T>(&self, _: u16, _: F) -> virtio::Result<T>
    where
        F: FnOnce(BorrowedFd) -> virtio::Result<T>,
    {
        unreachable!()
    }
}

#[derive(Debug)]
pub struct VuEventfd {
    fd: File,
}

impl AsFd for VuEventfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl IoeventFd for VuEventfd {}

#[derive(Debug, Default)]
struct VuQueueInit {
    enable: bool,
    size: Option<u16>,
    addr: Option<VirtqAddr>,
    ioeventfd: Option<File>,
    irqfd: Option<File>,
    errfd: Option<File>,
}

#[derive(Debug)]
struct VuInit {
    drv_feat: u64,
    queues: Box<[VuQueueInit]>,
    regions: Vec<MemoryRegion>,
}

pub struct VuBackend {
    session: VuSession,
    channel: Option<Arc<VuChannel>>,
    status: DevStatus,
    memory: Arc<RamBus>,
    dev: VirtioDevice<VuIrqSender, VuEventfd>,
    init: VuInit,
}

impl VuBackend {
    pub fn new(
        conn: UnixStream,
        dev: VirtioDevice<VuIrqSender, VuEventfd>,
        memory: Arc<RamBus>,
    ) -> Result<Self> {
        conn.set_nonblocking(false)?;
        let queue_num = dev.queue_regs.len();
        Ok(VuBackend {
            session: VuSession { conn },
            channel: None,
            dev,
            memory,
            status: DevStatus::empty(),
            init: VuInit {
                drv_feat: 0,
                queues: (0..queue_num).map(|_| VuQueueInit::default()).collect(),
                regions: vec![],
            },
        })
    }

    pub fn name(&self) -> &str {
        self.dev.name.as_ref()
    }

    fn wake_up_dev(&self, event: WakeEvent<VuIrqSender, VuEventfd>) {
        let is_start = matches!(event, WakeEvent::Start { .. });
        if let Err(e) = self.dev.event_tx.send(event) {
            log::error!("{}: failed to send event: {e}", self.dev.name);
            return;
        }
        if is_start {
            return;
        }
        if let Err(e) = self.dev.notifier.notify() {
            log::error!("{}: failed to wake up device: {e}", self.dev.name);
        }
    }

    fn convert_frontend_hva(&self, hva: u64) -> Result<u64> {
        for r in &self.init.regions {
            if hva >= r.hva && hva < r.hva + r.size {
                return Ok(r.gpa + (hva - r.hva));
            }
        }
        error::Convert { hva }.fail()
    }

    fn parse_init(&mut self) -> Result<StartParam<VuIrqSender, VuEventfd>> {
        for (index, (param, queue)) in zip(&self.init.queues, &*self.dev.queue_regs).enumerate() {
            let index = index as u16;
            queue.enabled.store(param.enable, Ordering::Release);
            if !param.enable {
                continue;
            }

            let Some(size) = param.size else {
                return error::MissingSize { index }.fail();
            };
            queue.size.store(size, Ordering::Release);

            let Some(addr) = &param.addr else {
                return error::MissingAddr { index }.fail();
            };

            let desc_gpa = self.convert_frontend_hva(addr.desc_hva)?;
            queue.desc.store(desc_gpa, Ordering::Release);

            let dev_gpa = self.convert_frontend_hva(addr.used_hva)?;
            queue.device.store(dev_gpa, Ordering::Release);

            let drv_gpa = self.convert_frontend_hva(addr.avail_hva)?;
            queue.driver.store(drv_gpa, Ordering::Release);
        }

        let queues = &mut self.init.queues;

        let queue_irqfds = queues.iter_mut().map(|q| q.irqfd.take()).collect();
        let irq_sender = VuIrqSender {
            queues: queue_irqfds,
        };

        let mut ioeventfds = vec![];
        for (index, q) in queues.iter_mut().enumerate() {
            match q.ioeventfd.take() {
                Some(fd) => ioeventfds.push(VuEventfd { fd }),
                None => {
                    let index = index as u16;
                    return error::MissingIoeventfd { index }.fail();
                }
            }
        }

        Ok(StartParam {
            feature: self.init.drv_feat as u128,
            irq_sender: Arc::new(irq_sender),
            ioeventfds: Some(ioeventfds.into()),
        })
    }

    fn handle_msg(&mut self, msg: &mut Message, fds: &mut [Option<OwnedFd>; 8]) -> Result<()> {
        let name = &*self.dev.name;
        let (req, size) = (VuFrontMsg::from(msg.request), msg.size);

        match (req, size) {
            (VuFrontMsg::GET_PROTOCOL_FEATURES, 0) => {
                let feature = VuFeature::MQ
                    | VuFeature::REPLY_ACK
                    | VuFeature::CONFIGURE_MEM_SLOTS
                    | VuFeature::BACKEND_REQ
                    | VuFeature::BACKEND_SEND_FD
                    | VuFeature::CONFIG
                    | VuFeature::STATUS;
                self.session.reply(req, &feature.bits(), &[])?;
                msg.flag.set_need_reply(false);
                log::debug!("{name}: get protocol feature: {feature:x?}");
            }
            (VuFrontMsg::SET_PROTOCOL_FEATURES, 8) => {
                let feature: u64 = self.session.recv_payload()?;
                let feature = VuFeature::from_bits_retain(feature);
                log::debug!("{name}: set protocol feature: {feature:x?}");
            }
            (VuFrontMsg::GET_FEATURES, 0) => {
                let feature = self.dev.device_feature | VirtioFeature::VHOST_PROTOCOL.bits();
                self.session.reply(req, &feature, &[])?;
                msg.flag.set_need_reply(false);
                log::debug!("{name}: get device feature: {feature:#x}");
            }
            (VuFrontMsg::SET_FEATURES, 8) => {
                self.init.drv_feat = self.session.recv_payload()?;
                log::debug!("{name}: set driver feature: {:#x}", self.init.drv_feat);
            }
            (VuFrontMsg::SET_OWNER, 0) => {
                log::trace!("{name}: set owner");
            }
            (VuFrontMsg::GET_QUEUE_NUM, 0) => {
                let count = self.init.queues.len() as u64;
                self.session.reply(req, &count, &[])?;
                log::debug!("{name}: get queue number: {count}");
                msg.flag.set_need_reply(false);
            }
            (VuFrontMsg::SET_BACKEND_REQ_FD, 0) => {
                let Some(fd) = fds[0].take() else {
                    return error::MissingFd { req }.fail()?;
                };
                log::trace!("{name}: set backend request fd: {}", fd.as_raw_fd());
                let channel = Arc::new(VuChannel {
                    conn: UnixStream::from(fd),
                });
                let r = self.dev.event_tx.send(WakeEvent::VuChannel {
                    channel: channel.clone(),
                });
                if r.is_err() {
                    return error::SendChannel.fail();
                }
                self.channel = Some(channel);
            }
            (VuFrontMsg::SET_VIRTQ_ERR, 8) => {
                let index = self.session.recv_payload::<u64>()? as u16;
                let Some(fd) = fds[0].take() else {
                    return error::MissingFd { req: msg.request }.fail();
                };
                let Some(q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                log::debug!("{name}: queue-{index}: set error fd: {}", fd.as_raw_fd());
                q.errfd = Some(File::from(fd));
            }
            (VuFrontMsg::SET_VIRTQ_CALL, 8) => {
                let index = self.session.recv_payload::<u64>()? as u16;
                let Some(fd) = fds[0].take() else {
                    return error::MissingFd { req: msg.request }.fail();
                };
                let Some(q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                log::debug!("{name}: queue-{index}: set call fd: {}", fd.as_raw_fd());
                q.irqfd = Some(File::from(fd));
            }
            (VuFrontMsg::SET_VIRTQ_KICK, 8) => {
                let index = self.session.recv_payload::<u64>()? as u16;
                let Some(fd) = fds[0].take() else {
                    return error::MissingFd { req: msg.request }.fail();
                };
                let Some(q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                log::debug!("{name}: queue-{index}: set kick fd: {}", fd.as_raw_fd());
                q.ioeventfd = Some(File::from(fd));
            }
            (VuFrontMsg::SET_VIRTQ_NUM, 8) => {
                let virtq_num: VirtqState = self.session.recv_payload()?;
                let (index, size) = (virtq_num.index as u16, virtq_num.val as u16);
                let Some(q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                q.size = Some(size);
                log::debug!("{name}: queue-{index}: set size: {size}");
            }
            (VuFrontMsg::SET_VIRTQ_BASE, 8) => {
                let virtq_base: VirtqState = self.session.recv_payload()?;
                let (index, base) = (virtq_base.index as u16, virtq_base.val);
                let Some(_q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                log::warn!("{name}: queue-{index}: set base: {base}");
            }
            (VuFrontMsg::GET_VIRTQ_BASE, 8) => {
                let mut virtq_base: VirtqState = self.session.recv_payload()?;
                let (index, base) = (virtq_base.index as u16, virtq_base.val);
                let Some(_q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                virtq_base.val = 0;
                self.session.reply(req, &virtq_base, &[])?;
                msg.flag.set_need_reply(false);
                log::warn!("{name}: queue-{index}: get base: {base}");
            }
            (VuFrontMsg::SET_VIRTQ_ADDR, 40) => {
                let virtq_addr: VirtqAddr = self.session.recv_payload()?;
                let index = virtq_addr.index as u16;
                let Some(q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                log::debug!("{name}: queue-{index}: set addr: {virtq_addr:x?}");
                q.addr = Some(virtq_addr);
            }
            (VuFrontMsg::SET_VIRTQ_ENABLE, 8) => {
                let virtq_num: VirtqState = self.session.recv_payload()?;
                let (index, enabled) = (virtq_num.index as u16, virtq_num.val != 0);
                let Some(q) = self.init.queues.get_mut(index as usize) else {
                    return error::InvalidQueue { index }.fail();
                };
                q.enable = enabled;
                log::debug!("{name}: queue-{index}: set enabled: {enabled}");
            }
            (VuFrontMsg::GET_MAX_MEM_SLOTS, 0) => {
                self.session.reply(req, &128u64, &[])?;
                msg.flag.set_need_reply(false);
                log::debug!("{name}: get max mem slots: 128");
            }
            (VuFrontMsg::ADD_MEM_REG, 40) => {
                let single: MemorySingleRegion = self.session.recv_payload()?;
                let Some(fd) = fds[0].take() else {
                    return error::MissingFd { req: msg.request }.fail();
                };
                let region = &single.region;
                if self.status.contains(DevStatus::DRIVER_OK) {
                    return error::ChangeMemoryLayout.fail();
                }
                log::debug!("{name}: add mem: {region:x?}, fd: {}", fd.as_raw_fd());
                let user_mem = ArcMemPages::from_file(
                    File::from(fd),
                    region.mmap_offset as i64,
                    region.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )?;
                self.memory.add(region.gpa, user_mem)?;
                self.init.regions.push(single.region);
            }
            (VuFrontMsg::REM_MEM_REG, 40) => {
                let single: MemorySingleRegion = self.session.recv_payload()?;
                let region = &single.region;
                if self.status.contains(DevStatus::DRIVER_OK) {
                    return error::ChangeMemoryLayout.fail();
                }
                for (index, r) in self.init.regions.iter().enumerate() {
                    if r.gpa == region.gpa && r.hva == region.hva && r.size == region.size {
                        log::info!("{name}: remove mem: {r:x?}");
                        self.init.regions.remove(index);
                        let _ = self.memory.remove(region.gpa);
                        break;
                    }
                }
            }
            (VuFrontMsg::GET_STATUS, 0) => {
                let status = self.status.bits() as u64;
                self.session.reply(req, &status, &[])?;
                msg.flag.set_need_reply(false);
                log::debug!("{name}: get status: {status:x?}");
            }
            (VuFrontMsg::SET_STATUS, 8) => {
                let status: u64 = self.session.recv_payload()?;
                let new = DevStatus::from_bits_retain(status as u8);
                let old = self.status;
                self.status = new;
                log::debug!("{name}: set status: {old:x?} -> {new:x?}");
                if (old ^ new).contains(DevStatus::DRIVER_OK) {
                    let event = if new.contains(DevStatus::DRIVER_OK) {
                        let param = self.parse_init()?;
                        WakeEvent::Start { param }
                    } else {
                        WakeEvent::Reset
                    };
                    self.wake_up_dev(event);
                }
            }
            (VuFrontMsg::GET_CONFIG, 12..) => {
                let mut region = [0u8; MAX_CONFIG_SIZE];
                let dev_config = self.session.recv_config(&mut region)?;
                let mut done = 0;
                while let Some(n) = (dev_config.size as usize - done).checked_ilog2() {
                    let size = min(1 << n, 8) as u8;
                    let offset = dev_config.offset as u64 + done as u64;
                    let v = self.dev.device_config.read(offset, size)?;
                    region[done..(done + size as usize)]
                        .copy_from_slice(&v.as_bytes()[..size as usize]);
                    done += size as usize;
                }
                self.session.reply_config(&dev_config, &region[..done])?;
                log::debug!("{name}: get config: {dev_config:?}");
                msg.flag.set_need_reply(false);
            }
            (VuFrontMsg::SET_CONFIG, 12..) => {
                let mut region = [0u8; MAX_CONFIG_SIZE];
                let dev_config = self.session.recv_config(&mut region)?;
                let mut done = 0;
                while let Some(n) = (dev_config.size as usize - done).checked_ilog2() {
                    let size = min(1 << n, 8) as u8;
                    let mut v = 0;
                    v.as_mut_bytes()[..size as usize]
                        .copy_from_slice(&region[done..(done + size as usize)]);
                    let offset = dev_config.offset as u64 + done as u64;
                    self.dev.device_config.write(offset, size, v)?;
                    done += size as usize;
                }
                log::debug!("{name}: set config: {dev_config:?}");
            }
            _ => return error::InvalidMsg { req, size }.fail(),
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let mut fds = [const { None }; 8];
        loop {
            let msg = self.session.recv_msg(&mut fds);
            match msg {
                Ok(mut msg) => {
                    let ret = self.handle_msg(&mut msg, &mut fds);
                    if let Err(e) = &ret {
                        let name = &*self.dev.name;
                        log::error!("{name}: cannot handle message {:#x}: {e:?}", msg.request);
                    }
                    let req = VuFrontMsg::from(msg.request);
                    if msg.flag.need_reply() {
                        let code = if ret.is_ok() { 0 } else { u64::MAX };
                        self.session.reply(req, &code, &[])?;
                    }
                }
                Err(VuError::System { error, .. })
                    if error.kind() == ErrorKind::ConnectionAborted =>
                {
                    break;
                }
                Err(e) => return Err(e)?,
            }
        }
        Ok(())
    }
}
