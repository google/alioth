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

use std::io::ErrorKind;
use std::iter::zip;
use std::mem::size_of_val;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use bitflags::bitflags;
use libc::{
    EFD_CLOEXEC, EFD_NONBLOCK, MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED, MAP_PRIVATE, MAP_SHARED,
    PROT_NONE, eventfd, mmap,
};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::hv::IoeventFd;
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::mem::{LayoutChanged, MemRegion, MemRegionType};
use crate::virtio::dev::{DevParam, Virtio, WakeEvent};
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::vu::{
    DeviceConfig, Error, UpdateVuMem, VirtqAddr, VirtqState, VuDev, VuFeature, error as vu_error,
};
use crate::virtio::worker::Waker;
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, IrqSender, Result, VirtioFeature, error};
use crate::{align_up, ffi, impl_mmio_for_zerocopy};

#[repr(C, align(4))]
#[derive(Debug, FromBytes, Immutable, IntoBytes)]
pub struct FsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
    notify_buf_size: u32,
}

impl_mmio_for_zerocopy!(FsConfig);

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FsFeature: u64 {
        const NOTIFICATION = 1 << 0;
    }
}

#[derive(Debug, Clone, FromBytes, Immutable, IntoBytes)]
#[repr(C)]
struct VuFsMap {
    pub fd_offset: [u64; 8],
    pub cache_offset: [u64; 8],
    pub len: [u64; 8],
    pub flags: [u64; 8],
}

const VHOST_USER_BACKEND_FS_MAP: u32 = 6;
const VHOST_USER_BACKEND_FS_UNMAP: u32 = 7;

#[derive(Debug)]
pub struct VuFs {
    name: Arc<str>,
    vu_dev: Arc<VuDev>,
    config: Arc<FsConfig>,
    feature: u64,
    num_queues: u16,
    dax_region: Option<ArcMemPages>,
    error_fds: Vec<OwnedFd>,
}

impl VuFs {
    pub fn new(param: VuFsParam, name: impl Into<Arc<str>>) -> Result<Self> {
        let name = name.into();
        let mut vu_dev = VuDev::new(param.socket)?;
        let dev_feat = vu_dev.get_features()?;
        let virtio_feat = VirtioFeature::from_bits_retain(dev_feat);
        let need_feat = VirtioFeature::VHOST_PROTOCOL | VirtioFeature::VERSION_1;
        if !virtio_feat.contains(need_feat) {
            return vu_error::DeviceFeature {
                feature: need_feat.bits(),
            }
            .fail()?;
        }

        let prot_feat = VuFeature::from_bits_retain(vu_dev.get_protocol_features()?);
        log::debug!("{name}: vhost-user feat: {prot_feat:x?}");
        let mut need_feat = VuFeature::MQ | VuFeature::REPLY_ACK | VuFeature::CONFIGURE_MEM_SLOTS;
        if param.tag.is_none() {
            need_feat |= VuFeature::CONFIG;
        }
        if param.dax_window > 0 {
            assert!(param.dax_window.count_ones() == 1 && param.dax_window > (4 << 10));
            need_feat |= VuFeature::BACKEND_REQ | VuFeature::BACKEND_SEND_FD;
        }
        if !prot_feat.contains(need_feat) {
            return vu_error::ProtocolFeature {
                feature: need_feat & !prot_feat,
            }
            .fail()?;
        }
        vu_dev.set_protocol_features(&need_feat.bits())?;

        vu_dev.set_owner()?;
        let num_queues = vu_dev.get_queue_num()? as u16;
        let config = if let Some(tag) = param.tag {
            assert!(tag.len() <= 36);
            assert_ne!(tag.len(), 0);
            let mut config = FsConfig::new_zeroed();
            config.tag[0..tag.len()].copy_from_slice(tag.as_bytes());
            config.num_request_queues = num_queues as u32 - 1;
            if FsFeature::from_bits_retain(dev_feat).contains(FsFeature::NOTIFICATION) {
                config.num_request_queues -= 1;
            }
            config
        } else {
            let mut empty_cfg = DeviceConfig::new_zeroed();
            empty_cfg.size = size_of_val(&empty_cfg.region) as _;
            let dev_config = vu_dev.get_config(&empty_cfg)?;
            FsConfig::read_from_prefix(&dev_config.region).unwrap().0
        };
        let dax_region = if param.dax_window > 0 {
            vu_dev.setup_channel()?;
            let size = align_up!(param.dax_window, 12);
            Some(ArcMemPages::from_anonymous(size, Some(PROT_NONE), None)?)
        } else {
            None
        };

        Ok(VuFs {
            num_queues,
            name,
            vu_dev: Arc::new(vu_dev),
            config: Arc::new(config),
            feature: dev_feat & !VirtioFeature::VHOST_PROTOCOL.bits(),
            error_fds: Vec::new(),
            dax_region,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Help)]
pub struct VuFsParam {
    /// Path to the vhost-user UNIX domain socket.
    pub socket: PathBuf,
    /// Mount tag seen by the guest.
    pub tag: Option<String>,
    /// Size of memory region for DAX in bytes.
    /// 0 means no DAX. [default: 0]
    #[serde(default)]
    pub dax_window: usize,
}

impl DevParam for VuFsParam {
    type Device = VuFs;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        VuFs::new(self, name)
    }

    fn needs_mem_shared_fd(&self) -> bool {
        true
    }
}

impl Virtio for VuFs {
    type Config = FsConfig;
    type Feature = FsFeature;

    fn id(&self) -> DeviceId {
        DeviceId::FileSystem
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn config(&self) -> Arc<Self::Config> {
        self.config.clone()
    }

    fn feature(&self) -> u64 {
        self.feature
    }

    fn num_queues(&self) -> u16 {
        self.num_queues
    }

    fn spawn_worker<S, E>(
        self,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
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
        let dax_region = self.dax_region.as_ref()?;
        Some(Arc::new(MemRegion::with_dev_mem(
            dax_region.clone(),
            MemRegionType::Hidden,
        )))
    }

    fn mem_change_callback(&self) -> Option<Box<dyn LayoutChanged>> {
        Some(Box::new(UpdateVuMem {
            dev: self.vu_dev.clone(),
        }))
    }
}

impl VirtioMio for VuFs {
    fn activate<'a, 'm, Q, S, E>(
        &mut self,
        feature: u64,
        active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        self.vu_dev
            .set_features(&(feature | VirtioFeature::VHOST_PROTOCOL.bits()))?;
        for (index, fd) in active_mio.ioeventfds.iter().enumerate() {
            self.vu_dev
                .set_virtq_kick(&(index as u64), fd.as_fd().as_raw_fd())?;
        }
        for (index, queue) in active_mio.queues.iter().enumerate() {
            let Some(queue) = queue else {
                continue;
            };
            let reg = queue.reg();
            let irq_fd = active_mio.irq_sender.queue_irqfd(index as _)?;
            self.vu_dev.set_virtq_call(&(index as u64), irq_fd).unwrap();

            let err_fd =
                unsafe { OwnedFd::from_raw_fd(ffi!(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))?) };
            self.vu_dev
                .set_virtq_err(&(index as u64), err_fd.as_raw_fd())
                .unwrap();
            active_mio.poll.registry().register(
                &mut SourceFd(&err_fd.as_raw_fd()),
                Token(index),
                Interest::READABLE,
            )?;
            self.error_fds.push(err_fd);

            let virtq_num = VirtqState {
                index: index as _,
                val: reg.size.load(Ordering::Acquire) as _,
            };
            self.vu_dev.set_virtq_num(&virtq_num).unwrap();
            log::info!("set_virtq_num: {virtq_num:x?}");

            let virtq_base = VirtqState {
                index: index as _,
                val: 0,
            };
            self.vu_dev.set_virtq_base(&virtq_base).unwrap();

            log::info!("set_virtq_base: {virtq_base:x?}");
            let mem = active_mio.mem;
            let virtq_addr = VirtqAddr {
                index: index as _,
                flags: 0,
                desc_hva: mem.translate(reg.desc.load(Ordering::Acquire) as _)? as _,
                used_hva: mem.translate(reg.device.load(Ordering::Acquire) as _)? as _,
                avail_hva: mem.translate(reg.driver.load(Ordering::Acquire) as _)? as _,
                log_guest_addr: 0,
            };
            self.vu_dev.set_virtq_addr(&virtq_addr).unwrap();
            log::info!("queue: {:x?}", reg);
            log::info!("virtq_addr: {virtq_addr:x?}");
        }
        for index in 0..active_mio.queues.len() {
            let virtq_enable = VirtqState {
                index: index as _,
                val: 1,
            };
            self.vu_dev.set_virtq_enable(&virtq_enable).unwrap();
            log::info!("virtq_enable: {virtq_enable:x?}");
        }
        if let Some(channel) = self.vu_dev.get_channel() {
            channel.set_nonblocking(true)?;
            active_mio.poll.registry().register(
                &mut SourceFd(&channel.as_raw_fd()),
                Token(self.num_queues as _),
                Interest::READABLE,
            )?;
        }
        Ok(())
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        event: &Event,
        active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let q_index = event.token().0;
        if q_index < active_mio.queues.len() {
            return vu_error::QueueErr {
                index: q_index as u16,
            }
            .fail()?;
        }

        let Some(dax_region) = &self.dax_region else {
            return vu_error::ProtocolFeature {
                feature: VuFeature::BACKEND_REQ,
            }
            .fail()?;
        };
        loop {
            let mut fs_map = VuFsMap::new_zeroed();
            let mut fds = [None, None, None, None, None, None, None, None];
            let ret = self
                .vu_dev
                .receive_from_channel(fs_map.as_mut_bytes(), &mut fds);
            let (request, size) = match ret {
                Ok((r, s)) => (r, s),
                Err(Error::System { error, .. }) if error.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e)?,
            };
            if size as usize != size_of_val(&fs_map) {
                return vu_error::PayloadSize {
                    want: size_of_val(&fs_map),
                    got: size,
                }
                .fail()?;
            }
            match request {
                VHOST_USER_BACKEND_FS_MAP => {
                    for (index, fd) in fds.iter().enumerate() {
                        let Some(fd) = fd else {
                            break;
                        };
                        let raw_fd = fd.as_raw_fd();
                        let map_addr = dax_region.addr() + fs_map.cache_offset[index] as usize;
                        log::trace!(
                            "{}: mapping fd {raw_fd} to offset {:#x}",
                            self.name,
                            fs_map.cache_offset[index]
                        );
                        ffi!(
                            unsafe {
                                mmap(
                                    map_addr as _,
                                    fs_map.len[index] as _,
                                    fs_map.flags[index] as _,
                                    MAP_SHARED | MAP_FIXED,
                                    raw_fd,
                                    fs_map.fd_offset[index] as _,
                                )
                            },
                            MAP_FAILED
                        )?;
                    }
                }
                VHOST_USER_BACKEND_FS_UNMAP => {
                    for (len, offset) in zip(fs_map.len, fs_map.cache_offset) {
                        if len == 0 {
                            continue;
                        }
                        log::trace!("{}: unmapping offset {offset:#x}, size {len:#x}", self.name);
                        let map_addr = dax_region.addr() + offset as usize;
                        let flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
                        ffi!(
                            unsafe { mmap(map_addr as _, len as _, PROT_NONE, flags, -1, 0) },
                            MAP_FAILED
                        )?;
                    }
                }
                _ => unimplemented!("unknown request {request:#x}"),
            }
            self.vu_dev.ack_request(request, &0u64)?;
        }
        Ok(())
    }

    fn handle_queue<'a, 'm, Q, S, E>(
        &mut self,
        index: u16,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
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
        for q_index in 0..self.num_queues {
            let disable = VirtqState {
                index: q_index as _,
                val: 0,
            };
            self.vu_dev.set_virtq_enable(&disable).unwrap();
        }
        while let Some(fd) = self.error_fds.pop() {
            registry.deregister(&mut SourceFd(&fd.as_raw_fd())).unwrap();
        }
        if let Some(channel) = self.vu_dev.get_channel() {
            registry
                .deregister(&mut SourceFd(&channel.as_raw_fd()))
                .unwrap();
        }
    }
}
