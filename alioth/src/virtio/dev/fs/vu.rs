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

use std::fs::File;
use std::io::ErrorKind;
use std::iter::zip;
use std::mem::size_of_val;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, PROT_NONE, mmap};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::{FromZeros, IntoBytes};

use crate::errors::BoxTrace;
use crate::fuse::bindings::FuseSetupmappingFlag;
use crate::fuse::{self, DaxRegion};
use crate::hv::IoeventFd;
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::mem::{LayoutChanged, MemRegion, MemRegionType};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::fs::{FsConfig, FsFeature};
use crate::virtio::dev::{DevParam, Virtio, WakeEvent};
use crate::virtio::queue::{QueueReg, VirtQueue};
use crate::virtio::vu::bindings::{DeviceConfig, FsMap, VuBackMsg, VuFeature};
use crate::virtio::vu::conn::VuChannel;
use crate::virtio::vu::frontend::VuFrontend;
use crate::virtio::vu::{Error, error as vu_error};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, IrqSender, Result};
use crate::{align_up, ffi};

#[derive(Debug)]
pub struct VuFs {
    frontend: VuFrontend,
    config: Arc<FsConfig>,
    dax_region: Option<ArcMemPages>,
}

impl VuFs {
    pub fn new(param: VuFsParam, name: impl Into<Arc<str>>) -> Result<Self> {
        let mut extra_features = VuFeature::empty();
        if param.dax_window > 0 {
            extra_features |= VuFeature::BACKEND_REQ | VuFeature::BACKEND_SEND_FD
        };
        if param.tag.is_none() {
            extra_features |= VuFeature::CONFIG;
        }
        let frontend = VuFrontend::new(name, &param.socket, DeviceId::FileSystem, extra_features)?;
        let config = if let Some(tag) = param.tag {
            assert!(tag.len() <= 36);
            assert_ne!(tag.len(), 0);
            let mut config = FsConfig::new_zeroed();
            config.tag[0..tag.len()].copy_from_slice(tag.as_bytes());
            config.num_request_queues = frontend.num_queues() as u32 - 1;
            if FsFeature::from_bits_retain(frontend.feature()).contains(FsFeature::NOTIFICATION) {
                config.num_request_queues -= 1;
            }
            config
        } else {
            let cfg = DeviceConfig {
                offset: 0,
                size: size_of::<FsConfig>() as u32,
                flags: 0,
            };
            let mut config = FsConfig::new_zeroed();
            frontend.session().get_config(&cfg, config.as_mut_bytes())?;
            log::info!("{}: get config: {config:?}", frontend.name());
            config
        };

        let dax_region = if param.dax_window > 0 {
            let size = align_up!(param.dax_window, 12);
            Some(ArcMemPages::from_anonymous(size, Some(PROT_NONE), None)?)
        } else {
            None
        };

        Ok(VuFs {
            frontend,
            config: Arc::new(config),
            dax_region,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct VuFsParam {
    /// Path to the vhost-user UNIX domain socket.
    pub socket: Box<Path>,
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
        self.frontend.name()
    }

    fn config(&self) -> Arc<Self::Config> {
        self.config.clone()
    }

    fn feature(&self) -> u128 {
        self.frontend.feature()
    }

    fn num_queues(&self) -> u16 {
        self.frontend.num_queues()
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
        self.frontend.ioeventfd_offloaded(q_index)
    }

    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        let dax_region = self.dax_region.as_ref()?;
        Some(Arc::new(MemRegion::with_dev_mem(
            dax_region.clone(),
            MemRegionType::Hidden,
        )))
    }

    fn mem_change_callback(&self) -> Option<Box<dyn LayoutChanged>> {
        self.frontend.mem_change_callback()
    }
}

impl VirtioMio for VuFs {
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
        self.frontend.activate(feature, active_mio)?;
        if let Some(channel) = self.frontend.channel() {
            channel.conn.set_nonblocking(true)?;
            active_mio.poll.registry().register(
                &mut SourceFd(&channel.conn.as_raw_fd()),
                Token(self.frontend.num_queues() as _),
                Interest::READABLE,
            )?;
        }
        Ok(())
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        event: &Event,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
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
        let Some(channel) = self.frontend.channel() else {
            return vu_error::ProtocolFeature {
                feature: VuFeature::BACKEND_REQ,
            }
            .fail()?;
        };
        loop {
            let mut fds = [const { None }; 8];
            let msg = channel.recv_msg(&mut fds);
            let (request, size) = match msg {
                Ok(m) => (m.request, m.size),
                Err(Error::System { error, .. }) if error.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e)?,
            };
            let fs_map: FsMap = channel.recv_payload()?;

            if size as usize != size_of_val(&fs_map) {
                return vu_error::PayloadSize {
                    want: size_of_val(&fs_map),
                    got: size,
                }
                .fail()?;
            }
            match VuBackMsg::from(request) {
                VuBackMsg::SHARED_OBJECT_ADD => {
                    for (index, fd) in fds.iter().enumerate() {
                        let Some(fd) = fd else {
                            break;
                        };
                        let raw_fd = fd.as_raw_fd();
                        let map_addr = dax_region.addr() + fs_map.cache_offset[index] as usize;
                        log::trace!(
                            "{}: mapping fd {raw_fd} to offset {:#x}",
                            self.name(),
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
                VuBackMsg::SHARED_OBJECT_REMOVE => {
                    for (len, offset) in zip(fs_map.len, fs_map.cache_offset) {
                        if len == 0 {
                            continue;
                        }
                        log::trace!(
                            "{}: unmapping offset {offset:#x}, size {len:#x}",
                            self.name()
                        );
                        let map_addr = dax_region.addr() + offset as usize;
                        let flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
                        ffi!(
                            unsafe { mmap(map_addr as _, len as _, PROT_NONE, flags, -1, 0) },
                            MAP_FAILED
                        )?;
                    }
                }
                _ => unimplemented!("{}: unknown request {request:#x}", self.name()),
            }
            channel.reply(VuBackMsg::from(request), &0u64, &[])?;
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
        self.frontend.handle_queue(index, active_mio)
    }

    fn reset(&mut self, registry: &Registry) {
        self.frontend.reset(registry)
    }
}

#[derive(Debug)]
pub struct VuDaxRegion {
    pub channel: Arc<VuChannel>,
}

impl DaxRegion for VuDaxRegion {
    fn map(
        &self,
        m_offset: u64,
        fd: &File,
        f_offset: u64,
        len: u64,
        flag: FuseSetupmappingFlag,
    ) -> fuse::Result<()> {
        let mut fs_map = FsMap::new_zeroed();
        fs_map.fd_offset[0] = f_offset;
        fs_map.cache_offset[0] = m_offset;

        let mut prot = 0;
        if flag.contains(FuseSetupmappingFlag::READ) {
            prot |= libc::PROT_READ;
        };
        if flag.contains(FuseSetupmappingFlag::WRITE) {
            prot |= libc::PROT_WRITE;
        }
        fs_map.flags[0] = prot as _;

        fs_map.len[0] = len;
        let fds = [fd.as_fd()];
        self.channel
            .fs_map(&fs_map, &fds)
            .box_trace(fuse::error::DaxMapping)
    }

    fn unmap(&self, m_offset: u64, len: u64) -> fuse::Result<()> {
        let mut fs_map = FsMap::new_zeroed();
        fs_map.cache_offset[0] = m_offset;
        fs_map.len[0] = len;
        self.channel
            .fs_unmap(&fs_map)
            .box_trace(fuse::error::DaxMapping)
    }
}
