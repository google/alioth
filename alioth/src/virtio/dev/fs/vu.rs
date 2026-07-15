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
use std::mem::size_of_val;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use flume::Receiver;
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
use crate::virtio::dev::fs::{DAX_SHMEM_ID, FsConfig, FsFeature};
use crate::virtio::dev::{DevSpec, Virtio, WakeEvent};
use crate::virtio::queue::{QueueReg, VirtQueue};
use crate::virtio::vu::bindings::{
    DeviceConfig, VhostUserMmap, VhostUserMmapFlag, VuBackMsg, VuFeature,
};
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
    pub fn new(spec: VuFsSpec, name: impl Into<Arc<str>>) -> Result<Self> {
        let mut extra_features = VuFeature::empty();
        if spec.dax_window > 0 {
            extra_features |= VuFeature::BACKEND_REQ | VuFeature::BACKEND_SEND_FD | VuFeature::SHMEM
        };
        if spec.tag.is_none() {
            extra_features |= VuFeature::CONFIG;
        }
        let frontend = VuFrontend::new(name, &spec.socket, DeviceId::FILE_SYSTEM, extra_features)?;
        let config = if let Some(tag) = spec.tag {
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

        let dax_region = if spec.dax_window > 0 {
            let size = align_up!(spec.dax_window, 12);
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
pub struct VuFsSpec {
    /// Path to the vhost-user UNIX domain socket.
    pub socket: Box<Path>,
    /// Mount tag seen by the guest.
    pub tag: Option<String>,
    /// Size of memory region for DAX in bytes.
    /// 0 means no DAX. [default: 0]
    #[serde(default)]
    pub dax_window: usize,
}

impl DevSpec for VuFsSpec {
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
        DeviceId::FILE_SYSTEM
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
            let mut fds = [None];
            let msg = channel.recv_msg(&mut fds);
            let (request, size) = match msg {
                Ok(m) => (m.request, m.size),
                Err(Error::System { error, .. }) if error.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e)?,
            };
            let payload: VhostUserMmap = channel.recv_payload()?;

            if size as usize != size_of_val(&payload) {
                return vu_error::PayloadSize {
                    want: size_of_val(&payload),
                    got: size,
                }
                .fail()?;
            }
            match VuBackMsg::from(request) {
                VuBackMsg::SHMEM_MAP => {
                    let [Some(fd)] = fds else {
                        return vu_error::MissingFd { req: request }.fail()?;
                    };
                    let shm_offset = payload.shm_offset;
                    let map_addr = dax_region.addr() + shm_offset as usize;
                    let prot = if payload.flags.contains(VhostUserMmapFlag::RW) {
                        libc::PROT_READ | libc::PROT_WRITE
                    } else {
                        libc::PROT_READ
                    };
                    log::trace!(
                        "{}: mapping fd {} to offset {shm_offset:#x}, size {:#x}",
                        self.name(),
                        fd.as_raw_fd(),
                        payload.len,
                    );
                    ffi!(
                        unsafe {
                            mmap(
                                map_addr as _,
                                payload.len as _,
                                prot,
                                MAP_SHARED | MAP_FIXED,
                                fd.as_raw_fd(),
                                payload.fd_offset as _,
                            )
                        },
                        MAP_FAILED
                    )?;
                }
                VuBackMsg::SHMEM_UNMAP => {
                    let shm_offset = payload.shm_offset;
                    let len = payload.len;
                    log::trace!(
                        "{}: unmapping offset {shm_offset:#x}, size {len:#x}",
                        self.name(),
                    );
                    let map_addr = dax_region.addr() + shm_offset as usize;
                    let flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED;
                    ffi!(
                        unsafe { mmap(map_addr as _, len as _, PROT_NONE, flags, -1, 0) },
                        MAP_FAILED
                    )?;
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
        let flags = if flag.contains(FuseSetupmappingFlag::WRITE) {
            VhostUserMmapFlag::RW
        } else {
            VhostUserMmapFlag::empty()
        };

        let payload = VhostUserMmap {
            shmid: DAX_SHMEM_ID,
            fd_offset: f_offset,
            shm_offset: m_offset,
            len,
            flags,
            ..Default::default()
        };
        self.channel
            .shmem_map(&payload, fd.as_fd())
            .box_trace(fuse::error::DaxMapping)
    }

    fn unmap(&self, m_offset: u64, len: u64) -> fuse::Result<()> {
        let payload = VhostUserMmap {
            shmid: DAX_SHMEM_ID,
            shm_offset: m_offset,
            len,
            ..Default::default()
        };
        self.channel
            .shmem_unmap(&payload)
            .box_trace(fuse::error::DaxMapping)
    }
}
