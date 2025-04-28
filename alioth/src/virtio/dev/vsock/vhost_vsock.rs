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

use std::iter::zip;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, eventfd};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;

use crate::ffi;
use crate::hv::IoeventFd;
use crate::mem::LayoutUpdated;
use crate::mem::mapped::RamBus;
use crate::virtio::dev::vsock::{VsockConfig, VsockFeature};
use crate::virtio::dev::{DevParam, DeviceId, Virtio, WakeEvent};
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::vhost::bindings::{VHOST_FILE_UNBIND, VirtqAddr, VirtqFile, VirtqState};
use crate::virtio::vhost::{UpdateVsockMem, VhostDev, error};
use crate::virtio::worker::Waker;
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{IrqSender, Result, VirtioFeature};

#[derive(Debug, Clone, Deserialize, Help)]
pub struct VhostVsockParam {
    /// Vsock context id.
    pub cid: u32,
    /// Path to the host device file. [default: /dev/vhost-vsock]
    pub dev: Option<PathBuf>,
}

impl DevParam for VhostVsockParam {
    type Device = VhostVsock;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        VhostVsock::new(self, name)
    }
}

#[derive(Debug)]
pub struct VhostVsock {
    name: Arc<str>,
    vhost_dev: Arc<VhostDev>,
    config: VsockConfig,
    features: u64,
    error_fds: [Option<OwnedFd>; 2],
}

impl VhostVsock {
    pub fn new(param: VhostVsockParam, name: impl Into<Arc<str>>) -> Result<VhostVsock> {
        let name = name.into();
        let vhost_dev = match param.dev {
            Some(dev) => VhostDev::new(dev),
            None => VhostDev::new("/dev/vhost-vsock"),
        }?;
        vhost_dev.set_owner()?;
        vhost_dev.vsock_set_guest_cid(param.cid as _)?;
        if let Ok(backend_feature) = vhost_dev.get_backend_features() {
            log::debug!("{name}: vhost-vsock backend feature: {backend_feature:x?}");
            vhost_dev.set_backend_features(&backend_feature)?;
        }
        let dev_feat = vhost_dev.get_features()?;
        let known_feat = VirtioFeature::from_bits_truncate(dev_feat).bits()
            | VsockFeature::from_bits_truncate(dev_feat).bits();
        if !VirtioFeature::from_bits_retain(known_feat).contains(VirtioFeature::VERSION_1) {
            return error::VhostMissingDeviceFeature {
                feature: VirtioFeature::VERSION_1.bits(),
            }
            .fail()?;
        }
        Ok(VhostVsock {
            name,
            vhost_dev: Arc::new(vhost_dev),
            config: VsockConfig {
                guest_cid: param.cid,
                ..Default::default()
            },
            features: known_feat,
            error_fds: [None, None],
        })
    }
}

impl Virtio for VhostVsock {
    type Config = VsockConfig;
    type Feature = VsockFeature;

    const DEVICE_ID: DeviceId = DeviceId::Socket;

    fn name(&self) -> &str {
        &self.name
    }

    fn num_queues(&self) -> u16 {
        3
    }

    fn config(&self) -> Arc<VsockConfig> {
        Arc::new(self.config)
    }

    fn feature(&self) -> u64 {
        self.features
    }

    fn offload_ioeventfd<E>(&self, q_index: u16, fd: &E) -> Result<bool>
    where
        E: crate::hv::IoeventFd,
    {
        match q_index {
            0 | 1 => {
                self.vhost_dev.set_virtq_kick(&VirtqFile {
                    index: q_index as _,
                    fd: fd.as_fd().as_raw_fd(),
                })?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn mem_update_callback(&self) -> Option<Box<dyn LayoutUpdated>> {
        Some(Box::new(UpdateVsockMem {
            dev: self.vhost_dev.clone(),
        }))
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
}

impl VirtioMio for VhostVsock {
    fn activate<'a, 'm, Q: VirtQueue<'m>, S: IrqSender>(
        &mut self,
        feature: u64,
        active_mio: &mut ActiveMio<'a, 'm, Q, S>,
    ) -> Result<()> {
        self.vhost_dev.set_features(&feature)?;
        for (index, (queue, error_fd)) in
            zip(active_mio.queues.iter().take(2), self.error_fds.iter_mut()).enumerate()
        {
            let Some(queue) = queue else {
                continue;
            };
            let reg = queue.reg();
            let index = index as u32;
            let fd = active_mio.irq_sender.queue_irqfd(index as _)?;
            self.vhost_dev.set_virtq_call(&VirtqFile { index, fd })?;

            let err_fd =
                unsafe { OwnedFd::from_raw_fd(ffi!(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))?) };
            self.vhost_dev.set_virtq_err(&VirtqFile {
                index,
                fd: err_fd.as_raw_fd(),
            })?;
            active_mio.poll.registry().register(
                &mut SourceFd(&err_fd.as_raw_fd()),
                Token(index as _),
                Interest::READABLE,
            )?;
            *error_fd = Some(err_fd);

            self.vhost_dev.set_virtq_num(&VirtqState {
                index: index as _,
                val: reg.size.load(Ordering::Acquire) as _,
            })?;
            self.vhost_dev
                .set_virtq_base(&VirtqState { index, val: 0 })?;
            let mem = active_mio.mem;
            let virtq_addr = VirtqAddr {
                index,
                flags: 0,
                desc_hva: mem.translate(reg.desc.load(Ordering::Acquire))? as _,
                used_hva: mem.translate(reg.device.load(Ordering::Acquire))? as _,
                avail_hva: mem.translate(reg.driver.load(Ordering::Acquire))? as _,
                log_guest_addr: 0,
            };
            self.vhost_dev.set_virtq_addr(&virtq_addr)?;
        }
        self.vhost_dev.vsock_set_running(true)?;
        Ok(())
    }

    fn reset(&mut self, registry: &Registry) {
        self.vhost_dev.vsock_set_running(false).unwrap();
        for (index, error_fd) in self.error_fds.iter_mut().enumerate() {
            let Some(err_fd) = error_fd else {
                continue;
            };
            self.vhost_dev
                .set_virtq_err(&VirtqFile {
                    index: index as _,
                    fd: VHOST_FILE_UNBIND,
                })
                .unwrap();
            registry
                .deregister(&mut SourceFd(&err_fd.as_raw_fd()))
                .unwrap();
            *error_fd = None;
        }
    }

    fn handle_event<'a, 'm, Q: VirtQueue<'m>, S: IrqSender>(
        &mut self,
        event: &Event,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S>,
    ) -> Result<()> {
        let q_index = event.token();
        error::VhostQueueErr {
            dev: "vsock",
            index: q_index.0 as u16,
        }
        .fail()?;
        Ok(())
    }

    fn handle_queue<'a, 'm, Q: VirtQueue<'m>, S: IrqSender>(
        &mut self,
        index: u16,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S>,
    ) -> Result<()> {
        match index {
            0 | 1 => unreachable!("{}: queue 0 and 1 are offloaded to kernel", self.name),
            2 => log::info!("{}: event queue buffer available", self.name),
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl Drop for VhostVsock {
    fn drop(&mut self) {
        let ret = self.vhost_dev.vsock_set_running(false);
        if let Err(e) = ret {
            log::error!("{}: {e}", self.name)
        }
    }
}
