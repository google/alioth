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

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, eventfd};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;

use crate::ffi;
use crate::mem::LayoutUpdated;
use crate::sync::notifier::Notifier;
use crate::sys::vhost::{VHOST_FILE_UNBIND, VirtqAddr, VirtqFile, VirtqState};
use crate::virtio::dev::vsock::{VsockConfig, VsockFeature};
use crate::virtio::dev::{DevSpec, DeviceId, Virtio, WorkerParam};
use crate::virtio::queue::VirtQueue;
use crate::virtio::vhost::{UpdateVsockMem, VhostDev, error};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{IrqSender, Result, VirtioFeature};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct VhostVsockSpec {
    /// Vsock context id.
    pub cid: u32,
    /// Path to the host device file. [default: /dev/vhost-vsock]
    pub dev: Option<Box<Path>>,
}

impl DevSpec for VhostVsockSpec {
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
    pub fn new(spec: VhostVsockSpec, name: impl Into<Arc<str>>) -> Result<VhostVsock> {
        let name = name.into();
        let vhost_dev = match spec.dev {
            Some(dev) => VhostDev::new(dev),
            None => VhostDev::new("/dev/vhost-vsock"),
        }?;
        vhost_dev.set_owner()?;
        vhost_dev.vsock_set_guest_cid(spec.cid as _)?;
        if let Ok(backend_feature) = vhost_dev.get_backend_features() {
            log::debug!("{name}: vhost-vsock backend feature: {backend_feature:x?}");
            vhost_dev.set_backend_features(&backend_feature)?;
        }
        let dev_feat = vhost_dev.get_features()? as u128;
        let known_feat =
            (VirtioFeature::from_bits_truncate(dev_feat) & !VirtioFeature::VHOST_PROTOCOL).bits()
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
                guest_cid: spec.cid,
                ..Default::default()
            },
            features: known_feat as u64,
            error_fds: [None, None],
        })
    }
}

impl Virtio for VhostVsock {
    type Config = VsockConfig;
    type Feature = VsockFeature;

    fn id(&self) -> DeviceId {
        DeviceId::SOCKET
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_queues(&self) -> u16 {
        3
    }

    fn config(&self) -> Arc<VsockConfig> {
        Arc::new(self.config)
    }

    fn feature(&self) -> u128 {
        self.features as u128
    }

    fn notifier_offloaded(&self, q_index: u16) -> Result<bool> {
        match q_index {
            0 | 1 => Ok(true),
            _ => Ok(false),
        }
    }

    fn mem_update_callback(&self) -> Option<Box<dyn LayoutUpdated>> {
        Some(Box::new(UpdateVsockMem {
            dev: self.vhost_dev.clone(),
        }))
    }

    fn spawn_worker<S>(self, param: WorkerParam<S>) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
    {
        Mio::spawn_worker(self, param)
    }
}

// VirtIO spec 1.4, Sec 2.8.1: both driver and device ring wrap counters
// are initialized to 1. For packed rings, VHOST_SET_VRING_BASE encodes
// the avail wrap counter in bit 15 and the used wrap counter in bit 31.
fn vring_base_init(feature: u128) -> u32 {
    if VirtioFeature::from_bits_retain(feature).contains(VirtioFeature::RING_PACKED) {
        (1 << 15) | (1 << 31)
    } else {
        0
    }
}

impl VirtioMio for VhostVsock {
    fn activate<Q, S>(&mut self, feature: u128, active_mio: &mut ActiveMio<'_, Q, S>) -> Result<()>
    where
        Q: VirtQueue,
        S: IrqSender,
    {
        self.vhost_dev.set_features(&(feature as u64))?;
        let base = vring_base_init(feature);
        for (index, notifier) in active_mio.notifiers.iter().take(2).enumerate() {
            let kick = VirtqFile {
                index: index as u32,
                fd: notifier.as_fd().as_raw_fd(),
            };
            self.vhost_dev.set_virtq_kick(&kick)?;
        }
        for (index, queue) in active_mio.queues.iter().take(2).enumerate() {
            let Some(queue) = queue else {
                continue;
            };
            let addrs = queue.addrs();
            let index = index as u32;
            active_mio.irq_sender.queue_irqfd(index as _, |fd| {
                self.vhost_dev.set_virtq_call(&VirtqFile {
                    index,
                    fd: fd.as_raw_fd(),
                })?;
                Ok(())
            })?;

            self.vhost_dev.set_virtq_num(&VirtqState {
                index,
                val: addrs.size as _,
            })?;
            self.vhost_dev
                .set_virtq_base(&VirtqState { index, val: base })?;
            let mem = queue.ram();
            let virtq_addr = VirtqAddr {
                index,
                flags: 0,
                desc_hva: mem.translate(addrs.desc)? as _,
                used_hva: mem.translate(addrs.device)? as _,
                avail_hva: mem.translate(addrs.driver)? as _,
                log_guest_addr: 0,
            };
            self.vhost_dev.set_virtq_addr(&virtq_addr)?;
        }
        for (index, fd) in self.error_fds.iter_mut().enumerate() {
            let err_fd =
                unsafe { OwnedFd::from_raw_fd(ffi!(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))?) };
            self.vhost_dev.set_virtq_err(&VirtqFile {
                index: index as u32,
                fd: err_fd.as_raw_fd(),
            })?;
            active_mio.poll.registry().register(
                &mut SourceFd(&err_fd.as_raw_fd()),
                Token(index as _),
                Interest::READABLE,
            )?;
            *fd = Some(err_fd);
        }
        self.vhost_dev.vsock_set_running(true)?;
        Ok(())
    }

    fn reset(&mut self, registry: &Registry) {
        let name = &*self.name;
        if let Err(e) = self.vhost_dev.vsock_set_running(false) {
            log::error!("{name}: failed to stop vhost-vsock: {e:?}");
        }
        for (index, error_fd) in self.error_fds.iter_mut().enumerate() {
            let Some(err_fd) = error_fd else {
                continue;
            };
            let unbind = VirtqFile {
                index: index as _,
                fd: VHOST_FILE_UNBIND,
            };
            if let Err(e) = self.vhost_dev.set_virtq_err(&unbind) {
                log::error!("{name}: queue-{index}: failed to unbind error fd: {e:?}");
            }
            if let Err(e) = registry.deregister(&mut SourceFd(&err_fd.as_raw_fd())) {
                log::error!("{name}: queue-{index}: failed to deregister error fd: {e:?}");
            }
            *error_fd = None;
        }
    }

    fn handle_event<'a, Q, S>(
        &mut self,
        event: &Event,
        _active_mio: &mut ActiveMio<'_, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue,
        S: IrqSender,
    {
        let q_index = event.token();
        error::VhostQueueErr {
            dev: "vsock",
            index: q_index.0 as u16,
        }
        .fail()?;
        Ok(())
    }

    fn handle_queue<Q, S>(&mut self, index: u16, active_mio: &mut ActiveMio<'_, Q, S>) -> Result<()>
    where
        Q: VirtQueue,
        S: IrqSender,
    {
        match index {
            0 | 1 => {
                if let Some(notifier) = active_mio.notifiers.get(index as usize) {
                    log::warn!(
                        "{}: forwarding queue {index} notification to kernel",
                        self.name
                    );
                    notifier.notify()?;
                } else {
                    log::error!(
                        "{}: unexpected queue {index} notification without kick notifier",
                        self.name
                    );
                }
            }
            2 => log::info!("{}: event queue buffer available", self.name),
            _ => log::error!("{}: invalid queue index {index}", self.name),
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

#[cfg(test)]
#[path = "vhost_vsock_test.rs"]
mod tests;
