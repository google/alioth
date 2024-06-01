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
use std::sync::atomic::Ordering;
use std::sync::Arc;

use libc::{eventfd, EFD_CLOEXEC, EFD_NONBLOCK};
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;

use crate::ffi;
use crate::mem::mapped::RamBus;
use crate::virtio::dev::vsock::{VsockConfig, VsockFeature};
use crate::virtio::dev::{DevParam, DeviceId, Virtio};
use crate::virtio::queue::VirtQueue;
use crate::virtio::vhost::bindings::{
    MemoryMultipleRegion, MemoryRegion, VirtqAddr, VirtqFile, VirtqState, VHOST_FILE_UNBIND,
};
use crate::virtio::vhost::VhostDev;
use crate::virtio::{Error, IrqSender, Result, VirtioFeature};

#[derive(Debug, Clone, Deserialize)]
pub struct VhostVsockParam {
    pub cid: u32,
    pub dev: Option<PathBuf>,
}

impl DevParam for VhostVsockParam {
    type Device = VhostVsock;
    fn build(self, name: Arc<String>) -> Result<Self::Device> {
        VhostVsock::new(self, name)
    }
}

#[derive(Debug)]
pub struct VhostVsock {
    name: Arc<String>,
    vhost_dev: VhostDev,
    config: VsockConfig,
    features: u64,
    error_fds: [Option<OwnedFd>; 2],
}

impl VhostVsock {
    pub fn new(param: VhostVsockParam, name: Arc<String>) -> Result<VhostVsock> {
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
            return Err(Error::VhostMissingDeviceFeature(
                VirtioFeature::VERSION_1.bits(),
            ));
        }
        Ok(VhostVsock {
            name,
            vhost_dev,
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

    fn device_id() -> DeviceId {
        DeviceId::Socket
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

    fn activate(
        &mut self,
        registry: &Registry,
        feature: u64,
        memory: &RamBus,
        irq_sender: &impl crate::virtio::IrqSender,
        queues: &[crate::virtio::queue::Queue],
    ) -> Result<()> {
        self.vhost_dev.set_features(&feature)?;
        let mut table = MemoryMultipleRegion {
            num: 0,
            _padding: 0,
            regions: [MemoryRegion::default(); 8],
        };
        let mem = memory.lock_layout();
        for (index, (gpa, user_mem)) in mem.iter().enumerate() {
            table.num += 1;
            table.regions[index].gpa = gpa as u64;
            table.regions[index].hva = user_mem.pages.addr() as u64;
            table.regions[index].size = user_mem.pages.size() as u64;
        }
        self.vhost_dev.set_mem_table(&table)?;
        for (index, (queue, error_fd)) in
            zip(queues.iter().take(2), self.error_fds.iter_mut()).enumerate()
        {
            let index = index as u32;
            let fd = irq_sender.queue_irqfd(index as _)?;
            self.vhost_dev.set_virtq_call(&VirtqFile { index, fd })?;

            let err_fd =
                unsafe { OwnedFd::from_raw_fd(ffi!(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))?) };
            self.vhost_dev.set_virtq_err(&VirtqFile {
                index,
                fd: err_fd.as_raw_fd(),
            })?;
            registry.register(
                &mut SourceFd(&err_fd.as_raw_fd()),
                Token(index as _),
                Interest::READABLE,
            )?;
            *error_fd = Some(err_fd);

            self.vhost_dev.set_virtq_num(&VirtqState {
                index: index as _,
                val: queue.size.load(Ordering::Acquire) as _,
            })?;
            self.vhost_dev
                .set_virtq_base(&VirtqState { index, val: 0 })?;
            let virtq_addr = VirtqAddr {
                index,
                flags: 0,
                desc_hva: mem.translate(queue.desc.load(Ordering::Acquire) as usize)? as _,
                used_hva: mem.translate(queue.device.load(Ordering::Acquire) as usize)? as _,
                avail_hva: mem.translate(queue.driver.load(Ordering::Acquire) as usize)? as _,
                log_guest_addr: 0,
            };
            self.vhost_dev.set_virtq_addr(&virtq_addr)?;
        }
        self.vhost_dev.vsock_set_running(true)
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

    fn handle_event(
        &mut self,
        event: &mio::event::Event,
        _queues: &[impl VirtQueue],
        _irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        let q_index = event.token();
        Err(Error::VhostQueueErr("vsock", q_index.0 as _))
    }

    fn handle_queue(
        &mut self,
        index: u16,
        _queues: &[impl VirtQueue],
        _irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        match index {
            0 | 1 => unreachable!("{}: queue 0 and 1 are offloaded to kernel", self.name),
            2 => log::info!("{}: event queue buffer available", self.name),
            _ => unreachable!(),
        }
        Ok(())
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
}

impl Drop for VhostVsock {
    fn drop(&mut self) {
        let ret = self.vhost_dev.vsock_set_running(false);
        if let Err(e) = ret {
            log::error!("{}: {e}", self.name)
        }
    }
}
