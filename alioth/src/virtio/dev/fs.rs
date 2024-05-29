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

use std::mem::size_of_val;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bitflags::bitflags;
use libc::{eventfd, EFD_CLOEXEC, EFD_NONBLOCK};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::hv::IoeventFd;
use crate::mem::mapped::RamBus;
use crate::virtio::dev::{DevParam, Virtio};
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::vu::{
    DeviceConfig, MemoryRegion, MemorySingleRegion, VirtqAddr, VirtqState, VuDev, VuFeature,
};
use crate::virtio::{DeviceId, Error, IrqSender, Result, VirtioFeature};
use crate::{ffi, impl_mmio_for_zerocopy};

#[repr(C, align(4))]
#[derive(Debug, FromBytes, FromZeroes, AsBytes)]
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

#[derive(Debug)]
pub struct VuFs {
    name: Arc<String>,
    vu_dev: VuDev,
    config: Arc<FsConfig>,
    feature: u64,
    num_queues: u16,
    regions: Vec<MemoryRegion>,
    error_fds: Vec<OwnedFd>,
}

impl VuFs {
    pub fn new(param: VuFsParam, name: Arc<String>) -> Result<Self> {
        let vu_dev = VuDev::new(param.socket)?;
        let dev_feat = vu_dev.get_features()?;
        let virtio_feat = VirtioFeature::from_bits_retain(dev_feat);
        let need_feat = VirtioFeature::VHOST_PROTOCOL | VirtioFeature::VERSION_1;
        if !virtio_feat.contains(need_feat) {
            return Err(Error::VuMissingDeviceFeature(need_feat.bits()));
        }

        let prot_feat = VuFeature::from_bits_retain(vu_dev.get_protocol_features()?);
        log::debug!("{name}: vhost-user feat: {prot_feat:x?}");
        let mut need_feat = VuFeature::MQ | VuFeature::REPLY_ACK | VuFeature::CONFIGURE_MEM_SLOTS;
        if param.tag.is_none() {
            need_feat |= VuFeature::CONFIG;
        }
        if !prot_feat.contains(need_feat) {
            return Err(Error::VuMissingProtocolFeature(need_feat & !prot_feat));
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
            FsConfig::read_from_prefix(&dev_config.region).unwrap()
        };

        Ok(VuFs {
            num_queues,
            name,
            vu_dev,
            config: Arc::new(config),
            feature: dev_feat & !VirtioFeature::VHOST_PROTOCOL.bits(),
            regions: Vec::new(),
            error_fds: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct VuFsParam {
    pub socket: PathBuf,
    pub tag: Option<String>,
}

impl DevParam for VuFsParam {
    type Device = VuFs;

    fn build(self, name: Arc<String>) -> Result<Self::Device> {
        VuFs::new(self, name)
    }
}

impl Virtio for VuFs {
    type Config = FsConfig;
    type Feature = FsFeature;

    fn config(&self) -> Arc<Self::Config> {
        self.config.clone()
    }
    fn device_id() -> DeviceId {
        DeviceId::FileSystem
    }
    fn feature(&self) -> u64 {
        self.feature
    }

    fn activate(
        &mut self,
        registry: &Registry,
        feature: u64,
        memory: &RamBus,
        irq_sender: &impl IrqSender,
        queues: &[Queue],
    ) -> Result<()> {
        self.vu_dev
            .set_features(&(feature | VirtioFeature::VHOST_PROTOCOL.bits()))?;
        let mem = memory.lock_layout();
        for (gpa, slot) in mem.iter() {
            let region = MemorySingleRegion {
                _padding: 0,
                region: MemoryRegion {
                    gpa: gpa as _,
                    size: slot.pages.size() as _,
                    hva: slot.pages.addr() as _,
                    mmap_offset: 0,
                },
            };
            self.vu_dev
                .add_mem_region(&region, slot.pages.fd().as_raw_fd())
                .unwrap();
            log::info!("region: {region:x?}");
            self.regions.push(region.region);
        }
        for (index, queue) in queues.iter().enumerate() {
            let irq_fd = irq_sender.queue_irqfd(index as _)?;
            self.vu_dev.set_virtq_call(&(index as u64), irq_fd).unwrap();

            let err_fd =
                unsafe { OwnedFd::from_raw_fd(ffi!(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))?) };
            self.vu_dev
                .set_virtq_err(&(index as u64), err_fd.as_raw_fd())
                .unwrap();
            registry.register(
                &mut SourceFd(&err_fd.as_raw_fd()),
                Token(index),
                Interest::READABLE,
            )?;
            self.error_fds.push(err_fd);

            let virtq_num = VirtqState {
                index: index as _,
                val: queue.size.load(Ordering::Acquire) as _,
            };
            self.vu_dev.set_virtq_num(&virtq_num).unwrap();
            log::info!("set_virtq_num: {virtq_num:x?}");

            let virtq_base = VirtqState {
                index: index as _,
                val: 0,
            };
            self.vu_dev.set_virtq_base(&virtq_base).unwrap();

            log::info!("set_virtq_base: {virtq_base:x?}");
            let virtq_addr = VirtqAddr {
                index: index as _,
                flags: 0,
                desc_hva: mem.translate(queue.desc.load(Ordering::Acquire) as _)? as _,
                used_hva: mem.translate(queue.device.load(Ordering::Acquire) as _)? as _,
                avail_hva: mem.translate(queue.driver.load(Ordering::Acquire) as _)? as _,
                log_guest_addr: 0,
            };
            self.vu_dev.set_virtq_addr(&virtq_addr).unwrap();
            log::info!("queue: {:x?}", queue);
            log::info!("virtq_addr: {virtq_addr:x?}");
        }
        for index in 0..queues.len() {
            let virtq_enable = VirtqState {
                index: index as _,
                val: 1,
            };
            self.vu_dev.set_virtq_enable(&virtq_enable).unwrap();
            log::info!("virtq_enable: {virtq_enable:x?}");
        }
        Ok(())
    }

    fn handle_event(
        &mut self,
        event: &Event,
        _queues: &[impl VirtQueue],
        _irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        let q_index = event.token();
        Err(Error::VuQueueErr(q_index.0 as _))
    }

    fn handle_queue(
        &mut self,
        index: u16,
        _queues: &[impl VirtQueue],
        _irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        unreachable!(
            "{}: queue {index} notification should go to vhost-user backend",
            self.name
        )
    }

    fn num_queues(&self) -> u16 {
        self.num_queues
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
        while let Some(region) = self.regions.pop() {
            self.vu_dev
                .remove_mem_region(&MemorySingleRegion {
                    _padding: 0,
                    region,
                })
                .unwrap()
        }
    }

    fn offload_ioeventfd<E>(&self, q_index: u16, fd: &E) -> Result<bool>
    where
        E: IoeventFd,
    {
        if q_index < self.num_queues {
            self.vu_dev
                .set_virtq_kick(&(q_index as u64), fd.as_fd().as_raw_fd())?;
            Ok(true)
        } else {
            Err(Error::InvalidQueueIndex(q_index))
        }
    }
}
