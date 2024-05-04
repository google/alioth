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

use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use macros::Layout;

use crate::mem;
use crate::mem::emulated::Mmio;
use crate::utils::{
    get_atomic_high32, get_atomic_low32, get_high32, get_low32, set_atomic_high32, set_atomic_low32,
};
use crate::virtio::dev::Register;
use crate::virtio::queue::Queue;

#[repr(C, align(4))]
#[derive(Layout)]
pub struct VirtioCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    config_msix_vector: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_driver_lo: u32,
    queue_driver_hi: u32,
    queue_device_lo: u32,
    queue_device_hi: u32,
    queue_notify_data: u16,
    queue_reset: u16,
}

#[derive(Layout)]
#[repr(C, align(4))]
pub struct VirtioPciRegister {
    common: VirtioCommonCfg,
    isr_status: u32,
    queue_notify: PhantomData<[u32]>,
}

#[derive(Debug)]
pub struct VirtioPciRegisterMmio {
    name: Arc<String>,
    reg: Arc<Register>,
    queues: Arc<Vec<Queue>>,
}

impl Mmio for VirtioPciRegisterMmio {
    fn size(&self) -> usize {
        size_of::<VirtioPciRegister>() + size_of::<u32>() * self.queues.len()
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let reg = &*self.reg;
        let ret = match (offset, size as usize) {
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT => {
                reg.device_feature_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE => {
                if reg.device_feature_sel.load(Ordering::Acquire) > 0 {
                    get_high32(reg.device_feature) as u64
                } else {
                    get_low32(reg.device_feature) as u64
                }
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT => {
                reg.driver_feature_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE => {
                if reg.driver_feature_sel.load(Ordering::Acquire) > 0 {
                    get_atomic_high32(&reg.driver_feature) as u64
                } else {
                    get_atomic_low32(&reg.driver_feature) as u64
                }
            }
            VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR => todo!(),
            VirtioCommonCfg::LAYOUT_NUM_QUEUES => self.queues.len() as u64,
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS => reg.status.load(Ordering::Acquire) as u64,
            VirtioCommonCfg::LAYOUT_CONFIG_GENERATION => {
                0 // TODO: support device config change at runtime
            }
            VirtioCommonCfg::LAYOUT_QUEUE_SELECT => reg.queue_sel.load(Ordering::Acquire) as u64,
            VirtioCommonCfg::LAYOUT_QUEUE_SIZE => {
                let q_sel = reg.queue_sel.load(Ordering::Acquire) as usize;
                if let Some(q) = self.queues.get(q_sel) {
                    q.size.load(Ordering::Acquire) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_MSIX_VECTOR => {
                todo!()
            }
            VirtioCommonCfg::LAYOUT_QUEUE_ENABLE => {
                let q_sel = reg.queue_sel.load(Ordering::Acquire) as usize;
                if let Some(q) = self.queues.get(q_sel) {
                    q.enabled.load(Ordering::Acquire) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_NOTIFY_OFF => {
                reg.queue_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_low32(&q.desc) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.desc) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.driver) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.driver) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.device) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.device) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_NOTIFY_DATA => {
                todo!()
            }
            VirtioCommonCfg::LAYOUT_QUEUE_RESET => {
                todo!()
            }
            _ => {
                log::error!(
                    "{}: read invalid register: offset = {offset:#x}, size = {size}",
                    self.name
                );
                0
            }
        };
        Ok(ret)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let reg = &*self.reg;
        match (offset, size as usize) {
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT => {
                reg.device_feature_sel.store(val as u8, Ordering::Release);
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT => {
                reg.driver_feature_sel.store(val as u8, Ordering::Release);
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE => {
                if reg.driver_feature_sel.load(Ordering::Relaxed) > 0 {
                    set_atomic_high32(&reg.driver_feature, val as u32)
                } else {
                    set_atomic_low32(&reg.driver_feature, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR => {
                todo!()
            }
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS => {
                todo!()
            }
            VirtioCommonCfg::LAYOUT_QUEUE_SELECT => {
                reg.queue_sel.store(val as u16, Ordering::Relaxed);
                if self.queues.get(val as usize).is_none() {
                    log::error!("{}: unknown queue index {val}", self.name)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_SIZE => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed) as usize;
                if let Some(q) = self.queues.get(q_sel) {
                    // TODO: validate queue size
                    q.size.store(val as u16, Ordering::Release);
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_MSIX_VECTOR => {
                todo!()
            }
            VirtioCommonCfg::LAYOUT_QUEUE_ENABLE => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    q.enabled.store(val != 0, Ordering::Release);
                };
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_low32(&q.desc, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_high32(&q.desc, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_low32(&q.driver, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_high32(&q.driver, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_low32(&q.device, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_high32(&q.device, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_RESET => {
                todo!()
            }
            (VirtioPciRegister::OFFSET_QUEUE_NOTIFY, _) => {
                todo!()
            }
            _ => {
                log::error!(
                    "{}: write 0x{val:0width$x} to invalid register offset = {offset:#x}",
                    self.name,
                    width = 2 * size as usize
                );
            }
        }
        Ok(())
    }
}
