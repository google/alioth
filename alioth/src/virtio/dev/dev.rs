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

use std::fmt::Debug;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8};
use std::sync::Arc;

use mio::event::Event;
use mio::Registry;

use crate::mem::emulated::Mmio;
use crate::mem::mapped::RamBus;
use crate::mem::MemRegion;
use crate::virtio::queue::VirtQueue;
use crate::virtio::{DeviceId, IrqSender, Result};

pub trait Virtio: Debug + Send + Sync + 'static {
    type Config: Mmio;

    fn num_queues(&self) -> u16;
    fn reset(&mut self, registry: &Registry);
    fn device_id() -> DeviceId;
    fn config(&self) -> Arc<Self::Config>;
    fn feature(&self) -> u64;
    fn activate(&mut self, registry: &Registry, feature: u64, memory: &RamBus) -> Result<()>;
    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()>;
    fn handle_event(
        &mut self,
        event: &Event,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()>;
    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }
}

#[derive(Debug, Default)]
pub struct Register {
    pub device_feature: u64,
    pub driver_feature: AtomicU64,
    pub device_feature_sel: AtomicU8,
    pub driver_feature_sel: AtomicU8,
    pub queue_sel: AtomicU16,
    pub status: AtomicU8,
}
