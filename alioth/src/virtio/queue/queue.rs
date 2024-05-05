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

use std::io::{IoSlice, IoSliceMut};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};

use crate::virtio::Result;

pub mod handlers;
pub mod split;

pub const QUEUE_SIZE_MAX: u16 = 256;

#[derive(Debug, Default)]
pub struct Queue {
    pub size: AtomicU16,
    pub desc: AtomicU64,
    pub driver: AtomicU64,
    pub device: AtomicU64,
    pub enabled: AtomicBool,
}

#[derive(Debug)]
pub struct Descriptor<'m> {
    pub id: u16,
    pub readable: Vec<IoSlice<'m>>,
    pub writable: Vec<IoSliceMut<'m>>,
}

pub trait LockedQueue<'g> {
    fn next_desc(&self) -> Option<Result<Descriptor<'g>>>;
    fn has_next_desc(&self) -> bool;
    fn push_used(&mut self, desc: Descriptor, len: usize) -> u16;
    fn enable_notification(&self, enabled: bool);
    fn interrupt_enabled(&self) -> bool;
}

pub trait QueueGuard {
    fn queue(&self) -> Result<impl LockedQueue>;
}

pub trait VirtQueue {
    fn size(&self) -> u16;
    fn lock_ram_layout(&self) -> impl QueueGuard;
    fn enable_notification(&self, val: bool) -> Result<()>;
    fn interrupt_enabled(&self) -> Result<bool>;
}
