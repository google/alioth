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

#[cfg(test)]
#[path = "queue_test.rs"]
pub(in crate::virtio) mod tests;

pub mod packed;
pub mod split;

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering, fence};

use bitflags::bitflags;

use crate::mem::mapped::Ram;
use crate::virtio::{IrqSender, Result, error};

pub const QUEUE_SIZE_MAX: u16 = 256;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DescFlag: u16 {
        const NEXT = 1;
        const WRITE = 2;
        const INDIRECT = 4;
        const AVAIL = 1 << 7;
        const USED = 1 << 15;
    }
}

#[derive(Debug, Default)]
pub struct QueueReg {
    pub size: AtomicU16,
    pub desc: AtomicU64,
    pub driver: AtomicU64,
    pub device: AtomicU64,
    pub enabled: AtomicBool,
}

#[derive(Debug)]
pub struct DescChain<'m> {
    id: u16,
    delta: u16,
    pub readable: Vec<IoSlice<'m>>,
    pub writable: Vec<IoSliceMut<'m>>,
}

impl DescChain<'_> {
    pub fn id(&self) -> u16 {
        self.id
    }
}

pub trait VirtQueue<'m> {
    type Index: Clone + Copy;
    const INIT_INDEX: Self::Index;
    fn desc_avail(&self, index: Self::Index) -> bool;
    fn get_avail(&self, index: Self::Index, ram: &'m Ram) -> Result<Option<DescChain<'m>>>;
    fn set_used(&self, index: Self::Index, id: u16, len: u32);
    fn enable_notification(&self, enabled: bool);
    fn interrupt_enabled(&self, index: Self::Index, delta: u16) -> bool;
    fn index_add(&self, index: Self::Index, delta: u16) -> Self::Index;
}

#[derive(Debug)]
pub enum Status {
    Done { len: u32 },
    Deferred,
    Break,
}

pub struct Queue<'r, 'm, Q>
where
    Q: VirtQueue<'m>,
{
    q: Q,
    avail: Q::Index,
    used: Q::Index,
    reg: &'r QueueReg,
    ram: &'m Ram,
    deferred: HashMap<u16, DescChain<'m>>,
}

impl<'r, 'm, Q> Queue<'r, 'm, Q>
where
    Q: VirtQueue<'m>,
{
    pub fn new(q: Q, reg: &'r QueueReg, ram: &'m Ram) -> Self {
        Self {
            q,
            avail: Q::INIT_INDEX,
            used: Q::INIT_INDEX,
            reg,
            ram,
            deferred: HashMap::new(),
        }
    }

    pub fn reg(&self) -> &QueueReg {
        self.reg
    }

    fn push_used(&mut self, chain: DescChain, len: u32) {
        self.q.set_used(self.used, chain.id, len);
        self.used = self.q.index_add(self.used, chain.delta);
    }

    pub fn handle_deferred(
        &mut self,
        id: u16,
        q_index: u16,
        irq_sender: &impl IrqSender,
        mut op: impl FnMut(&mut DescChain) -> Result<u32>,
    ) -> Result<()> {
        let Some(mut chain) = self.deferred.remove(&id) else {
            return error::InvalidDescriptor { id }.fail();
        };
        let len = op(&mut chain)?;
        let delta = chain.delta;
        self.push_used(chain, len);
        if self.q.interrupt_enabled(self.used, delta) {
            irq_sender.queue_irq(q_index);
        }
        Ok(())
    }

    pub fn handle_desc(
        &mut self,
        q_index: u16,
        irq_sender: &impl IrqSender,
        mut op: impl FnMut(&mut DescChain) -> Result<Status>,
    ) -> Result<()> {
        let mut send_irq = false;
        let mut ret = Ok(());
        'out: loop {
            if !self.q.desc_avail(self.avail) {
                break;
            }
            self.q.enable_notification(false);
            while let Some(mut chain) = self.q.get_avail(self.avail, self.ram)? {
                let delta = chain.delta;
                match op(&mut chain) {
                    Err(e) => {
                        ret = Err(e);
                        self.q.enable_notification(true);
                        break 'out;
                    }
                    Ok(Status::Break) => break 'out,
                    Ok(Status::Done { len }) => {
                        self.push_used(chain, len);
                        send_irq = send_irq || self.q.interrupt_enabled(self.used, delta);
                    }
                    Ok(Status::Deferred) => {
                        self.deferred.insert(chain.id, chain);
                    }
                }
                self.avail = self.q.index_add(self.avail, delta);
            }
            self.q.enable_notification(true);
            fence(Ordering::SeqCst);
        }
        if send_irq {
            fence(Ordering::SeqCst);
            irq_sender.queue_irq(q_index);
        }
        ret
    }
}

pub fn copy_from_reader(mut reader: impl Read) -> impl FnMut(&mut DescChain) -> Result<Status> {
    move |chain| {
        let ret = reader.read_vectored(&mut chain.writable);
        match ret {
            Ok(0) => {
                let size: usize = chain.writable.iter().map(|s| s.len()).sum();
                if size == 0 {
                    Ok(Status::Done { len: 0 })
                } else {
                    Ok(Status::Break)
                }
            }
            Ok(len) => Ok(Status::Done { len: len as u32 }),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(Status::Break),
            Err(e) => Err(e.into()),
        }
    }
}

pub fn copy_to_writer(mut writer: impl Write) -> impl FnMut(&mut DescChain) -> Result<Status> {
    move |chain| {
        let ret = writer.write_vectored(&chain.readable);
        match ret {
            Ok(0) => {
                let size: usize = chain.readable.iter().map(|s| s.len()).sum();
                if size == 0 {
                    Ok(Status::Done { len: 0 })
                } else {
                    Ok(Status::Break)
                }
            }
            Ok(_) => Ok(Status::Done { len: 0 }),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(Status::Break),
            Err(e) => Err(e.into()),
        }
    }
}
