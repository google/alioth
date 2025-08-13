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
mod tests;

pub mod packed;
pub mod split;

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering, fence};

use bitflags::bitflags;

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
    index: u16,
    count: u16,
    pub readable: Vec<IoSlice<'m>>,
    pub writable: Vec<IoSliceMut<'m>>,
}

impl DescChain<'_> {
    pub fn id(&self) -> u16 {
        self.id
    }
}

mod private {
    use crate::virtio::Result;
    use crate::virtio::queue::DescChain;

    pub trait VirtQueuePrivate<'m> {
        type Index: Clone + Copy;
        const INIT_INDEX: Self::Index;
        fn desc_avail(&self, index: Self::Index) -> bool;
        fn get_desc_chain(&self, index: Self::Index) -> Result<Option<DescChain<'m>>>;
        fn push_used(&mut self, chain: DescChain, len: u32);
        fn enable_notification(&self, enabled: bool);
        fn interrupt_enabled(&self, count: u16) -> bool;
        fn next_index(&self, chain: &DescChain) -> Self::Index;
    }
}

pub trait VirtQueue<'m>: private::VirtQueuePrivate<'m> {
    fn reg(&self) -> &QueueReg;
}

#[derive(Debug)]
pub enum Status {
    Done { len: u32 },
    Deferred,
    Break,
}

pub struct Queue<'m, Q>
where
    Q: VirtQueue<'m>,
{
    q: Q,
    iter: Q::Index,
    deferred: HashMap<u16, DescChain<'m>>,
}

impl<'m, Q> Queue<'m, Q>
where
    Q: VirtQueue<'m>,
{
    pub fn new(q: Q) -> Self {
        Self {
            q,
            iter: Q::INIT_INDEX,
            deferred: HashMap::new(),
        }
    }

    pub fn reg(&self) -> &QueueReg {
        self.q.reg()
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
        let count = chain.count;
        self.q.push_used(chain, len);
        if self.q.interrupt_enabled(count) {
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
            if !self.q.desc_avail(self.iter) {
                break;
            }
            self.q.enable_notification(false);
            while let Some(mut chain) = self.q.get_desc_chain(self.iter)? {
                let next_iter = self.q.next_index(&chain);
                let count = chain.count;
                match op(&mut chain) {
                    Err(e) => {
                        ret = Err(e);
                        self.q.enable_notification(true);
                        break 'out;
                    }
                    Ok(Status::Break) => break 'out,
                    Ok(Status::Done { len }) => {
                        self.q.push_used(chain, len);
                        send_irq = send_irq || self.q.interrupt_enabled(count);
                    }
                    Ok(Status::Deferred) => {
                        self.deferred.insert(chain.id(), chain);
                    }
                }
                self.iter = next_iter;
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
