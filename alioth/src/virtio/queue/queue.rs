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

pub mod split;
#[cfg(test)]
#[path = "queue_test.rs"]
mod tests;

use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering, fence};

use crate::virtio::{IrqSender, Result};

pub const QUEUE_SIZE_MAX: u16 = 256;

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
    pub id: u16,
    pub readable: Vec<IoSlice<'m>>,
    pub writable: Vec<IoSliceMut<'m>>,
}

pub trait VirtQueue<'m> {
    fn reg(&self) -> &QueueReg;
    fn size(&self) -> u16;
    fn next_desc_chain(&self) -> Option<Result<DescChain<'m>>>;
    fn avail_index(&self) -> u16;
    fn get_desc_chain(&self, index: u16) -> Result<DescChain<'m>>;
    fn has_next_desc(&self) -> bool;
    fn push_used(&mut self, desc: DescChain, len: usize) -> u16;
    fn enable_notification(&self, enabled: bool);
    fn interrupt_enabled(&self) -> bool;

    fn handle_desc(
        &mut self,
        q_index: u16,
        irq_sender: &impl IrqSender,
        mut op: impl FnMut(&mut DescChain) -> Result<Option<usize>>,
    ) -> Result<()> {
        let mut send_irq = false;
        let mut ret = Ok(());
        'out: loop {
            if !self.has_next_desc() {
                break;
            }
            self.enable_notification(false);
            while let Some(chain) = self.next_desc_chain() {
                let mut chain = chain?;
                match op(&mut chain) {
                    Err(e) => {
                        ret = Err(e);
                        self.enable_notification(true);
                        break 'out;
                    }
                    Ok(None) => break 'out,
                    Ok(Some(len)) => {
                        self.push_used(chain, len);
                        send_irq = send_irq || self.interrupt_enabled();
                    }
                }
            }
            self.enable_notification(true);
            fence(Ordering::SeqCst);
        }
        if send_irq {
            fence(Ordering::SeqCst);
            irq_sender.queue_irq(q_index)
        }
        ret
    }
}

pub fn copy_from_reader(
    mut reader: impl Read,
) -> impl FnMut(&mut DescChain) -> Result<Option<usize>> {
    move |chain| {
        let ret = reader.read_vectored(&mut chain.writable);
        match ret {
            Ok(0) => {
                let size: usize = chain.writable.iter().map(|s| s.len()).sum();
                if size == 0 { Ok(Some(0)) } else { Ok(None) }
            }
            Ok(len) => Ok(Some(len)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e)?,
        }
    }
}

pub fn copy_to_writer(
    mut writer: impl Write,
) -> impl FnMut(&mut DescChain) -> Result<Option<usize>> {
    move |chain| {
        let ret = writer.write_vectored(&chain.readable);
        match ret {
            Ok(0) => {
                let size: usize = chain.readable.iter().map(|s| s.len()).sum();
                if size == 0 { Ok(Some(0)) } else { Ok(None) }
            }
            Ok(_) => Ok(Some(0)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e)?,
        }
    }
}
