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

use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{fence, Ordering};

use crate::virtio::queue::{Descriptor, LockedQueue, QueueGuard, VirtQueue};
use crate::virtio::{IrqSender, Result};

pub fn handle_desc(
    dev_name: &str,
    q_index: u16,
    queue: &impl VirtQueue,
    irq_sender: &impl IrqSender,
    mut op: impl FnMut(&mut Descriptor) -> Result<Option<usize>>,
) -> Result<()> {
    let guard = queue.lock_ram_layout();
    let mut q = guard.queue()?;
    'out: loop {
        if !q.has_next_desc() {
            break;
        }
        q.enable_notification(false);
        while let Some(desc) = q.next_desc() {
            let mut desc = desc?;
            match op(&mut desc) {
                Err(e) => {
                    log::error!("{dev_name}: queue {q_index}: {e}");
                    q.enable_notification(true);
                    break 'out;
                }
                Ok(None) => break 'out,
                Ok(Some(len)) => {
                    q.push_used(desc, len);
                    if q.interrupt_enabled() {
                        fence(Ordering::SeqCst);
                        irq_sender.queue_irq(q_index)
                    }
                }
            }
        }
        q.enable_notification(true);
        fence(Ordering::SeqCst);
    }
    Ok(())
}

pub fn reader_to_queue(
    dev_name: &str,
    mut reader: impl Read,
    q_index: u16,
    queue: &impl VirtQueue,
    irq_sender: &impl IrqSender,
) -> Result<()> {
    handle_desc(dev_name, q_index, queue, irq_sender, |desc| {
        let ret = reader.read_vectored(&mut desc.writable);
        match ret {
            Ok(0) => Err(std::io::Error::from(ErrorKind::UnexpectedEof))?,
            Ok(len) => Ok(Some(len)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e)?,
        }
    })
}

pub fn queue_to_writer(
    dev_name: &str,
    mut writer: impl Write,
    q_index: u16,
    queue: &impl VirtQueue,
    irq_sender: &impl IrqSender,
) -> Result<()> {
    handle_desc(dev_name, q_index, queue, irq_sender, |desc| {
        let ret = writer.write_vectored(&desc.readable);
        match ret {
            Ok(0) => Err(std::io::Error::from(ErrorKind::WriteZero))?,
            Ok(len) => Ok(Some(len)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e)?,
        }
    })
}
