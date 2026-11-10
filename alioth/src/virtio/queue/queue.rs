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

pub mod packed;
pub mod split;

use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering, fence};

use crate::bitflags;
use crate::mem::mapped::{Ram, RamBus};
use crate::virtio::{IrqSender, Result, error};

pub const QUEUE_SIZE_MAX: u16 = 256;

bitflags! {
    pub struct DescFlag(u16) {
        NEXT = 1 << 0;
        WRITE = 1 << 1;
        INDIRECT = 1 << 2;
        AVAIL = 1 << 7;
        USED = 1 << 15;
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

/// The ring addresses of a queue, copied from its [`QueueReg`].
///
/// Transports do not let the driver change the registers of an enabled
/// queue, so the copy stays valid until the device is reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingAddrs {
    pub size: u16,
    pub desc: u64,
    pub driver: u64,
    pub device: u64,
}

impl RingAddrs {
    /// Reads the ring addresses, or returns `None` if the queue is disabled.
    pub fn load(reg: &QueueReg) -> Option<Self> {
        if !reg.enabled.load(Ordering::Acquire) {
            return None;
        }
        let addrs = RingAddrs {
            size: reg.size.load(Ordering::Acquire),
            desc: reg.desc.load(Ordering::Acquire),
            driver: reg.driver.load(Ordering::Acquire),
            device: reg.device.load(Ordering::Acquire),
        };
        // The registers may be cleared by a concurrent reset, which disables
        // the queue first.
        if !reg.enabled.load(Ordering::Acquire) {
            return None;
        }
        Some(addrs)
    }
}

#[derive(Debug)]
pub struct DescChain<'m> {
    id: u16,
    delta: u16,
    pub readable: Vec<IoSlice<'m>>,
    pub writable: Vec<IoSliceMut<'m>>,
    ram: &'m Ram,
}

impl<'m> DescChain<'m> {
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns the guest memory snapshot the buffers were translated with.
    ///
    /// A device accessing guest memory at addresses found in the buffers
    /// should use it.
    pub fn ram(&self) -> &Ram {
        self.ram
    }

    /// Erases the lifetime of the guest memory the chain points to.
    ///
    /// # Safety
    ///
    /// The caller must keep the snapshot the chain was translated with alive
    /// until the returned chain is dropped.
    ///
    /// Device code must only see the returned chain through a callback that
    /// takes `&mut DescChain` of any lifetime, like the `op` of
    /// [`Queue::handle_deferred`], so that it cannot keep the buffers.
    unsafe fn into_static(self) -> DescChain<'static> {
        unsafe { std::mem::transmute::<DescChain<'m>, DescChain<'static>>(self) }
    }
}

/// A descriptor chain the device has not completed yet.
///
/// It holds the snapshot the chain was translated with, so that the buffers
/// stay valid until the device completes the chain.
struct DeferredChain {
    chain: DescChain<'static>,
    // Dropped after `chain`, since fields are dropped in declaration order.
    _ram: Arc<Ram>,
}

pub trait VirtQueue: Sized {
    type Index: Clone + Copy;
    const INIT_INDEX: Self::Index;
    /// Creates the queue on the rings at `addrs` in the snapshot `ram`,
    /// which the queue holds on to.
    fn new(addrs: &RingAddrs, ram: &Arc<Ram>, event_idx: bool) -> Result<Self>;
    /// Returns the guest memory snapshot the rings are in.
    fn ram(&self) -> &Arc<Ram>;
    fn desc_avail(&self, index: Self::Index) -> bool;
    fn get_avail<'m>(&self, index: Self::Index, ram: &'m Ram) -> Result<Option<DescChain<'m>>>;
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

/// The device side of a virtqueue.
///
/// The queue can move to a newer guest memory snapshot, see
/// [`Queue::sync_ram`].
pub struct Queue<Q>
where
    Q: VirtQueue,
{
    q: Q,
    avail: Q::Index,
    used: Q::Index,
    addrs: RingAddrs,
    event_idx: bool,
    deferred: HashMap<u16, DeferredChain>,
    ram_bus: Arc<RamBus>,
}

impl<Q> Queue<Q>
where
    Q: VirtQueue,
{
    /// Creates the queue from its registers on the latest snapshot of
    /// `ram_bus`, or returns `None` if the queue is disabled.
    pub fn new(reg: &QueueReg, ram_bus: Arc<RamBus>, event_idx: bool) -> Result<Option<Self>> {
        let Some(addrs) = RingAddrs::load(reg) else {
            return Ok(None);
        };
        let ram = ram_bus.load();
        let q = Q::new(&addrs, &ram, event_idx)?;
        Ok(Some(Queue {
            q,
            avail: Q::INIT_INDEX,
            used: Q::INIT_INDEX,
            addrs,
            event_idx,
            deferred: HashMap::new(),
            ram_bus,
        }))
    }

    /// Returns the ring addresses.
    pub fn addrs(&self) -> &RingAddrs {
        &self.addrs
    }

    /// Returns the guest memory snapshot the queue works on.
    pub fn ram(&self) -> &Ram {
        self.q.ram()
    }

    /// Moves the queue to the latest snapshot of its [`RamBus`], keeping the
    /// ring indices and the deferred chains. Returns `true` if it moved.
    ///
    /// It fails if the rings are not accessible in the latest snapshot, and
    /// the queue stays where it is.
    pub fn sync_ram(&mut self) -> Result<bool> {
        if self.q.ram().generation() == self.ram_bus.generation() {
            return Ok(false);
        }
        let ram = self.ram_bus.load();
        self.q = Q::new(&self.addrs, &ram, self.event_idx)?;
        Ok(true)
    }

    /// Forgets the chains the device has not completed, and leaks the
    /// snapshots they hold.
    ///
    /// This is the last resort for buffers that might still be accessed,
    /// e.g. by the kernel, but cannot be waited for.
    pub fn leak_deferred(&mut self) {
        for (_, deferred) in self.deferred.drain() {
            std::mem::forget(deferred);
        }
    }

    pub fn desc_avail(&self) -> bool {
        self.q.desc_avail(self.avail)
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
        let Some(mut deferred) = self.deferred.remove(&id) else {
            return error::InvalidDescriptor { id }.fail();
        };
        let len = op(&mut deferred.chain)?;
        let delta = deferred.chain.delta;
        self.push_used(deferred.chain, len);
        fence(Ordering::SeqCst);
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
        let mut ram = self.q.ram().clone();
        'out: loop {
            if !self.q.desc_avail(self.avail) {
                break;
            }
            self.q.enable_notification(false);
            loop {
                let mut chain = match self.q.get_avail(self.avail, &ram) {
                    Ok(Some(chain)) => chain,
                    Ok(None) => break,
                    Err(e) => {
                        // The chain may be in memory published after the
                        // queue moved to its snapshot, e.g. while the worker
                        // was handling an earlier event. Catch up and retry.
                        match self.sync_ram() {
                            Ok(true) => {
                                ram = self.q.ram().clone();
                                continue;
                            }
                            Ok(false) => ret = Err(e),
                            Err(sync_err) => ret = Err(sync_err),
                        }
                        // Chains completed so far still need the interrupt.
                        self.q.enable_notification(true);
                        break 'out;
                    }
                };
                // A driver cannot make a chain available again before the
                // device has used it. Replacing the deferred chain would
                // release its snapshot while the device may still access the
                // buffers.
                if self.deferred.contains_key(&chain.id) {
                    ret = error::InvalidDescriptor { id: chain.id }.fail();
                    self.q.enable_notification(true);
                    break 'out;
                }
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
                        if !send_irq {
                            fence(Ordering::SeqCst);
                            send_irq = self.q.interrupt_enabled(self.used, delta);
                        }
                    }
                    Ok(Status::Deferred) => {
                        let id = chain.id;
                        // SAFETY: the deferred chain holds the snapshot the
                        // chain was translated with.
                        let chain = unsafe { chain.into_static() };
                        let _ram = ram.clone();
                        self.deferred.insert(id, DeferredChain { chain, _ram });
                    }
                }
                self.avail = self.q.index_add(self.avail, delta);
            }
            self.q.enable_notification(true);
            fence(Ordering::SeqCst);
        }
        if send_irq {
            irq_sender.queue_irq(q_index);
        }
        ret
    }
}

/// Moves `queues` to the latest guest memory snapshot, see
/// [`Queue::sync_ram`]. Returns `true` if any queue moved.
pub fn sync_queues<Q>(queues: &mut [Option<Queue<Q>>]) -> Result<bool>
where
    Q: VirtQueue,
{
    let mut moved = false;
    for queue in queues.iter_mut().flatten() {
        moved |= queue.sync_ram()?;
    }
    Ok(moved)
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

#[cfg(test)]
#[path = "queue_test.rs"]
pub(in crate::virtio) mod tests;
