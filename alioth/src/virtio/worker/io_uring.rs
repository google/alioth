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

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::JoinHandle;

use io_uring::cqueue::Entry as Cqe;
use io_uring::squeue::Entry as Sqe;
use io_uring::{opcode, types, SubmissionQueue};

use crate::hv::IoeventFd;
use crate::mem::mapped::{Ram, RamBus};
use crate::virtio::dev::{
    ActiveBackend, Backend, BackendEvent, Context, Virtio, WakeEvent, Worker, WorkerState,
};
use crate::virtio::queue::{Descriptor, Queue, VirtQueue};
use crate::virtio::worker::Waker;
use crate::virtio::{IrqSender, Result};

pub enum BufferAction {
    Sqe(Sqe),
    Written(usize),
}

pub trait VirtioIoUring: Virtio {
    fn activate<'m, S: IrqSender, Q: VirtQueue<'m>>(
        &mut self,
        feature: u64,
        memory: &Ram,
        irq_sender: &S,
        queues: &mut [Option<Q>],
    ) -> Result<()>;

    fn handle_buffer(
        &mut self,
        q_index: u16,
        buffer: &mut Descriptor,
        irq_sender: &impl IrqSender,
    ) -> Result<BufferAction>;

    fn complete_buffer(
        &mut self,
        q_index: u16,
        buffer: &mut Descriptor,
        cqe: &Cqe,
    ) -> Result<usize>;
}

const TOKEN_QUEUE: u64 = 1 << 62;
const TOKEN_DESCRIPTOR: u64 = (1 << 62) | (1 << 61);

pub struct IoUring<E> {
    queue_ioeventfds: Arc<[(E, bool)]>,
    waker: Arc<Waker>,
    waker_token: u64,
}

impl<E> IoUring<E>
where
    E: IoeventFd,
{
    fn submit_waker(&self, sq: &mut SubmissionQueue) -> Result<()> {
        let fd = types::Fd(self.waker.0.as_raw_fd());
        let poll = opcode::PollAdd::new(fd, libc::EPOLLIN as _).multi(true);
        let entry = poll.build().user_data(self.waker_token);
        unsafe { sq.push(&entry) }.unwrap();
        Ok(())
    }

    pub fn spawn_worker<D, S>(
        dev: D,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
        fds: Arc<[(E, bool)]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
    where
        D: VirtioIoUring,
        E: IoeventFd,
        S: IrqSender,
    {
        let waker = Waker::new_eventfd()?;
        let ring = IoUring {
            queue_ioeventfds: fds,
            waker: Arc::new(waker),
            waker_token: 0,
        };
        Worker::spawn(dev, ring, event_rx, memory, queue_regs)
    }
}

impl BackendEvent for Cqe {
    fn token(&self) -> u64 {
        self.user_data()
    }
}

const RING_SIZE: u16 = 256;
const QUEUE_RESERVE_SIZE: u16 = 1;

#[derive(Debug, Clone, Default)]
struct QueueSubmit {
    index: u16,
    count: u16,
}

impl<D, E> Backend<D> for IoUring<E>
where
    D: VirtioIoUring,
    E: IoeventFd,
{
    fn register_waker(&mut self, token: u64) -> Result<Arc<Waker>> {
        self.waker_token = token;
        Ok(self.waker.clone())
    }

    fn reset(&self, _dev: &mut D) -> Result<()> {
        Ok(())
    }

    fn event_loop<'m, S: IrqSender, Q: VirtQueue<'m>>(
        &mut self,
        feature: u64,
        memory: &'m Ram,
        context: &mut Context<D, S>,
        queues: &mut [Option<Q>],
        irq_sender: &S,
    ) -> Result<()> {
        context.dev.activate(feature, memory, irq_sender, queues)?;

        let queue_submits = queues.iter().map(|_| QueueSubmit::default()).collect();
        let mut ring = io_uring::IoUring::new(RING_SIZE as u32)?;
        let mut queue_count = 0;
        {
            let sq = &mut ring.submission();
            self.submit_waker(sq)?;
            for (index, (fd, offloaded)) in self.queue_ioeventfds.iter().enumerate() {
                if *offloaded {
                    continue;
                }
                submit_queue_ioeventfd(index as u16, fd, sq)?;
                queue_count += 1;
            }
        }

        let mut active_ring = ActiveIoUring {
            ring,
            submitted_buffers: HashMap::new(),
            shared_count: RING_SIZE - 1 - queue_count * (QUEUE_RESERVE_SIZE + 1),
            irq_sender,
            queues,
            queue_submits,
        };

        'out: loop {
            active_ring.ring.submit_and_wait(1)?;
            loop {
                let Some(entry) = active_ring.ring.completion().next() else {
                    break;
                };
                context.handle_event(&entry, &mut active_ring)?;
                if context.state != WorkerState::Running {
                    break 'out;
                }
            }
        }
        Ok(())
    }
}

struct ActiveIoUring<'a, 'm, Q, S>
where
    Q: VirtQueue<'m>,
{
    ring: io_uring::IoUring,
    queues: &'a mut [Option<Q>],
    irq_sender: &'a S,
    submitted_buffers: HashMap<u32, Descriptor<'m>>,
    shared_count: u16,
    queue_submits: Box<[QueueSubmit]>,
}

fn submit_queue_ioeventfd<E>(index: u16, fd: &E, sq: &mut SubmissionQueue) -> Result<()>
where
    E: IoeventFd,
{
    let token = index as u64 | TOKEN_QUEUE;

    let fd = types::Fd(fd.as_fd().as_raw_fd());
    let poll = opcode::PollAdd::new(fd, libc::EPOLLIN as _).multi(true);
    let entry = poll.build().user_data(token);
    unsafe { sq.push(&entry) }.unwrap();
    Ok(())
}

impl<'m, Q, S> ActiveIoUring<'_, 'm, Q, S>
where
    Q: VirtQueue<'m>,
    S: IrqSender,
{
    fn submit_buffers<D>(&mut self, dev: &mut D, index: u16) -> Result<()>
    where
        D: VirtioIoUring,
    {
        let Some(Some(q)) = self.queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", dev.name());
            return Ok(());
        };

        let queue_submit = self.queue_submits.get_mut(index as usize).unwrap();
        'out: loop {
            if q.avail_index() == queue_submit.index {
                break;
            }
            q.enable_notification(false);
            while q.avail_index() != queue_submit.index {
                if queue_submit.count >= QUEUE_RESERVE_SIZE && self.shared_count == 0 {
                    log::debug!("{}: queue-{index}: no more free entries", dev.name());
                    break 'out;
                }
                let mut buffer = q.get_descriptor(queue_submit.index)?;
                match dev.handle_buffer(index, &mut buffer, self.irq_sender)? {
                    BufferAction::Sqe(sqe) => {
                        let buffer_key = ((queue_submit.index as u32) << 16) | index as u32;
                        let sqe = sqe.user_data(buffer_key as u64 | TOKEN_DESCRIPTOR);
                        if unsafe { self.ring.submission().push(&sqe) }.is_err() {
                            log::error!("{}: queue-{index}: unexpected full queue", dev.name());
                            break 'out;
                        }
                        self.submitted_buffers.insert(buffer_key, buffer);

                        queue_submit.count += 1;
                        if queue_submit.count > QUEUE_RESERVE_SIZE {
                            self.shared_count -= 1;
                        }
                    }
                    BufferAction::Written(len) => {
                        q.push_used(buffer, len);
                        if q.interrupt_enabled() {
                            self.irq_sender.queue_irq(index);
                        }
                    }
                }
                queue_submit.index = queue_submit.index.wrapping_add(1);
            }
            q.enable_notification(true);
        }
        Ok(())
    }
}

impl<'m, Q, S, D> ActiveBackend<D> for ActiveIoUring<'_, 'm, Q, S>
where
    D: VirtioIoUring,
    Q: VirtQueue<'m>,
    S: IrqSender,
{
    type Event = Cqe;

    fn handle_event(&mut self, dev: &mut D, event: &Self::Event) -> Result<()> {
        let token = event.user_data();
        if token & TOKEN_DESCRIPTOR == TOKEN_DESCRIPTOR {
            let buffer_key = token as u32;
            let index = buffer_key as u16;
            let Some(Some(queue)) = self.queues.get_mut(index as usize) else {
                log::error!("{}: invalid queue index {index}", dev.name());
                return Ok(());
            };
            let Some(mut buffer) = self.submitted_buffers.remove(&buffer_key) else {
                log::error!("{}: unexpected buffer key {buffer_key:#x}", dev.name());
                return Ok(());
            };

            let queue_submit = self.queue_submits.get_mut(index as usize).unwrap();
            if queue_submit.count > QUEUE_RESERVE_SIZE {
                self.shared_count += 1;
            }
            queue_submit.count -= 1;

            let written_len = dev.complete_buffer(index, &mut buffer, event)?;
            queue.push_used(buffer, written_len);
            if queue.interrupt_enabled() {
                self.irq_sender.queue_irq(index);
            }
            self.submit_buffers(dev, index)
        } else if token & TOKEN_QUEUE == TOKEN_QUEUE {
            let index = token as u16;
            self.submit_buffers(dev, index)
        } else {
            unreachable!()
        }
    }

    fn handle_queue(&mut self, dev: &mut D, index: u16) -> Result<()> {
        self.submit_buffers(dev, index)
    }
}
