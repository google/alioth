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
use io_uring::{opcode, types};

use crate::hv::IoeventFd;
use crate::mem::mapped::{Ram, RamBus};
use crate::virtio::dev::{Backend, BackendEvent, Context, Virtio, WakeEvent, Worker, WorkerState};
use crate::virtio::queue::{Descriptor, Queue, VirtQueue};
use crate::virtio::worker::Waker;
use crate::virtio::{IrqSender, Result};

pub enum BufferAction {
    Sqe(Sqe),
    Written(usize),
}

pub trait VirtioIoUring: Virtio {
    fn activate(
        &mut self,
        feature: u64,
        memory: &Ram,
        irq_sender: &impl IrqSender,
        queues: &[Queue],
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
const TOKEN_DESCRIPTOR: u64 = 1 << 62 | 1 << 61;

pub struct IoUring<E> {
    queue_ioeventfds: Arc<[(E, bool)]>,
    queue_submits: Box<[QueueSubmit]>,
    waker: Arc<Waker>,
    waker_token: u64,
}

impl<E> IoUring<E>
where
    E: IoeventFd,
{
    fn submit_queue_ioeventfd(&self, index: u16, fd: &E, data: &mut RingData) -> Result<()> {
        let token = index as u64 | TOKEN_QUEUE;
        let fd = types::Fd(fd.as_fd().as_raw_fd());
        let poll = opcode::PollAdd::new(fd, libc::EPOLLIN as _);
        let entry = poll.build().user_data(token);
        unsafe { data.ring.submission().push(&entry) }.unwrap();
        Ok(())
    }

    fn submit_waker(&mut self, data: &mut RingData) -> Result<()> {
        let fd = types::Fd(self.waker.0.as_raw_fd());
        let poll = opcode::PollAdd::new(fd, libc::EPOLLIN as _).multi(true);
        let entry = poll.build().user_data(self.waker_token);
        unsafe { data.ring.submission().push(&entry) }.unwrap();
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
            queue_submits: Box::new([]),
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

pub struct RingData<'m> {
    ring: io_uring::IoUring,
    submitted_buffers: HashMap<u32, Descriptor<'m>>,
    shared_count: u16,
}

fn submit_buffer<'m, D, Q>(
    q: &mut Q,
    queue_submit: &mut QueueSubmit,
    dev: &mut D,
    index: u16,
    irq_sender: &impl IrqSender,
    data: &mut RingData<'m>,
) -> Result<()>
where
    D: VirtioIoUring,
    Q: VirtQueue<'m>,
{
    'out: loop {
        if q.avail_index() == queue_submit.index {
            break;
        }
        q.enable_notification(false);
        while q.avail_index() != queue_submit.index {
            if queue_submit.count >= QUEUE_RESERVE_SIZE && data.shared_count == 0 {
                log::debug!("{}: queue-{index}: no more free entries", dev.name());
                break 'out;
            }
            let mut buffer = q.get_descriptor(queue_submit.index)?;
            match dev.handle_buffer(index, &mut buffer, irq_sender)? {
                BufferAction::Sqe(sqe) => {
                    let buffer_key = (queue_submit.index as u32) << 16 | index as u32;
                    let sqe = sqe.user_data(buffer_key as u64 | TOKEN_DESCRIPTOR);
                    if unsafe { data.ring.submission().push(&sqe) }.is_err() {
                        log::error!("{}: queue-{index}: unexpected full queue", dev.name());
                        break 'out;
                    }
                    data.submitted_buffers.insert(buffer_key, buffer);

                    queue_submit.count += 1;
                    if queue_submit.count > QUEUE_RESERVE_SIZE {
                        data.shared_count -= 1;
                    }
                }
                BufferAction::Written(len) => {
                    q.push_used(buffer, len);
                    if q.interrupt_enabled() {
                        irq_sender.queue_irq(index);
                    }
                }
            }
            queue_submit.index = queue_submit.index.wrapping_add(1);
        }
        q.enable_notification(true);
    }
    Ok(())
}

impl<D, E> Backend<D> for IoUring<E>
where
    D: VirtioIoUring,
    E: IoeventFd,
{
    type Event = Cqe;
    type Data<'m> = RingData<'m>;

    fn register_waker(&mut self, token: u64) -> Result<Arc<Waker>> {
        self.waker_token = token;
        Ok(self.waker.clone())
    }

    fn activate_dev(
        &mut self,
        dev: &mut D,
        feature: u64,
        memory: &Ram,
        irq_sender: &impl IrqSender,
        queues: &[Queue],
    ) -> Result<()> {
        dev.activate(feature, memory, irq_sender, queues)
    }

    fn handle_event<'m, Q: VirtQueue<'m>>(
        &mut self,
        dev: &mut D,
        event: &Self::Event,
        queues: &mut [Option<Q>],
        irq_sender: &impl IrqSender,
        data: &mut RingData<'m>,
    ) -> Result<()> {
        let token = event.user_data();
        if token & TOKEN_DESCRIPTOR == TOKEN_DESCRIPTOR {
            let buffer_key = token as u32;
            let index = buffer_key as u16;
            let Some(Some(queue)) = queues.get_mut(index as usize) else {
                log::error!("{}: invalid queue index {index}", dev.name());
                return Ok(());
            };
            let Some(mut buffer) = data.submitted_buffers.remove(&buffer_key) else {
                log::error!("{}: unexpected buffer key {buffer_key:#x}", dev.name());
                return Ok(());
            };

            let queue_submit = self.queue_submits.get_mut(index as usize).unwrap();
            if queue_submit.count > QUEUE_RESERVE_SIZE {
                data.shared_count += 1;
            }
            queue_submit.count -= 1;

            let written_len = dev.complete_buffer(index, &mut buffer, event)?;
            queue.push_used(buffer, written_len);
            if queue.interrupt_enabled() {
                irq_sender.queue_irq(index);
            }

            submit_buffer(queue, queue_submit, dev, index, irq_sender, data)
        } else if token & TOKEN_QUEUE == TOKEN_QUEUE {
            self.handle_queue(dev, token as u16, queues, irq_sender, data)
        } else {
            unreachable!()
        }
    }

    fn handle_queue<'m, Q: VirtQueue<'m>>(
        &mut self,
        dev: &mut D,
        index: u16,
        queues: &mut [Option<Q>],
        irq_sender: &impl IrqSender,
        data: &mut RingData<'m>,
    ) -> Result<()> {
        let Some(Some(q)) = queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", dev.name());
            return Ok(());
        };

        let queue_submit = self.queue_submits.get_mut(index as usize).unwrap();
        submit_buffer(q, queue_submit, dev, index, irq_sender, data)?;
        let (fd, _) = self.queue_ioeventfds.get(index as usize).unwrap();
        self.submit_queue_ioeventfd(index, fd, data)?;
        Ok(())
    }

    fn reset(&self, _dev: &mut D) -> Result<()> {
        Ok(())
    }

    fn event_loop<'m, S: IrqSender, Q: VirtQueue<'m>>(
        &mut self,
        context: &mut Context<D, S>,
        queues: &mut [Option<Q>],
        irq_sender: &S,
    ) -> Result<()> {
        let mut data = RingData {
            ring: io_uring::IoUring::new(RING_SIZE as u32)?,
            submitted_buffers: HashMap::new(),
            shared_count: 0,
        };
        let mut queue_count = 0;
        self.submit_waker(&mut data)?;
        for (index, (fd, offloaded)) in self.queue_ioeventfds.iter().enumerate() {
            if *offloaded {
                continue;
            }
            self.submit_queue_ioeventfd(index as u16, fd, &mut data)?;
            queue_count += 1;
        }
        data.shared_count = RING_SIZE - 1 - queue_count * (QUEUE_RESERVE_SIZE + 1);

        self.queue_submits = queues.iter().map(|_| QueueSubmit::default()).collect();

        'out: loop {
            data.ring.submit_and_wait(1)?;
            loop {
                let Some(entry) = data.ring.completion().next() else {
                    break;
                };
                context.handle_event(queues, &entry, irq_sender, self, &mut data)?;
                if context.state != WorkerState::Running {
                    break 'out;
                }
            }
        }
        Ok(())
    }
}
