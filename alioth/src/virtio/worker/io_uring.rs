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

use std::iter;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use io_uring::cqueue::Entry as Cqe;
use io_uring::squeue::Entry as Sqe;
use io_uring::{SubmissionQueue, opcode, types};

use crate::hv::IoeventFd;
use crate::mem::mapped::{Ram, RamBus};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{
    ActiveBackend, Backend, BackendEvent, Context, StartParam, Virtio, WakeEvent, Worker,
    WorkerState,
};
use crate::virtio::queue::{DescChain, Queue, QueueReg, Status, VirtQueue};
use crate::virtio::{IrqSender, Result};

pub enum BufferAction {
    Sqe(Sqe),
    Written(u32),
}

pub trait VirtioIoUring: Virtio {
    fn activate<'m, Q, S, E>(
        &mut self,
        feature: u128,
        ring: &mut ActiveIoUring<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd;

    fn handle_desc(&mut self, q_index: u16, chain: &mut DescChain) -> Result<BufferAction>;

    fn complete_desc(&mut self, q_index: u16, chain: &mut DescChain, cqe: &Cqe) -> Result<u32>;
}

const TOKEN_QUEUE: u64 = 1 << 62;
const TOKEN_DESCRIPTOR: u64 = (1 << 62) | (1 << 61);

pub struct IoUring {
    notifier: Arc<Notifier>,
    notifier_token: u64,
}

impl IoUring {
    fn submit_notifier(&self, sq: &mut SubmissionQueue) -> Result<()> {
        let fd = types::Fd(self.notifier.as_fd().as_raw_fd());
        let poll = opcode::PollAdd::new(fd, libc::EPOLLIN as _).multi(true);
        let entry = poll.build().user_data(self.notifier_token);
        unsafe { sq.push(&entry) }.unwrap();
        Ok(())
    }

    pub fn spawn_worker<D, S, E>(
        dev: D,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        D: VirtioIoUring,
        E: IoeventFd,
        S: IrqSender,
    {
        let notifier = Notifier::new()?;
        let ring = IoUring {
            notifier: Arc::new(notifier),
            notifier_token: 0,
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

impl<D> Backend<D> for IoUring
where
    D: VirtioIoUring,
{
    fn register_notifier(&mut self, token: u64) -> Result<Arc<Notifier>> {
        self.notifier_token = token;
        Ok(self.notifier.clone())
    }

    fn reset(&self, _dev: &mut D) -> Result<()> {
        Ok(())
    }

    fn event_loop<'m, S, Q, E>(
        &mut self,
        memory: &'m Ram,
        context: &mut Context<D, S, E>,
        queues: &mut [Option<Queue<'_, 'm, Q>>],
        param: &StartParam<S, E>,
    ) -> Result<()>
    where
        S: IrqSender,
        Q: VirtQueue<'m>,
        E: IoeventFd,
    {
        let submit_counts = iter::repeat_n(0, queues.len()).collect();
        let mut active_ring = ActiveIoUring {
            ring: io_uring::IoUring::new(RING_SIZE as u32)?,
            shared_count: RING_SIZE - 1,
            irq_sender: &*param.irq_sender,
            ioeventfds: param.ioeventfds.as_deref().unwrap_or(&[]),
            mem: memory,
            queues,
            submit_counts,
        };
        self.submit_notifier(&mut active_ring.ring.submission())?;
        context.dev.activate(param.feature, &mut active_ring)?;

        if let Some(fds) = &param.ioeventfds {
            let sq = &mut active_ring.ring.submission();
            for (index, fd) in fds.iter().enumerate() {
                if context.dev.ioeventfd_offloaded(index as u16)? {
                    continue;
                }
                submit_queue_ioeventfd(index as u16, fd, sq)?;
                active_ring.shared_count -= QUEUE_RESERVE_SIZE + 1;
            }
        }

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

pub struct ActiveIoUring<'a, 'r, 'm, Q, S, E>
where
    Q: VirtQueue<'m>,
{
    ring: io_uring::IoUring,
    pub queues: &'a mut [Option<Queue<'r, 'm, Q>>],
    pub irq_sender: &'a S,
    pub ioeventfds: &'a [E],
    pub mem: &'m Ram,
    shared_count: u16,
    submit_counts: Box<[u16]>,
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

impl<'m, Q, S, E> ActiveIoUring<'_, '_, 'm, Q, S, E>
where
    Q: VirtQueue<'m>,
    S: IrqSender,
    E: IoeventFd,
{
    fn submit_buffers<D>(&mut self, dev: &mut D, q_index: u16) -> Result<()>
    where
        D: VirtioIoUring,
    {
        let Some(Some(q)) = self.queues.get_mut(q_index as usize) else {
            log::error!("{}: invalid queue index {q_index}", dev.name());
            return Ok(());
        };
        let submit_count = self.submit_counts.get_mut(q_index as usize).unwrap();

        q.handle_desc(q_index, self.irq_sender, |chain| {
            if *submit_count >= QUEUE_RESERVE_SIZE && self.shared_count == 0 {
                log::debug!("{}: queue-{q_index}: no more free entries", dev.name());
                return Ok(Status::Break);
            };
            match dev.handle_desc(q_index, chain)? {
                BufferAction::Sqe(sqe) => {
                    let buffer_key = ((chain.id() as u64) << 16) | q_index as u64;
                    let sqe = sqe.user_data(buffer_key | TOKEN_DESCRIPTOR);
                    if unsafe { self.ring.submission().push(&sqe) }.is_err() {
                        log::error!("{}: queue-{q_index}: unexpected full queue", dev.name());
                        return Ok(Status::Break);
                    }
                    *submit_count += 1;
                    if *submit_count > QUEUE_RESERVE_SIZE {
                        self.shared_count -= 1;
                    }
                    Ok(Status::Deferred)
                }
                BufferAction::Written(len) => Ok(Status::Done { len }),
            }
        })
    }
}

impl<'m, D, Q, S, E> ActiveBackend<D> for ActiveIoUring<'_, '_, 'm, Q, S, E>
where
    D: VirtioIoUring,
    Q: VirtQueue<'m>,
    S: IrqSender,
    E: IoeventFd,
{
    type Event = Cqe;

    fn handle_event(&mut self, dev: &mut D, event: &Self::Event) -> Result<()> {
        let token = event.user_data();
        if token & TOKEN_DESCRIPTOR == TOKEN_DESCRIPTOR {
            let buffer_key = token as u32;
            let q_index = buffer_key as u16;
            let chain_id = (buffer_key >> 16) as u16;
            let Some(Some(queue)) = self.queues.get_mut(q_index as usize) else {
                log::error!("{}: invalid queue index {q_index}", dev.name());
                return Ok(());
            };
            let submit_count = self.submit_counts.get_mut(q_index as usize).unwrap();
            if *submit_count > QUEUE_RESERVE_SIZE {
                self.shared_count += 1;
            }
            *submit_count -= 1;
            queue.handle_deferred(chain_id, q_index, self.irq_sender, |chain| {
                dev.complete_desc(q_index, chain, event)
            })?;

            self.submit_buffers(dev, q_index)
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
