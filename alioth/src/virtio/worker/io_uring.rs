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
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use io_uring::cqueue::Entry as Cqe;
use io_uring::squeue::Entry as Sqe;
use io_uring::{SubmissionQueue, opcode, types};

use crate::mem::mapped::Ram;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{
    ActiveBackend, Backend, BackendEvent, Context, StartParam, Virtio, Worker, WorkerParam,
    WorkerState,
};
use crate::virtio::queue::{DescChain, Queue, Status, VirtQueue};
use crate::virtio::{IrqSender, Result};

pub enum BufferAction {
    Sqe(Sqe),
    Written(u32),
}

pub trait VirtioIoUring: Virtio {
    fn activate<'m, Q, S>(
        &mut self,
        feature: u128,
        ring: &mut ActiveIoUring<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender;

    fn handle_desc(&mut self, q_index: u16, chain: &mut DescChain) -> Result<BufferAction>;

    fn complete_desc(&mut self, q_index: u16, chain: &mut DescChain, cqe: &Cqe) -> Result<u32>;
}

const TOKEN_QUEUE: u64 = 1 << 62;
const TOKEN_DESCRIPTOR: u64 = (1 << 62) | (1 << 61);
const TOKEN_CANCEL: u64 = 1 << 60;

/// How long to wait for in-flight requests when leaving the event loop.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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

    pub fn spawn_worker<D, S>(
        dev: D,
        param: WorkerParam<S>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        D: VirtioIoUring,
        S: IrqSender,
    {
        let notifier = Notifier::new()?;
        let ring = IoUring {
            notifier: Arc::new(notifier),
            notifier_token: 0,
        };
        Worker::spawn(dev, ring, param)
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

    fn event_loop<'m, S, Q>(
        &mut self,
        memory: &'m Ram,
        context: &mut Context<D, S>,
        queues: &mut [Option<Queue<'_, 'm, Q>>],
        param: &StartParam<S>,
    ) -> Result<()>
    where
        S: IrqSender,
        Q: VirtQueue<'m>,
    {
        let submit_counts = iter::repeat_n(0, queues.len()).collect();
        // One entry for the worker notifier, and a reserve for each queue
        // that submit_buffers() may take even if no shared entry is left.
        let num_queues = queues.iter().flatten().count() as u16;
        let mut active_ring = ActiveIoUring {
            ring: io_uring::IoUring::new(RING_SIZE as u32)?,
            shared_count: RING_SIZE - 1 - num_queues * QUEUE_RESERVE_SIZE,
            irq_sender: &*param.irq_sender,
            notifiers: param.notifiers.as_deref().unwrap_or(&[]),
            mem: memory,
            queues,
            submit_counts,
        };
        self.submit_notifier(&mut active_ring.ring.submission())?;
        context.dev.activate(param.feature, &mut active_ring)?;

        if let Some(notifiers) = &param.notifiers {
            let sq = &mut active_ring.ring.submission();
            for (index, notifier) in notifiers.iter().enumerate() {
                if context.dev.notifier_offloaded(index as u16)? {
                    continue;
                }
                submit_queue_notifier(index as u16, notifier, sq)?;
                active_ring.shared_count -= 1;
            }
        }

        let ret = active_ring.run(context);
        let drained = active_ring.drain();
        ret.and(drained)
    }
}

pub struct ActiveIoUring<'a, 'r, 'm, Q, S>
where
    Q: VirtQueue<'m>,
{
    ring: io_uring::IoUring,
    pub queues: &'a mut [Option<Queue<'r, 'm, Q>>],
    pub irq_sender: &'a S,
    pub notifiers: &'a [Notifier],
    pub mem: &'m Ram,
    shared_count: u16,
    submit_counts: Box<[u16]>,
}

fn submit_queue_notifier(index: u16, notifier: &Notifier, sq: &mut SubmissionQueue) -> Result<()> {
    let token = index as u64 | TOKEN_QUEUE;

    let fd = types::Fd(notifier.as_fd().as_raw_fd());
    let poll = opcode::PollAdd::new(fd, libc::EPOLLIN as _).multi(true);
    let entry = poll.build().user_data(token);
    unsafe { sq.push(&entry) }.unwrap();
    Ok(())
}

impl<'m, Q, S> ActiveIoUring<'_, '_, 'm, Q, S>
where
    Q: VirtQueue<'m>,
    S: IrqSender,
{
    fn run<D>(&mut self, context: &mut Context<D, S>) -> Result<()>
    where
        D: VirtioIoUring,
    {
        loop {
            self.ring.submit_and_wait(1)?;
            loop {
                let Some(entry) = self.ring.completion().next() else {
                    break;
                };
                context.handle_event(&entry, self)?;
                if context.state != WorkerState::Running {
                    return Ok(());
                }
            }
        }
    }

    /// Cancels in-flight descriptor requests and waits for all of them to
    /// complete.
    ///
    /// Requests like reading from a tap device may never complete by
    /// themselves, and closing the ring does not wait for the kernel to
    /// finish them. Without draining, the kernel could still write into
    /// guest memory after the worker releases the memory layout, i.e.
    /// after the memory may be unmapped and reused.
    ///
    /// The results are discarded. The device is being reset or shut down,
    /// so the guest does not expect the chains back.
    ///
    /// Some requests cannot be cancelled, e.g. block I/O on a hung NFS
    /// mount. Waiting is bounded by [`DRAIN_TIMEOUT`] so that a reset or a
    /// VM shutdown does not hang forever. If requests are still in flight
    /// after that, or draining fails, guest memory is leaked instead: it
    /// stays mapped even after it is removed from the guest.
    fn drain(&mut self) -> Result<()> {
        let ret = self.try_drain();
        match &ret {
            Ok(0) => {}
            Ok(n) => log::error!(
                "{n} io_uring requests still in flight after {DRAIN_TIMEOUT:?}, leaking guest memory"
            ),
            Err(e) => {
                log::error!("failed to drain io_uring requests, leaking guest memory: {e:?}")
            }
        }
        if !matches!(ret, Ok(0)) {
            for (_, pages) in self.mem.iter() {
                std::mem::forget(pages.clone());
            }
        }
        self.submit_counts.fill(0);
        ret.map(|_| ())
    }

    /// Returns the number of requests still in flight at the deadline.
    fn try_drain(&mut self) -> Result<usize> {
        let mut in_flight: usize = self.submit_counts.iter().map(|c| *c as usize).sum();
        if in_flight == 0 {
            return Ok(0);
        }
        // Cancel every request in the ring at once. This also ends the
        // polls on the notifiers, which is fine since the loop is done.
        let cancel = opcode::AsyncCancel2::new(types::CancelBuilder::any())
            .build()
            .user_data(TOKEN_CANCEL);
        while unsafe { self.ring.submission().push(&cancel) }.is_err() {
            self.ring.submit()?;
        }
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while in_flight > 0 {
            let Some(timeout) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let timeout = types::Timespec::from(timeout);
            let args = types::SubmitArgs::new().timespec(&timeout);
            match self.ring.submitter().submit_with_args(1, &args) {
                Ok(_) => {}
                Err(e) if matches!(e.raw_os_error(), Some(libc::ETIME | libc::EINTR)) => {}
                Err(e) => return Err(e.into()),
            }
            let done = (self.ring.completion())
                .filter(|cqe| cqe.user_data() & TOKEN_DESCRIPTOR == TOKEN_DESCRIPTOR)
                .count();
            in_flight = in_flight.saturating_sub(done);
        }
        Ok(in_flight)
    }

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

impl<'m, D, Q, S> ActiveBackend<D> for ActiveIoUring<'_, '_, 'm, Q, S>
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
            let q_index = buffer_key as u16;
            let chain_id = (buffer_key >> 16) as u16;
            // Account for the completion first, so that drain() never waits
            // for a request that has already completed.
            if let Some(submit_count) = self.submit_counts.get_mut(q_index as usize) {
                if *submit_count > QUEUE_RESERVE_SIZE {
                    self.shared_count += 1;
                }
                *submit_count = submit_count.saturating_sub(1);
            }
            let Some(Some(queue)) = self.queues.get_mut(q_index as usize) else {
                log::error!("{}: invalid queue index {q_index}", dev.name());
                return Ok(());
            };
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

#[cfg(test)]
#[path = "io_uring_test.rs"]
mod tests;
