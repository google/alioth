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

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::thread::JoinHandle;

use flume::Receiver;
use mio::event::Event;
#[cfg(target_os = "linux")]
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use snafu::ResultExt;

use crate::mem::mapped::{Ram, RamBus};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{
    ActiveBackend, Backend, BackendEvent, Context, StartParam, Virtio, WakeEvent, Worker,
    WorkerState,
};
use crate::virtio::queue::{Queue, QueueReg, VirtQueue};
use crate::virtio::{IrqSender, Result, error};

pub trait VirtioMio: Virtio {
    fn activate<'m, Q, S>(
        &mut self,
        feature: u128,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender;

    fn handle_queue<'m, Q, S>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender;

    fn handle_event<'m, Q, S>(
        &mut self,
        event: &Event,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender;

    fn reset(&mut self, registry: &Registry);
}

impl BackendEvent for Event {
    fn token(&self) -> u64 {
        self.token().0 as u64
    }
}

const TOKEN_QUEUE: u64 = 1 << 62;

pub struct Mio {
    poll: Poll,
}

impl Mio {
    pub fn spawn_worker<D, S>(
        dev: D,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        D: VirtioMio,
        S: IrqSender,
    {
        let poll = Poll::new().context(error::CreatePoll)?;
        let m = Mio { poll };
        Worker::spawn(dev, m, event_rx, memory, queue_regs)
    }
}

impl<D> Backend<D> for Mio
where
    D: VirtioMio,
{
    fn register_notifier(&mut self, token: u64) -> Result<Arc<Notifier>> {
        let mut notifier = Notifier::new()?;
        let registry = self.poll.registry();
        registry.register(&mut notifier, Token(token as usize), Interest::READABLE)?;
        Ok(Arc::new(notifier))
    }

    fn reset(&self, dev: &mut D) -> Result<()> {
        dev.reset(self.poll.registry());
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
        let mut events = Events::with_capacity(128);
        let mut active_mio = ActiveMio {
            queues,
            irq_sender: &*param.irq_sender,
            notifiers: param.notifiers.as_deref().unwrap_or(&[]),
            poll: &mut self.poll,
            mem: memory,
        };
        context.dev.activate(param.feature, &mut active_mio)?;
        // Only KVM offers ioeventfds, see [`crate::hv::NotifierRegistry`].
        #[cfg(target_os = "linux")]
        for (index, notifier) in active_mio.notifiers.iter().enumerate() {
            if context.dev.notifier_offloaded(index as u16)? {
                continue;
            }
            let token = index as u64 | TOKEN_QUEUE;
            let registry = active_mio.poll.registry();
            registry
                .register(
                    &mut SourceFd(&notifier.as_fd().as_raw_fd()),
                    Token(token as usize),
                    Interest::READABLE,
                )
                .context(error::EventSource)?;
        }
        'out: loop {
            active_mio
                .poll
                .poll(&mut events, None)
                .context(error::PollEvents)?;
            for event in events.iter() {
                context.handle_event(event, &mut active_mio)?;
                if context.state != WorkerState::Running {
                    break 'out;
                }
            }
        }
        #[cfg(target_os = "linux")]
        for (index, notifier) in active_mio.notifiers.iter().enumerate() {
            if context.dev.notifier_offloaded(index as u16)? {
                continue;
            }
            let registry = active_mio.poll.registry();
            registry
                .deregister(&mut SourceFd(&notifier.as_fd().as_raw_fd()))
                .context(error::EventSource)?;
        }
        Ok(())
    }
}

pub struct ActiveMio<'a, 'r, 'm, Q, S>
where
    Q: VirtQueue<'m>,
{
    pub queues: &'a mut [Option<Queue<'r, 'm, Q>>],
    pub irq_sender: &'a S,
    pub notifiers: &'a [Notifier],
    pub poll: &'a mut Poll,
    pub mem: &'m Ram,
}

impl<'m, D, Q, S> ActiveBackend<D> for ActiveMio<'_, '_, 'm, Q, S>
where
    D: VirtioMio,
    Q: VirtQueue<'m>,
    S: IrqSender,
{
    type Event = Event;

    fn handle_event(&mut self, dev: &mut D, event: &Self::Event) -> Result<()> {
        let token = event.token().0 as u64;
        if token & TOKEN_QUEUE == TOKEN_QUEUE {
            dev.handle_queue(token as u16, self)
        } else {
            dev.handle_event(event, self)
        }
    }

    fn handle_queue(&mut self, dev: &mut D, index: u16) -> Result<()> {
        dev.handle_queue(index, self)
    }
}
