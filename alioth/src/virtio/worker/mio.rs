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

use std::os::fd::AsRawFd;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::JoinHandle;

use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use snafu::ResultExt;

use crate::hv::IoeventFd;
use crate::mem::mapped::{Ram, RamBus};
use crate::virtio::dev::{
    ActiveBackend, Backend, BackendEvent, Context, Virtio, WakeEvent, Worker, WorkerState,
};
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::worker::Waker;
use crate::virtio::{error, IrqSender, Result};

pub trait VirtioMio: Virtio {
    fn activate<'m, S: IrqSender, Q: VirtQueue<'m>>(
        &mut self,
        registry: &Registry,
        feature: u64,
        memory: &'m Ram,
        irq_sender: &S,
        queues: &mut [Option<Q>],
    ) -> Result<()>;
    fn handle_queue<'m, Q>(
        &mut self,
        index: u16,
        queues: &mut [Option<Q>],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>;
    fn handle_event<'m, Q>(
        &mut self,
        event: &Event,
        queues: &mut [Option<Q>],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>;

    fn reset(&mut self, registry: &Registry);
}

impl BackendEvent for Event {
    fn token(&self) -> u64 {
        self.token().0 as u64
    }
}

const TOKEN_QUEUE: u64 = 1 << 62;

pub struct Mio<E> {
    poll: Poll,
    _queue_ioeventfds: Arc<[(E, bool)]>,
}

impl<E> Mio<E>
where
    E: IoeventFd,
{
    pub fn spawn_worker<D, S>(
        dev: D,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
        fds: Arc<[(E, bool)]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
    where
        D: VirtioMio,
        S: IrqSender,
    {
        let poll = Poll::new().context(error::CreatePoll)?;
        for (index, (fd, offloaded)) in fds.iter().enumerate() {
            if *offloaded {
                continue;
            }
            let token = index as u64 | TOKEN_QUEUE;
            poll.registry()
                .register(
                    &mut SourceFd(&fd.as_fd().as_raw_fd()),
                    Token(token as usize),
                    Interest::READABLE,
                )
                .context(error::EventSource)?;
        }
        let m = Mio {
            poll,
            _queue_ioeventfds: fds,
        };
        Worker::spawn(dev, m, event_rx, memory, queue_regs)
    }
}

impl<D, E> Backend<D> for Mio<E>
where
    D: VirtioMio,
    E: IoeventFd,
{
    fn register_waker(&mut self, token: u64) -> Result<Arc<Waker>> {
        #[cfg(target_os = "linux")]
        {
            let waker = Waker::new_eventfd()?;
            self.poll.registry().register(
                &mut SourceFd(&waker.0.as_raw_fd()),
                Token(token as usize),
                Interest::READABLE,
            )?;
            Ok(Arc::new(waker))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let waker = ::mio::Waker::new(self.poll.registry(), Token(token as usize))
                .context(error::CreateWaker)?;
            Ok(Arc::new(Waker(waker)))
        }
    }

    fn reset(&self, dev: &mut D) -> Result<()> {
        dev.reset(self.poll.registry());
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
        context
            .dev
            .activate(self.poll.registry(), feature, memory, irq_sender, queues)?;

        let mut events = Events::with_capacity(128);
        let mut active_mio = ActiveMio {
            queues,
            irq_sender,
            poll: &mut self.poll,
        };
        'out: loop {
            active_mio
                .poll
                .poll(&mut events, None)
                .context(error::PollEvents)?;
            for event in events.iter() {
                context.handle_event(event, &mut active_mio)?;
                if context.state != WorkerState::Running {
                    break 'out Ok(());
                }
            }
        }
    }
}

struct ActiveMio<'a, Q, S> {
    queues: &'a mut [Option<Q>],
    irq_sender: &'a S,
    poll: &'a mut Poll,
}

impl<'a, 'm, Q, S, D> ActiveBackend<D> for ActiveMio<'a, Q, S>
where
    D: VirtioMio,
    Q: VirtQueue<'m>,
    S: IrqSender,
{
    type Event = Event;
    fn handle_event(&mut self, dev: &mut D, event: &Self::Event) -> Result<()> {
        let token = event.token().0 as u64;
        let registry = self.poll.registry();
        if token & TOKEN_QUEUE == TOKEN_QUEUE {
            dev.handle_queue(token as u16, self.queues, self.irq_sender, registry)
        } else {
            dev.handle_event(event, self.queues, self.irq_sender, registry)
        }
    }

    fn handle_queue(&mut self, dev: &mut D, index: u16) -> Result<()> {
        let registry = self.poll.registry();
        dev.handle_queue(index, self.queues, self.irq_sender, registry)
    }
}
