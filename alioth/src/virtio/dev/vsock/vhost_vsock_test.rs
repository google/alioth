// Copyright 2026 Google LLC
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

use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use mio::{Events, Interest, Poll, Token};
use rstest::rstest;

use crate::sync::notifier::Notifier;
use crate::virtio::dev::vsock::VsockConfig;
use crate::virtio::dev::vsock::vhost_vsock::{self, VhostVsock};
use crate::virtio::queue::Queue;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::vhost::{Error as VhostError, VhostDev};
use crate::virtio::worker::mio::{ActiveMio, VirtioMio};
use crate::virtio::{Error, IrqSender, Result, VirtioFeature};

#[derive(Debug)]
struct DummyIrqSender;

impl IrqSender for DummyIrqSender {
    fn queue_irq(&self, _idx: u16) {}

    fn config_irq(&self) {}

    fn queue_irqfd<F, T>(&self, _idx: u16, _f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        unimplemented!()
    }

    fn config_irqfd<F, T>(&self, _f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        unimplemented!()
    }
}

#[rstest]
#[case(VirtioFeature::VERSION_1, 0)]
#[case(VirtioFeature::VERSION_1 | VirtioFeature::RING_PACKED, (1 << 15) | (1 << 31))]
fn test_vring_base_init(#[case] feat: VirtioFeature, #[case] expected: u32) {
    assert_eq!(vhost_vsock::vring_base_init(feat.bits()), expected);
}

#[test]
fn test_vhost_vsock_handle_event_and_queue() {
    let mut dev = VhostVsock {
        name: "vhost-vsock".into(),
        vhost_dev: Arc::new(VhostDev::new("/dev/null").unwrap()),
        config: VsockConfig::default(),
        features: VirtioFeature::VERSION_1.bits() as u64,
        error_fds: [None, None],
    };

    let mut poll = Poll::new().unwrap();
    let mut kick_0 = Notifier::new().unwrap();
    poll.registry()
        .register(&mut kick_0, Token(1), Interest::READABLE)
        .unwrap();
    kick_0.notify().unwrap();

    let mut events = Events::with_capacity(4);
    poll.poll(&mut events, Some(Duration::from_secs(5)))
        .unwrap();
    let event = events.iter().next().unwrap();

    let notifiers = [kick_0];
    let mut queues: [Option<Queue<SplitQueue>>; 0] = [];
    let irq_sender = DummyIrqSender;
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &notifiers,
        poll: &mut poll,
    };

    let ret = dev.handle_event(event, &mut active_mio);
    assert_matches!(
        ret,
        Err(Error::Vhost { source, .. })
            if matches!(*source, VhostError::VhostQueueErr { dev: "vsock", index: 1, .. })
    );

    assert_matches!(dev.handle_queue(0, &mut active_mio), Ok(()));
    assert_matches!(dev.handle_queue(1, &mut active_mio), Ok(()));
    assert_matches!(dev.handle_queue(2, &mut active_mio), Ok(()));
    assert_matches!(dev.handle_queue(3, &mut active_mio), Ok(()));
}
