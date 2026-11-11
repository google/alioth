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

use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use mio::Poll;
use rstest::rstest;

use crate::sync::notifier::Notifier;
use crate::virtio::queue::Queue;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::tests::{fixture_queues, fixture_ram_bus};
use crate::virtio::vu::bindings::{VirtqAddr, VirtqState, VuFeature, VuFrontMsg};
use crate::virtio::vu::conn::VuSession;
use crate::virtio::vu::frontend::VuFrontend;
use crate::virtio::worker::mio::{ActiveMio, VirtioMio};
use crate::virtio::{DeviceId, IrqSender, Result, VirtioFeature};

#[derive(Debug)]
struct TestIrqSender {
    irqfd: Notifier,
}

impl Default for TestIrqSender {
    fn default() -> Self {
        Self {
            irqfd: Notifier::new().unwrap(),
        }
    }
}

impl IrqSender for TestIrqSender {
    fn queue_irq(&self, _idx: u16) {}

    fn config_irq(&self) {}

    fn queue_irqfd<F, T>(&self, _idx: u16, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        f(self.irqfd.as_fd())
    }

    fn config_irqfd<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        f(self.irqfd.as_fd())
    }
}

#[test]
fn test_vu_frontend_reset_stops_rings() {
    let (frontend_conn, backend_conn) = UnixStream::pair().unwrap();
    let backend = VuSession::from(backend_conn);
    let backend_thread = thread::spawn(move || {
        let mut fds = [const { None }; 8];
        let mut requests = vec![];
        while let Ok(msg) = backend.recv_msg(&mut fds) {
            let req = VuFrontMsg::from(msg.request);
            match req {
                VuFrontMsg::GET_VIRTQ_BASE => {
                    let mut virtq_base: VirtqState = backend.recv_payload().unwrap();
                    requests.push((req, virtq_base.index as u64));
                    virtq_base.val = 0;
                    backend.reply(req, &virtq_base, &[]).unwrap();
                }
                VuFrontMsg::SET_VIRTQ_ENABLE => {
                    let virtq_enable: VirtqState = backend.recv_payload().unwrap();
                    assert_eq!(virtq_enable.val, 0);
                    requests.push((req, virtq_enable.index as u64));
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                VuFrontMsg::SET_STATUS => {
                    let status: u64 = backend.recv_payload().unwrap();
                    requests.push((req, status));
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                req => panic!("unexpected request: {req:?}"),
            }
        }
        requests
    });

    let mut frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::STATUS,
        device_feature: 0,
        num_queues: 2,
        err_fds: Box::default(),
    };
    let poll = Poll::new().unwrap();
    frontend.reset(poll.registry());
    drop(frontend);

    // Every ring is stopped before the device is reset.
    let requests = backend_thread.join().unwrap();
    assert_eq!(
        requests,
        [
            (VuFrontMsg::GET_VIRTQ_BASE, 0),
            (VuFrontMsg::SET_VIRTQ_ENABLE, 0),
            (VuFrontMsg::GET_VIRTQ_BASE, 1),
            (VuFrontMsg::SET_VIRTQ_ENABLE, 1),
            (VuFrontMsg::SET_STATUS, 0),
        ]
    );
}

#[rstest]
#[case(VirtioFeature::VERSION_1, 0)]
#[case(VirtioFeature::VERSION_1 | VirtioFeature::RING_PACKED, (1 << 15) | (1 << 31))]
fn test_vu_frontend_activate_vring_base(#[case] drv_feat: VirtioFeature, #[case] expected: u32) {
    let (frontend_conn, backend_conn) = UnixStream::pair().unwrap();
    let backend = VuSession::from(backend_conn);
    let backend_thread = thread::spawn(move || {
        let mut fds = [const { None }; 8];
        let mut bases = vec![];
        while let Ok(msg) = backend.recv_msg(&mut fds) {
            let req = VuFrontMsg::from(msg.request);
            match req {
                VuFrontMsg::SET_FEATURES
                | VuFrontMsg::SET_VIRTQ_KICK
                | VuFrontMsg::SET_VIRTQ_CALL
                | VuFrontMsg::SET_STATUS => {
                    let _: u64 = backend.recv_payload().unwrap();
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                VuFrontMsg::SET_VIRTQ_NUM | VuFrontMsg::SET_VIRTQ_ENABLE => {
                    let _: VirtqState = backend.recv_payload().unwrap();
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                VuFrontMsg::SET_VIRTQ_BASE => {
                    let state: VirtqState = backend.recv_payload().unwrap();
                    bases.push((state.index, state.val));
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                VuFrontMsg::SET_VIRTQ_ADDR => {
                    let _: VirtqAddr = backend.recv_payload().unwrap();
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                req => panic!("unexpected request: {req:?}"),
            }
        }
        bases
    });

    let mut frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::STATUS,
        device_feature: (drv_feat | VirtioFeature::VHOST_PROTOCOL).bits() as u64,
        num_queues: 2,
        err_fds: Box::default(),
    };

    let ram_bus = Arc::new(fixture_ram_bus());
    let queue_regs = fixture_queues(2);
    let mut queues: Box<_> = queue_regs
        .iter()
        .map(|reg| Queue::<SplitQueue>::new(reg, ram_bus.clone(), false))
        .collect::<Result<_>>()
        .unwrap();
    let irq_sender = TestIrqSender::default();
    let notifiers = [Notifier::new().unwrap(), Notifier::new().unwrap()];
    let mut poll = Poll::new().unwrap();
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &notifiers,
        poll: &mut poll,
    };

    frontend.activate(drv_feat.bits(), &mut active_mio).unwrap();
    drop(frontend);

    let bases = backend_thread.join().unwrap();
    assert_eq!(bases, [(0, expected), (1, expected)]);
}
