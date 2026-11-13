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

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use assert_matches::assert_matches;
use libc::{EFD_CLOEXEC, EFD_NONBLOCK};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rstest::rstest;
use zerocopy::IntoBytes;

use crate::ffi;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::Virtio;
use crate::virtio::queue::Queue;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::tests::{fixture_queues, fixture_ram_bus};
use crate::virtio::vu::Error as VuError;
use crate::virtio::vu::bindings::{VirtqAddr, VirtqState, VuFeature, VuFrontMsg};
use crate::virtio::vu::conn::VuSession;
use crate::virtio::vu::frontend::VuFrontend;
use crate::virtio::worker::mio::{ActiveMio, VirtioMio};
use crate::virtio::{DeviceId, Error, IrqSender, Result, VirtioFeature};

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
#[case(VirtioFeature::VERSION_1, true, 0)]
#[case(VirtioFeature::VERSION_1, false, 0)]
#[case(
    VirtioFeature::VERSION_1 | VirtioFeature::RING_PACKED,
    true,
    (1 << 15) | (1 << 31)
)]
fn test_vu_frontend_activate_vring_base(
    #[case] drv_feat: VirtioFeature,
    #[case] has_vhost_proto: bool,
    #[case] expected: u32,
) {
    let (frontend_conn, backend_conn) = UnixStream::pair().unwrap();
    let backend = VuSession::from(backend_conn);
    let backend_thread = thread::spawn(move || {
        let mut fds = [const { None }; 8];
        let mut set_feat = None;
        let mut bases = vec![];
        while let Ok(msg) = backend.recv_msg(&mut fds) {
            let req = VuFrontMsg::from(msg.request);
            match req {
                VuFrontMsg::SET_FEATURES => {
                    let feat: u64 = backend.recv_payload().unwrap();
                    set_feat = Some(feat);
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                VuFrontMsg::SET_VIRTQ_KICK
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
        (set_feat, bases)
    });

    let mut device_feature = drv_feat.bits() as u64;
    if has_vhost_proto {
        device_feature |= VirtioFeature::VHOST_PROTOCOL.bits() as u64;
    }
    let mut frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::STATUS,
        device_feature,
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

    let (set_feat, bases) = backend_thread.join().unwrap();
    assert_eq!(set_feat, Some(device_feature));
    assert_eq!(bases, [(0, expected), (1, expected)]);
}

#[test]
fn test_vu_frontend_feature_filtering() {
    let (frontend_conn, _backend_conn) = UnixStream::pair().unwrap();
    let dev_low = (1 << 0) | (1 << 5) | (1 << 23);
    let dev_high = (1 << 50) | (1 << 57) | (1 << 63);
    let supported_transport = (VirtioFeature::INDIRECT_DESC
        | VirtioFeature::EVENT_IDX
        | VirtioFeature::VERSION_1
        | VirtioFeature::ACCESS_PLATFORM
        | VirtioFeature::RING_PACKED)
        .bits() as u64;
    // VHOST_PROTOCOL (30) plus unsupported/reserved transport bits:
    // NOTIFY_ON_EMPTY (24), ANY_LAYOUT (27), IN_ORDER (35),
    // NOTIFICATION_DATA (38), RING_RESET (40), ADMIN_VQ (41), SUSPEND (43),
    // and reserved bit 49.
    let unsupported_transport = VirtioFeature::VHOST_PROTOCOL.bits() as u64
        | (1 << 24)
        | (1 << 27)
        | (1 << 35)
        | (1 << 38)
        | (1 << 40)
        | (1 << 41)
        | (1 << 43)
        | (1 << 49);

    let frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::empty(),
        device_feature: dev_low | dev_high | supported_transport | unsupported_transport,
        num_queues: 1,
        err_fds: Box::default(),
    };

    let exposed = frontend.feature();
    assert_eq!(exposed, (dev_low | dev_high | supported_transport) as u128);
    assert_eq!(exposed & VirtioFeature::VHOST_PROTOCOL.bits(), 0);
    assert_eq!(exposed & (unsupported_transport as u128), 0);
}

#[test]
fn test_vu_frontend_handle_event_returns_queue_err() {
    let (frontend_conn, _backend_conn) = UnixStream::pair().unwrap();
    let err_fd_0 =
        unsafe { File::from_raw_fd(ffi!(libc::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)).unwrap()) };
    let err_fd_1 =
        unsafe { File::from_raw_fd(ffi!(libc::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)).unwrap()) };
    let mut writer_1 = err_fd_1.try_clone().unwrap();

    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(
            &mut SourceFd(&err_fd_1.as_raw_fd()),
            Token(1),
            Interest::READABLE,
        )
        .unwrap();

    let mut frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::empty(),
        device_feature: 0,
        num_queues: 2,
        err_fds: Box::new([err_fd_0, err_fd_1]),
    };

    writer_1.write_all(1u64.as_bytes()).unwrap();
    let mut events = Events::with_capacity(4);
    poll.poll(&mut events, Some(Duration::from_secs(5)))
        .unwrap();
    let event = events.iter().next().unwrap();

    let mut queues: [Option<Queue<SplitQueue>>; 0] = [];
    let irq_sender = TestIrqSender::default();
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &[],
        poll: &mut poll,
    };

    let ret = frontend.handle_event(event, &mut active_mio);
    assert_matches!(
        ret,
        Err(Error::Vu { source, .. }) if matches!(*source, VuError::QueueErr { index: 1, .. })
    );
    // The error eventfd was drained so re-arming after reset does not loop.
    assert_matches!(
        writer_1.read(&mut [0u8; 8]),
        Err(e) if e.kind() == ErrorKind::WouldBlock
    );
}

#[test]
fn test_vu_frontend_handle_queue() {
    let (frontend_conn, _backend_conn) = UnixStream::pair().unwrap();
    let mut frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::empty(),
        device_feature: 0,
        num_queues: 1,
        err_fds: Box::default(),
    };

    let mut poll = Poll::new().unwrap();
    let mut kick = Notifier::new().unwrap();
    poll.registry()
        .register(&mut kick, Token(0), Interest::READABLE)
        .unwrap();
    let notifiers = [kick];
    let mut queues: [Option<Queue<SplitQueue>>; 0] = [];
    let irq_sender = TestIrqSender::default();
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &notifiers,
        poll: &mut poll,
    };

    // With a kick notifier available, handle_queue forwards the notification.
    assert_matches!(frontend.handle_queue(0, &mut active_mio), Ok(()));
    let mut events = Events::with_capacity(1);
    active_mio
        .poll
        .poll(&mut events, Some(Duration::from_secs(5)))
        .unwrap();
    assert!(!events.is_empty());

    // Without a kick notifier (out-of-range queue), handle_queue logs and does not panic.
    assert_matches!(frontend.handle_queue(1, &mut active_mio), Ok(()));
}
