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

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::mem;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::RamBus;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{VirtioDevice, WakeEvent, WorkerCtl};
use crate::virtio::queue::QueueReg;
use crate::virtio::vu::backend::VuBackend;
use crate::virtio::vu::bindings::VirtqState;
use crate::virtio::vu::conn::VuSession;
use crate::virtio::{DevStatus, DeviceId};

#[derive(Debug)]
struct TestDevConfig;

impl Mmio for TestDevConfig {
    fn size(&self) -> u64 {
        0
    }

    fn read(&self, _offset: u64, _size: u8) -> mem::Result<u64> {
        Ok(0)
    }

    fn write(&self, _offset: u64, _size: u8, _val: u64) -> mem::Result<Action> {
        Ok(Action::None)
    }
}

#[test]
fn test_vu_backend_stops_worker_before_reply() {
    let (event_tx, event_rx) = flume::unbounded();
    let (reset_tx, reset_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let dev = VirtioDevice {
        name: "vu-backend".into(),
        id: DeviceId::NET,
        device_config: Arc::new(TestDevConfig),
        device_feature: 0,
        queue_regs: Arc::new([QueueReg::default()]),
        shared_mem_regions: None,
        ctl: Arc::new(WorkerCtl::new(
            "vu-backend".into(),
            event_tx,
            notifier,
            reset_rx,
        )),
        worker_handle: None,
    };

    // A fake worker that takes a while to stop.
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = stopped.clone();
    let worker = thread::spawn(move || {
        let mut starts = 0;
        for event in event_rx.iter() {
            match event {
                WakeEvent::Start { .. } => starts += 1,
                WakeEvent::Reset { seq } => {
                    thread::sleep(Duration::from_millis(50));
                    worker_stopped.store(true, Ordering::Release);
                    reset_tx.send(seq).unwrap();
                }
                event => panic!("unexpected event: {event:?}"),
            }
        }
        starts
    });

    let (frontend_conn, backend_conn) = UnixStream::pair().unwrap();
    let mut backend = VuBackend::new(backend_conn, dev, Arc::new(RamBus::new())).unwrap();
    let backend_thread = thread::spawn(move || backend.run().unwrap());

    let frontend = VuSession::from(frontend_conn);
    let kick = Notifier::new().unwrap();
    let driver_ok =
        DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK;
    let driver_ok = driver_ok.bits() as u64;

    // The reply to SET_STATUS(0) means that the worker has stopped.
    frontend.set_virtq_kick(&0, kick.as_fd()).unwrap();
    frontend.set_status(&driver_ok).unwrap();
    frontend.set_status(&0).unwrap();
    assert!(stopped.swap(false, Ordering::AcqRel));

    // So does the reply to GET_VRING_BASE.
    frontend.set_virtq_kick(&0, kick.as_fd()).unwrap();
    frontend.set_status(&driver_ok).unwrap();
    let virtq_base = VirtqState { index: 0, val: 0 };
    assert_eq!(frontend.get_virtq_base(&virtq_base).unwrap().val, 0);
    assert!(stopped.swap(false, Ordering::AcqRel));

    // The worker has already stopped, so there is nothing left to stop.
    frontend.set_status(&0).unwrap();
    assert!(!stopped.load(Ordering::Acquire));

    drop(frontend);
    backend_thread.join().unwrap();
    // Dropping the backend disconnects the worker.
    assert_eq!(worker.join().unwrap(), 2);
}
