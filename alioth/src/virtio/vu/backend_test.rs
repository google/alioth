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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flume::{Receiver, Sender};

use crate::mem;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::RamBus;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{VirtioDevice, WakeEvent, WorkerCtl, WorkerReport};
use crate::virtio::queue::QueueReg;
use crate::virtio::vu::backend::{VuBackend, VuIrqSender};
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

type TestWakeReceiver = Receiver<WakeEvent<VuIrqSender>>;

/// Serves a device with one queue, whose worker is `worker`, on a backend
/// thread. Returns the frontend end of the connection and the thread.
///
/// The thread joins the worker after the frontend disconnects.
fn spawn_backend<W>(worker: W) -> (VuSession, JoinHandle<()>)
where
    W: FnOnce(TestWakeReceiver, Sender<WorkerReport>) + Send + 'static,
{
    let (event_tx, event_rx) = flume::unbounded();
    let (report_tx, report_rx) = flume::unbounded();
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
            report_rx,
        )),
        worker_handle: None,
    };
    let worker = thread::spawn(move || worker(event_rx, report_tx));

    let (frontend_conn, backend_conn) = UnixStream::pair().unwrap();
    let mut backend = VuBackend::new(backend_conn, dev, Arc::new(RamBus::new())).unwrap();
    let backend_thread = thread::spawn(move || {
        backend.run().unwrap();
        // Dropping the backend disconnects the worker.
        drop(backend);
        worker.join().unwrap();
    });
    (VuSession::from(frontend_conn), backend_thread)
}

fn driver_ok() -> u64 {
    let status = DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK;
    status.bits() as u64
}

/// Starts the device. The backend takes the kick fd for each start.
fn start(frontend: &VuSession) {
    let kick = Notifier::new().unwrap();
    frontend.set_virtq_kick(&0, kick.as_fd()).unwrap();
    frontend.set_status(&driver_ok()).unwrap();
}

#[test]
fn test_vu_backend_stops_worker_before_reply() {
    // A fake worker that takes a while to stop.
    let starts = Arc::new(AtomicU32::new(0));
    let stopped = Arc::new(AtomicBool::new(false));
    let (worker_starts, worker_stopped) = (starts.clone(), stopped.clone());
    let (frontend, backend_thread) = spawn_backend(move |event_rx, report_tx| {
        for event in event_rx.iter() {
            match event {
                WakeEvent::Start { .. } => {
                    worker_starts.fetch_add(1, Ordering::AcqRel);
                }
                WakeEvent::Reset { seq } => {
                    thread::sleep(Duration::from_millis(50));
                    worker_stopped.store(true, Ordering::Release);
                    report_tx.send(WorkerReport::ResetDone { seq }).unwrap();
                }
                event => panic!("unexpected event: {event:?}"),
            }
        }
    });

    // The reply to SET_STATUS(0) means that the worker has stopped.
    start(&frontend);
    frontend.set_status(&0).unwrap();
    assert!(stopped.swap(false, Ordering::AcqRel));

    // So does the reply to GET_VRING_BASE.
    start(&frontend);
    let virtq_base = VirtqState { index: 0, val: 0 };
    assert_eq!(frontend.get_virtq_base(&virtq_base).unwrap().val, 0);
    assert!(stopped.swap(false, Ordering::AcqRel));

    // The worker has already stopped, so there is nothing left to stop.
    frontend.set_status(&0).unwrap();
    assert!(!stopped.load(Ordering::Acquire));

    drop(frontend);
    backend_thread.join().unwrap();
    assert_eq!(starts.load(Ordering::Acquire), 2);
}

#[test]
fn test_vu_backend_needs_reset_after_worker_failure() {
    // A fake worker that fails as soon as it starts.
    let (frontend, backend_thread) = spawn_backend(move |event_rx, report_tx| {
        for event in event_rx.iter() {
            let report = match event {
                WakeEvent::Start { .. } => WorkerReport::Failed,
                WakeEvent::Reset { seq } => WorkerReport::ResetDone { seq },
                event => panic!("unexpected event: {event:?}"),
            };
            report_tx.send(report).unwrap();
        }
    });

    start(&frontend);
    let needs_reset = driver_ok() | DevStatus::NEEDS_RESET.bits() as u64;
    let deadline = Instant::now() + Duration::from_secs(5);
    while frontend.get_status().unwrap() != needs_reset {
        assert!(Instant::now() < deadline, "no DEVICE_NEEDS_RESET");
        thread::sleep(Duration::from_millis(1));
    }

    // Resetting the device brings it back into service.
    frontend.set_status(&0).unwrap();
    assert_eq!(frontend.get_status().unwrap(), 0);

    drop(frontend);
    backend_thread.join().unwrap();
}
