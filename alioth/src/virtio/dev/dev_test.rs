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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use assert_matches::assert_matches;
use mio::Registry;
use mio::event::Event;

use crate::sync::notifier::Notifier;
use crate::virtio::dev::entropy::{EntropyConfig, EntropyFeature};
use crate::virtio::dev::{Register, StartParam, Virtio, WakeEvent, WorkerCtl, WorkerParam};
use crate::virtio::queue::VirtQueue;
use crate::virtio::tests::{FakeIrqSender, fixture_queues, fixture_ram_bus};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, Error, IrqSender, Result, VirtioFeature, error};

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn test_virtio_register_get_driver_feature() {
    let reg = Register::default();
    assert_eq!(reg.get_driver_feature(), 0);

    reg.driver_feature[0].store(0x1234_5678, Ordering::Release);
    reg.driver_feature[1].store(0x9abc_def0, Ordering::Release);
    reg.driver_feature[2].store(0xfeed_cafe, Ordering::Release);
    reg.driver_feature[3].store(0x0123_4567, Ordering::Release);

    let expected = (0x1234_5678u128)
        | ((0x9abc_def0u128) << 32)
        | ((0xfeed_cafeu128) << 64)
        | ((0x0123_4567u128) << 96);
    assert_eq!(reg.get_driver_feature(), expected);
}

/// A device that only records what the worker does to it.
///
/// It borrows the config and feature types of the entropy device, which
/// has neither.
#[derive(Debug, Default)]
struct FakeDev {
    /// Makes activation fail, like a backend rejecting the driver setup.
    fail_activate: Arc<AtomicBool>,
    /// Counts the calls to [`VirtioMio::reset`].
    resets: Arc<AtomicU32>,
}

impl Virtio for FakeDev {
    type Config = EntropyConfig;
    type Feature = EntropyFeature;

    fn name(&self) -> &str {
        "fake"
    }

    fn id(&self) -> DeviceId {
        DeviceId::ENTROPY
    }

    fn num_queues(&self) -> u16 {
        1
    }

    fn config(&self) -> Arc<EntropyConfig> {
        Arc::new(EntropyConfig)
    }

    fn feature(&self) -> u128 {
        0
    }

    fn spawn_worker<S>(self, param: WorkerParam<S>) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
    {
        Mio::spawn_worker(self, param)
    }
}

impl VirtioMio for FakeDev {
    fn activate<'m, Q, S>(
        &mut self,
        _feature: u128,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        if self.fail_activate.load(Ordering::Acquire) {
            return error::InvalidBuffer.fail();
        }
        Ok(())
    }

    fn handle_queue<'m, Q, S>(
        &mut self,
        _index: u16,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        Ok(())
    }

    fn handle_event<'m, Q, S>(
        &mut self,
        _event: &Event,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        Ok(())
    }

    fn reset(&mut self, _registry: &Registry) {
        self.resets.fetch_add(1, Ordering::AcqRel);
    }
}

struct TestWorker {
    ctl: WorkerCtl<FakeIrqSender>,
    handle: JoinHandle<()>,
    fail_activate: Arc<AtomicBool>,
    resets: Arc<AtomicU32>,
}

impl TestWorker {
    fn spawn() -> Self {
        let dev = FakeDev::default();
        let fail_activate = dev.fail_activate.clone();
        let resets = dev.resets.clone();
        let (event_tx, event_rx) = flume::unbounded();
        let (reset_tx, reset_rx) = flume::unbounded();
        let param = WorkerParam {
            event_rx,
            reset_tx,
            memory: Arc::new(fixture_ram_bus()),
            queue_regs: Arc::from(fixture_queues(1)),
        };
        let (handle, notifier) = dev.spawn_worker(param).unwrap();
        TestWorker {
            ctl: WorkerCtl::new("fake".into(), event_tx, notifier, reset_rx),
            handle,
            fail_activate,
            resets,
        }
    }

    fn start(&self) {
        let (q_tx, _) = flume::unbounded();
        let param = StartParam {
            feature: VirtioFeature::VERSION_1.bits(),
            irq_sender: Arc::new(FakeIrqSender { q_tx }),
            notifiers: None,
        };
        assert!(self.ctl.wake(WakeEvent::Start { param }));
    }

    fn reset(&self) {
        let seq = self.ctl.request_reset();
        assert_matches!(self.ctl.wait_reset(seq, TIMEOUT), Ok(()));
        assert!(self.ctl.poll_reset(seq));
    }

    fn resets(&self) -> u32 {
        self.resets.load(Ordering::Acquire)
    }

    fn shutdown(self) {
        assert!(self.ctl.wake(WakeEvent::Shutdown));
        self.handle.join().unwrap();
    }
}

#[test]
fn test_worker_reset_before_start() {
    let worker = TestWorker::spawn();
    worker.reset();
    // The device has not started, so there was nothing to clean up.
    assert_eq!(worker.resets(), 0);
    worker.shutdown();
}

#[test]
fn test_worker_reset_after_start() {
    let worker = TestWorker::spawn();
    worker.start();
    worker.reset();
    // The worker acknowledges a reset only after cleaning up.
    assert_eq!(worker.resets(), 1);

    worker.start();
    worker.reset();
    assert_eq!(worker.resets(), 2);
    worker.shutdown();
}

#[test]
fn test_worker_survives_activation_failure() {
    let worker = TestWorker::spawn();
    worker.fail_activate.store(true, Ordering::Release);
    worker.start();
    // The worker cleans up the partially activated device, and stays alive
    // to complete the reset.
    worker.reset();
    assert_eq!(worker.resets(), 1);

    worker.fail_activate.store(false, Ordering::Release);
    worker.start();
    worker.reset();
    assert_eq!(worker.resets(), 2);
    worker.shutdown();
}

#[test]
fn test_worker_exit_completes_reset() {
    let worker = TestWorker::spawn();
    worker.start();
    let TestWorker { ctl, handle, .. } = worker;
    assert!(ctl.wake(WakeEvent::Shutdown));
    handle.join().unwrap();

    // An exited worker no longer uses the queues.
    let seq = ctl.request_reset();
    assert!(ctl.poll_reset(seq));
    assert_matches!(ctl.wait_reset(seq, TIMEOUT), Ok(()));
}

#[test]
fn test_wait_reset_timeout() {
    let (event_tx, _event_rx) = flume::unbounded();
    let (reset_tx, reset_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let ctl = WorkerCtl::<FakeIrqSender>::new("fake".into(), event_tx, notifier, reset_rx);

    let seq1 = ctl.request_reset();
    let seq2 = ctl.request_reset();
    assert!(!ctl.poll_reset(seq1));
    assert_matches!(
        ctl.wait_reset(seq1, Duration::from_millis(10)),
        Err(Error::ResetTimeout { timeout, .. }) if timeout == Duration::from_millis(10)
    );

    // Completing a reset also completes the earlier ones.
    reset_tx.send(seq2).unwrap();
    assert!(ctl.poll_reset(seq1));
    assert_matches!(ctl.wait_reset(seq2, Duration::ZERO), Ok(()));
}

#[test]
fn test_reset_seq_wraps_around() {
    let (event_tx, event_rx) = flume::unbounded();
    let (reset_tx, reset_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let ctl = WorkerCtl::<FakeIrqSender>::new("fake".into(), event_tx, notifier, reset_rx);
    // Pretend that almost all sequence numbers have been used up.
    *ctl.reset_seq.lock() = u64::MAX - 1;
    ctl.reset_acks.lock().done = u64::MAX - 1;

    let seq1 = ctl.request_reset();
    let seq2 = ctl.request_reset();
    assert_eq!((seq1, seq2), (u64::MAX, 0));
    for seq in [seq1, seq2] {
        assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Reset { seq: s }) if s == seq);
    }
    assert!(!ctl.poll_reset(seq1));

    reset_tx.send(seq1).unwrap();
    assert!(ctl.poll_reset(seq1));
    assert!(!ctl.poll_reset(seq2));

    reset_tx.send(seq2).unwrap();
    assert!(ctl.poll_reset(seq1));
    assert_matches!(ctl.wait_reset(seq2, Duration::ZERO), Ok(()));
}

#[test]
fn test_request_reset_in_order() {
    let (event_tx, event_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let reset_rx = flume::unbounded().1;
    let ctl = WorkerCtl::<FakeIrqSender>::new("fake".into(), event_tx, notifier, reset_rx);
    let ctl = Arc::new(ctl);

    let threads: Vec<_> = (0..4)
        .map(|_| {
            let ctl = ctl.clone();
            thread::spawn(move || {
                for _ in 0..100 {
                    ctl.request_reset();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }

    // The worker sees the resets in the order of their sequence numbers,
    // even when they are requested concurrently.
    let seqs: Vec<u64> = event_rx
        .try_iter()
        .map(|event| match event {
            WakeEvent::Reset { seq } => seq,
            event => panic!("unexpected event: {event:?}"),
        })
        .collect();
    assert_eq!(seqs, (1..=400).collect::<Vec<_>>());
}
