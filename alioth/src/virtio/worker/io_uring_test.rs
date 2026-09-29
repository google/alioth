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
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use flume::{Receiver, Sender};
use io_uring::cqueue::Entry as Cqe;
use io_uring::opcode;
use io_uring::types::Fd;

use crate::ffi;
use crate::mem::mapped::RamBus;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::entropy::{EntropyConfig, EntropyFeature};
use crate::virtio::dev::{StartParam, Virtio, WakeEvent};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::GuestQueue;
use crate::virtio::queue::{DescChain, Queue, QueueReg, VirtQueue};
use crate::virtio::tests::{DATA_ADDR, FakeIrqSender, fixture_queues, fixture_ram_bus};
use crate::virtio::worker::io_uring::{
    ActiveIoUring, BufferAction, IoUring, RING_SIZE, VirtioIoUring,
};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, IrqSender, Result, VirtioFeature};

/// A device that reads guest buffers from a pipe with io_uring.
#[derive(Debug)]
struct PipeReader {
    reader: OwnedFd,
    config: Arc<EntropyConfig>,
    submitted: Sender<u16>,
    completed: Arc<AtomicUsize>,
}

impl Virtio for PipeReader {
    type Config = EntropyConfig;
    type Feature = EntropyFeature;

    fn id(&self) -> DeviceId {
        DeviceId::ENTROPY
    }

    fn name(&self) -> &str {
        "pipe-reader"
    }

    fn spawn_worker<S>(
        self,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
    {
        IoUring::spawn_worker(self, event_rx, memory, queue_regs)
    }

    fn num_queues(&self) -> u16 {
        1
    }

    fn config(&self) -> Arc<EntropyConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u128 {
        FEATURE_BUILT_IN
    }
}

impl VirtioIoUring for PipeReader {
    fn activate<'m, Q, S>(
        &mut self,
        _feature: u128,
        _ring: &mut ActiveIoUring<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        Ok(())
    }

    fn handle_desc(&mut self, _q_index: u16, chain: &mut DescChain) -> Result<BufferAction> {
        let writable = &chain.writable;
        let entry = opcode::Readv::new(
            Fd(self.reader.as_raw_fd()),
            writable.as_ptr() as *const _,
            writable.len() as _,
        )
        .build();
        self.submitted.send(chain.id()).unwrap();
        Ok(BufferAction::Sqe(entry))
    }

    fn complete_desc(&mut self, _q_index: u16, _chain: &mut DescChain, cqe: &Cqe) -> Result<u32> {
        self.completed.fetch_add(1, Ordering::Relaxed);
        Ok(cqe.result().max(0) as u32)
    }
}

fn pipe() -> (OwnedFd, File) {
    let mut fds = [0; 2];
    ffi!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }).unwrap();
    let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let writer = unsafe { File::from_raw_fd(fds[1]) };
    (reader, writer)
}

#[test]
fn io_uring_drain_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let regs: Arc<[QueueReg]> = Arc::from(fixture_queues(1));

    let (reader, mut writer) = pipe();
    let observer = unsafe { File::from_raw_fd(libc::dup(reader.as_raw_fd())) };
    let (submitted_tx, submitted_rx) = flume::unbounded();
    let completed = Arc::new(AtomicUsize::new(0));
    let dev = PipeReader {
        reader,
        config: Arc::new(EntropyConfig),
        submitted: submitted_tx,
        completed: completed.clone(),
    };

    let (tx, rx) = flume::unbounded();
    let (handle, notifier) = dev.spawn_worker(rx, ram_bus.clone(), regs.clone()).unwrap();
    let (irq_tx, irq_rx) = flume::unbounded();
    let start_param = StartParam {
        feature: VirtioFeature::VERSION_1.bits(),
        irq_sender: Arc::new(FakeIrqSender { q_tx: irq_tx }),
        notifiers: Option::<Arc<[Notifier]>>::None,
    };
    tx.send(WakeEvent::Start { param: start_param }).unwrap();
    notifier.notify().unwrap();

    // The pipe is empty, so the read stays in flight.
    {
        let ram = ram_bus.lock_layout();
        let mut guest_q = GuestQueue::new(
            SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
            &regs[0],
        );
        let id = guest_q.add_desc(&[], &[(DATA_ADDR, 4 << 10)]);
        tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
        notifier.notify().unwrap();
        assert_eq!(submitted_rx.recv_timeout(Duration::from_secs(1)), Ok(id));
    }

    // Shutting down cancels and reaps the read, instead of hanging or
    // leaving it to the kernel after the worker releases guest memory.
    tx.send(WakeEvent::Shutdown).unwrap();
    notifier.notify().unwrap();
    handle.join().unwrap();
    assert_eq!(completed.load(Ordering::Relaxed), 0);
    assert!(irq_rx.try_recv().is_err());

    // Nobody reads from the pipe any more, so the data stays there and
    // never reaches guest memory.
    let s = b"written after shutdown";
    let sentinel = [0xa5u8; 22];
    ram_bus.write(DATA_ADDR, &sentinel).unwrap();
    writer.write_all(s).unwrap();
    drop(writer);
    let mut buf = Vec::new();
    let mut observer = observer;
    observer.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, s);
    let mut guest_buf = [0u8; 22];
    ram_bus.read(DATA_ADDR, &mut guest_buf).unwrap();
    assert_eq!(guest_buf, sentinel);
}

#[test]
fn io_uring_drain_cancels_pending_reads() {
    let ram_bus = fixture_ram_bus();
    let ram = ram_bus.lock_layout();
    let regs = fixture_queues(1);
    let mut guest_q = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    guest_q.add_desc(&[], &[(DATA_ADDR, 4 << 10)]);

    let (reader, mut writer) = pipe();
    let mut observer = unsafe { File::from_raw_fd(libc::dup(reader.as_raw_fd())) };
    let (submitted_tx, submitted_rx) = flume::unbounded();
    let completed = Arc::new(AtomicUsize::new(0));
    let mut dev = PipeReader {
        reader,
        config: Arc::new(EntropyConfig),
        submitted: submitted_tx,
        completed: completed.clone(),
    };

    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let split_q = SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap();
    let mut queues = [Some(Queue::new(split_q, &regs[0], &ram))];
    let mut active = ActiveIoUring {
        ring: io_uring::IoUring::new(RING_SIZE as u32).unwrap(),
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &[],
        mem: &ram,
        shared_count: RING_SIZE - 1,
        submit_counts: Box::new([0]),
    };
    active.submit_buffers(&mut dev, 0).unwrap();
    active.ring.submit().unwrap();
    assert!(submitted_rx.try_recv().is_ok());
    assert_eq!(active.submit_counts[0], 1);

    active.drain().unwrap();
    assert_eq!(active.submit_counts[0], 0);

    // The ring is still alive, but the read is gone: data written now
    // stays in the pipe.
    let s = b"written after drain";
    writer.write_all(s).unwrap();
    drop(writer);
    drop(dev);
    let mut buf = Vec::new();
    observer.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, s);
    assert_eq!(completed.load(Ordering::Relaxed), 0);
    assert!(irq_rx.try_recv().is_err());
    drop(active);
}
