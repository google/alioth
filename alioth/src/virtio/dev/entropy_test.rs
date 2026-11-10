// Copyright 2025 Google LLC
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

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use assert_matches::assert_matches;
use flume::{Receiver, Sender, TryRecvError};
use tempfile::TempDir;

use crate::ffi;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::entropy::{EntropyConfig, EntropySpec};
use crate::virtio::dev::{DevSpec, StartParam, Virtio, WakeEvent, WorkerParam};
use crate::virtio::queue::QueueReg;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::GuestQueue;
use crate::virtio::tests::{DATA_ADDR, FakeIrqSender, MEM_SIZE, fixture_queues, fixture_ram_bus};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, VirtioFeature};

#[test]
fn entry_config_test() {
    let config = EntropyConfig;

    assert_eq!(config.size(), 0);
    assert_matches!(config.read(0, 1), Ok(0));
    assert_matches!(config.write(0, 1, 0), Ok(Action::None));
}

#[test]
fn entropy_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.load();
    let regs: Arc<[QueueReg]> = Arc::from(fixture_queues(1));

    let mut guest_q = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );

    let buf0_addr = DATA_ADDR;
    let buf1_addr = buf0_addr + (4 << 10);
    let s0 = "Hello, World!";
    let s1 = "Goodbye, World!";

    let temp_dir = TempDir::new().unwrap();
    let pipe_path = temp_dir.path().join("urandom");
    let pipe_path_c = CString::new(pipe_path.as_os_str().as_encoded_bytes()).unwrap();
    ffi!(unsafe { libc::mkfifo(pipe_path_c.as_ptr(), 0o600) }).unwrap();

    let param = EntropySpec {
        source: Some(pipe_path.clone().into()),
    };
    let dev = param.build("entropy").unwrap();

    assert_matches!(dev.id(), DeviceId::ENTROPY);
    assert_eq!(dev.name(), "entropy");
    assert_eq!(dev.num_queues(), 1);
    assert_matches!(*dev.config(), EntropyConfig);
    assert_eq!(dev.feature(), FEATURE_BUILT_IN);

    let (tx, rx) = flume::unbounded();
    let (handle, notifier) = dev
        .spawn_worker(WorkerParam {
            event_rx: rx,
            report_tx: flume::unbounded().0,
            memory: ram_bus.clone(),
            queue_regs: regs,
        })
        .unwrap();
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = Arc::new(FakeIrqSender { q_tx: irq_tx });
    let start_param = StartParam {
        feature: VirtioFeature::VERSION_1.bits(),
        irq_sender,
        notifiers: Option::<Arc<[Notifier]>>::None,
    };
    tx.send(WakeEvent::Start { param: start_param }).unwrap();
    notifier.notify().unwrap();

    let mut writer = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe_path)
        .unwrap();

    let id0 = guest_q.add_desc(&[], &[(buf0_addr, 4 << 10)]);
    tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
    notifier.notify().unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    writer.write_all(s0.as_bytes()).unwrap();
    writer.flush().unwrap();
    tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
    notifier.notify().unwrap();
    assert_eq!(irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 0);
    let used0 = guest_q.get_used().unwrap();
    assert_eq!(used0.id, id0);
    assert_eq!(used0.len, s0.len() as u32);

    // The guest memory layout can change while the device is running.
    let pages = ArcMemPages::from_anonymous(4 << 10, None, None).unwrap();
    let (done_tx, done_rx) = flume::bounded(1);
    let bus = ram_bus.clone();
    thread::spawn(move || {
        let ret = bus.update(|ram| ram.add(MEM_SIZE as u64, pages));
        done_tx.send(ret).unwrap();
    });
    let ret = done_rx.recv_timeout(Duration::from_secs(5));
    assert_matches!(ret, Ok(Ok(())));

    writer.write_all(s1.as_bytes()).unwrap();
    writer.flush().unwrap();
    let id1 = guest_q.add_desc(&[], &[(buf1_addr, 4 << 10)]);
    tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
    notifier.notify().unwrap();
    assert_eq!(irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 0);

    let used1 = guest_q.get_used().unwrap();
    assert_eq!(used1.id, id1);
    assert_eq!(used1.len, s1.len() as u32);

    tx.send(WakeEvent::Shutdown).unwrap();
    notifier.notify().unwrap();
    handle.join().unwrap();

    for (s, addr) in [(s0, buf0_addr), (s1, buf1_addr)] {
        let mut buf = vec![0u8; s.len()];
        ram.read(addr, &mut buf).unwrap();
        assert_eq!(String::from_utf8_lossy(buf.as_slice()), s);
    }
}

/// A running entropy worker with a guest queue, fed through a FIFO.
struct EntropyWorker {
    guest_q: GuestQueue<SplitQueue>,
    writer: File,
    tx: Sender<WakeEvent<FakeIrqSender>>,
    irq_rx: Receiver<u16>,
    notifier: Arc<Notifier>,
    handle: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl EntropyWorker {
    /// Starts a worker whose queue is in the fixture memory of `ram_bus`.
    fn start(ram_bus: &Arc<RamBus>) -> Self {
        let regs: Arc<[QueueReg]> = Arc::from(fixture_queues(1));
        let ram = ram_bus.load();
        let guest_q = GuestQueue::new(
            SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
            &regs[0],
        );

        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("urandom");
        let pipe_path_c = CString::new(pipe_path.as_os_str().as_encoded_bytes()).unwrap();
        ffi!(unsafe { libc::mkfifo(pipe_path_c.as_ptr(), 0o600) }).unwrap();
        let param = EntropySpec {
            source: Some(pipe_path.clone().into()),
        };
        let dev = param.build("entropy").unwrap();

        let (tx, rx) = flume::unbounded();
        let (handle, notifier) = dev
            .spawn_worker(WorkerParam {
                event_rx: rx,
                report_tx: flume::unbounded().0,
                memory: ram_bus.clone(),
                queue_regs: regs,
            })
            .unwrap();
        let (irq_tx, irq_rx) = flume::unbounded();
        let start_param = StartParam {
            feature: VirtioFeature::VERSION_1.bits(),
            irq_sender: Arc::new(FakeIrqSender { q_tx: irq_tx }),
            notifiers: None,
        };
        tx.send(WakeEvent::Start { param: start_param }).unwrap();
        notifier.notify().unwrap();
        let writer = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&pipe_path)
            .unwrap();
        EntropyWorker {
            guest_q,
            writer,
            tx,
            irq_rx,
            notifier,
            handle,
            _temp_dir: temp_dir,
        }
    }

    /// Asks the device to fill the buffer at `gpa` with `s`.
    fn request(&mut self, s: &str, gpa: u64) {
        self.writer.write_all(s.as_bytes()).unwrap();
        self.writer.flush().unwrap();
        let id = self.guest_q.add_desc(&[], &[(gpa, 4 << 10)]);
        self.tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
        self.notifier.notify().unwrap();
        let irq = self.irq_rx.recv_timeout(Duration::from_secs(1));
        assert_eq!(irq, Ok(0), "no response for a buffer at {gpa:#x}");
        let used = self.guest_q.get_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, s.len() as u32);
    }

    fn shutdown(self) {
        self.tx.send(WakeEvent::Shutdown).unwrap();
        self.notifier.notify().unwrap();
        self.handle.join().unwrap();
    }
}

const HOTPLUG_GPA: u64 = 4 << 20;
const HOTPLUG_SIZE: usize = 1 << 20;

#[test]
fn entropy_memory_hotplug_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let mut worker = EntropyWorker::start(&ram_bus);
    let s0 = "before hot-plug";
    worker.request(s0, DATA_ADDR);

    // The driver uses memory plugged while the device runs right away.
    let pages = ArcMemPages::from_anonymous(HOTPLUG_SIZE, None, None).unwrap();
    ram_bus.update(|ram| ram.add(HOTPLUG_GPA, pages)).unwrap();
    let s1 = "right after hot-plug";
    worker.request(s1, HOTPLUG_GPA);
    let mut buf = vec![0u8; s1.len()];
    ram_bus.read(HOTPLUG_GPA, &mut buf).unwrap();
    assert_eq!(buf, s1.as_bytes());

    // So is unplugging memory.
    ram_bus.update(|ram| ram.remove(HOTPLUG_GPA)).unwrap();
    let s2 = "after hot-unplug";
    worker.request(s2, DATA_ADDR + (4 << 10));

    worker.shutdown();
    for (s, gpa) in [(s0, DATA_ADDR), (s2, DATA_ADDR + (4 << 10))] {
        let mut buf = vec![0u8; s.len()];
        ram_bus.read(gpa, &mut buf).unwrap();
        assert_eq!(buf, s.as_bytes());
    }
}
