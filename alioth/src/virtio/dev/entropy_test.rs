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
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use assert_matches::assert_matches;
use rstest::rstest;
use tempdir::TempDir;

use crate::ffi;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::RamBus;
use crate::virtio::dev::entropy::{EntropyConfig, EntropyParam};
use crate::virtio::dev::{DevParam, StartParam, Virtio, WakeEvent};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{Queue, QueueReg};
use crate::virtio::tests::{
    DATA_ADDR, FakeIoeventFd, FakeIrqSender, fixture_queue, fixture_ram_bus,
};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, VirtioFeature};

#[test]
fn entry_config_test() {
    let config = EntropyConfig;

    assert_eq!(config.size(), 0);
    assert_matches!(config.read(0, 1), Ok(0));
    assert_matches!(config.write(0, 1, 0), Ok(Action::None));
}

#[rstest]
fn entropy_test(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram_bus = Arc::new(fixture_ram_bus);
    let ram = ram_bus.lock_layout();
    let queues = Arc::new([fixture_queue]);

    let q = SplitQueue::new(&queues[0], &*ram, false).unwrap().unwrap();
    let mut q = Queue::new(q);

    let buf0_addr = DATA_ADDR;
    let buf1_addr = buf0_addr + (4 << 10);
    let s0 = "Hello, World!";
    let s1 = "Goodbye, World!";

    let temp_dir = TempDir::new("entropy_test").unwrap();
    let pipe_path = temp_dir.path().join("urandom");
    let pipe_path_c = CString::new(pipe_path.as_os_str().as_encoded_bytes()).unwrap();
    ffi!(unsafe { libc::mkfifo(pipe_path_c.as_ptr(), 0o600) }).unwrap();

    let param = EntropyParam {
        source: Some(pipe_path.clone()),
    };
    let dev = param.build("entropy").unwrap();

    assert_matches!(dev.id(), DeviceId::Entropy);
    assert_eq!(dev.name(), "entropy");
    assert_eq!(dev.num_queues(), 1);
    assert_matches!(*dev.config(), EntropyConfig);
    assert_eq!(dev.feature(), FEATURE_BUILT_IN);

    let (tx, rx) = mpsc::channel();
    let (handle, waker) = dev
        .spawn_worker(rx, ram_bus.clone(), queues.clone())
        .unwrap();
    let (irq_tx, irq_rx) = mpsc::channel();
    let irq_sender = Arc::new(FakeIrqSender { q_tx: irq_tx });
    let start_param = StartParam {
        feature: VirtioFeature::VERSION_1.bits(),
        irq_sender,
        ioeventfds: Option::<Arc<[FakeIoeventFd]>>::None,
    };
    tx.send(WakeEvent::Start { param: start_param }).unwrap();
    waker.wake().unwrap();

    let mut writer = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe_path)
        .unwrap();

    q.add_desc(0, 0, &[], &[(buf0_addr, 4 << 10)]);
    tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
    waker.wake().unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    writer.write_all(s0.as_bytes()).unwrap();
    writer.flush().unwrap();
    tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
    waker.wake().unwrap();
    assert_eq!(irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 0);

    writer.write_all(s1.as_bytes()).unwrap();
    writer.flush().unwrap();
    q.add_desc(1, 1, &[], &[(buf1_addr, 4 << 10)]);
    tx.send(WakeEvent::Notify { q_index: 0 }).unwrap();
    waker.wake().unwrap();
    assert_eq!(irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 0);

    tx.send(WakeEvent::Shutdown).unwrap();
    waker.wake().unwrap();
    handle.join().unwrap();

    for (s, addr) in [(s0, buf0_addr), (s1, buf1_addr)] {
        let mut buf = vec![0u8; s.len()];
        ram.read(addr, &mut buf).unwrap();
        assert_eq!(String::from_utf8_lossy(buf.as_slice()), s);
    }
}
