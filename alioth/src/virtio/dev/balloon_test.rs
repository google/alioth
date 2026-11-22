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

use std::io::IoSliceMut;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use assert_matches::assert_matches;
use flume::Receiver;
use libc::_SC_PAGESIZE;
use mio::Poll;
use parking_lot::RwLock;

use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::virtio::dev::balloon::{
    Balloon, BalloonConfig, BalloonConfigMmio, BalloonFeature, BalloonQueue, BalloonSpec,
};
use crate::virtio::dev::{DevSpec, StartParam, Virtio, WakeEvent, WorkerCtl, WorkerParam};
use crate::virtio::queue::QueueReg;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::GuestQueue;
use crate::virtio::tests::{self, DATA_ADDR, FakeIrqSender};
use crate::virtio::worker::mio::VirtioMio;
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, VirtioFeature};

const TIMEOUT: Duration = Duration::from_secs(5);

fn host_page_size() -> usize {
    let size = unsafe { libc::sysconf(_SC_PAGESIZE) };
    assert!(size > 0);
    size as usize
}

struct BalloonWorker {
    config: Arc<BalloonConfigMmio>,
    ram_bus: Arc<RamBus>,
    regs: Arc<[QueueReg]>,
    ctl: Arc<WorkerCtl<FakeIrqSender>>,
    irq_rx: Receiver<u16>,
    handle: JoinHandle<()>,
}

impl BalloonWorker {
    fn spawn(spec: BalloonSpec) -> Self {
        let dev = Balloon::new_inner(spec, "balloon".into());
        let config = dev.config();
        let ram_bus = Arc::new(tests::fixture_ram_bus());
        let regs: Arc<[QueueReg]> = Arc::from(tests::fixture_queues(5));
        let (event_tx, event_rx) = flume::unbounded();
        let (report_tx, report_rx) = flume::unbounded();
        let (handle, notifier) = dev
            .spawn_worker(WorkerParam {
                event_rx,
                report_tx,
                memory: ram_bus.clone(),
                queue_regs: regs.clone(),
            })
            .unwrap();
        let (_irq_tx, irq_rx) = flume::unbounded();
        Self {
            config,
            ram_bus,
            regs,
            ctl: Arc::new(WorkerCtl::new(
                "balloon".into(),
                event_tx,
                notifier,
                report_rx,
            )),
            irq_rx,
            handle,
        }
    }

    fn start(&mut self, feature: BalloonFeature) {
        let (irq_tx, irq_rx) = flume::unbounded();
        self.irq_rx = irq_rx;
        let param = StartParam {
            feature: VirtioFeature::VERSION_1.bits() | feature.bits(),
            irq_sender: Arc::new(FakeIrqSender { q_tx: irq_tx }),
            notifiers: None,
        };
        assert!(self.ctl.wake(WakeEvent::Start { param }));
    }

    fn report_page(&self, q_index: u16, gpa: u64, len: u32) {
        let ram = self.ram_bus.load();
        let reg = &self.regs[q_index as usize];
        let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
        let id = guest_q.add_desc(&[], &[(gpa, len)]);
        assert!(self.ctl.wake(WakeEvent::Notify { q_index }));
        assert_eq!(self.irq_rx.recv_timeout(TIMEOUT), Ok(q_index));
        let used = guest_q.get_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, 0);
    }

    fn reset(&self) {
        let seq = self.ctl.request_reset();
        assert_matches!(self.ctl.wait_reset(seq, TIMEOUT), Ok(()));
    }

    fn shutdown(self) {
        assert!(self.ctl.wake(WakeEvent::Shutdown));
        self.handle.join().unwrap();
    }
}

#[test]
fn test_balloon_config_mmio() {
    let mmio = BalloonConfigMmio {
        name: "balloon".into(),
        config: RwLock::new(BalloonConfig {
            num_pages: 0x1122_3344,
            actual: 0,
            free_page_hint_cmd_id: 0x5566_7788,
            poison_val: 0,
        }),
    };

    assert_eq!(mmio.size(), 16);
    assert_eq!(
        mmio.read(BalloonConfig::OFFSET_NUM_PAGES as u64, 4)
            .unwrap(),
        0x1122_3344
    );
    assert_eq!(
        mmio.read(BalloonConfig::OFFSET_FREE_PAGE_HINT_CMD_ID as u64, 4)
            .unwrap(),
        0x5566_7788
    );

    // 32-bit and sub-word little-endian writes to `actual`.
    let actual_off = BalloonConfig::OFFSET_ACTUAL as u64;
    assert_matches!(mmio.write(actual_off, 4, 0x1234_5678), Ok(Action::None));
    assert_eq!(mmio.read(actual_off, 4).unwrap(), 0x1234_5678);

    assert_matches!(mmio.write(actual_off, 2, 0xabcd), Ok(Action::None));
    assert_eq!(mmio.read(actual_off, 4).unwrap(), 0x1234_abcd);

    assert_matches!(mmio.write(actual_off + 2, 2, 0xef01), Ok(Action::None));
    assert_eq!(mmio.read(actual_off, 4).unwrap(), 0xef01_abcd);

    assert_matches!(mmio.write(actual_off + 1, 1, 0x99), Ok(Action::None));
    assert_eq!(mmio.read(actual_off, 4).unwrap(), 0xef01_99cd);

    // 32-bit and sub-word little-endian writes to `poison_val`.
    let poison_off = BalloonConfig::OFFSET_POISON_VAL as u64;
    assert_matches!(mmio.write(poison_off, 4, 0xaaaa_aaaa), Ok(Action::None));
    assert_eq!(mmio.read(poison_off, 4).unwrap(), 0xaaaa_aaaa);

    assert_matches!(mmio.write(poison_off, 2, 0x1122), Ok(Action::None));
    assert_eq!(mmio.read(poison_off, 4).unwrap(), 0xaaaa_1122);

    assert_matches!(mmio.write(poison_off + 3, 1, 0x33), Ok(Action::None));
    assert_eq!(mmio.read(poison_off, 4).unwrap(), 0x33aa_1122);

    // Writes to read-only fields, cross-field boundaries, invalid widths, and OOB offsets
    // are ignored without mutating config state.
    for (offset, size, val) in [
        (BalloonConfig::OFFSET_NUM_PAGES as u64, 4, 0xdead_beef),
        (BalloonConfig::OFFSET_NUM_PAGES as u64, 1, 0xff),
        (
            BalloonConfig::OFFSET_FREE_PAGE_HINT_CMD_ID as u64,
            4,
            0xdead_beef,
        ),
        (
            BalloonConfig::OFFSET_FREE_PAGE_HINT_CMD_ID as u64,
            2,
            0xffff,
        ),
        (3, 2, 0xffff),
        (7, 2, 0xffff),
        (11, 2, 0xffff),
        (15, 2, 0xffff),
        (actual_off, 8, 0xffff_ffff_ffff_ffff),
        (actual_off, 3, 0xffffff),
        (actual_off, 0, 0),
        (16, 4, 0xdead_beef),
        (u64::MAX, 1, 0xff),
    ] {
        assert_matches!(mmio.write(offset, size, val), Ok(Action::None));
    }

    assert_eq!(
        mmio.read(BalloonConfig::OFFSET_NUM_PAGES as u64, 4)
            .unwrap(),
        0x1122_3344
    );
    assert_eq!(mmio.read(actual_off, 4).unwrap(), 0xef01_99cd);
    assert_eq!(
        mmio.read(BalloonConfig::OFFSET_FREE_PAGE_HINT_CMD_ID as u64, 4)
            .unwrap(),
        0x5566_7788
    );
    assert_eq!(mmio.read(poison_off, 4).unwrap(), 0x33aa_1122);
}

#[test]
fn test_balloon_free_reporting_with_page_poison_nonzero() {
    let page_size = host_page_size();

    // Direct check on Balloon::free_reporting.
    let mut dev = Balloon::new_inner(
        BalloonSpec {
            free_page_reporting: true,
        },
        "balloon".into(),
    );
    dev.driver_feature = BalloonFeature::PAGE_REPORTING | BalloonFeature::PAGE_POISON;
    dev.config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0xaaaa_aaaa)
        .unwrap();
    assert!(!dev.should_reclaim_reported_pages());

    let mut pages = ArcMemPages::from_anonymous(page_size, None, None).unwrap();
    pages.as_slice_mut().fill(0xaa);
    dev.free_reporting(&mut [IoSliceMut::new(pages.as_slice_mut())]);
    assert!(pages.as_slice().iter().all(|&b| b == 0xaa));

    // End-to-end check through worker and reporting virtqueue.
    let mut worker = BalloonWorker::spawn(BalloonSpec {
        free_page_reporting: true,
    });
    worker
        .config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0xaaaa_aaaa)
        .unwrap();
    worker.start(BalloonFeature::PAGE_REPORTING | BalloonFeature::PAGE_POISON);

    let init = vec![0xaau8; page_size];
    worker.ram_bus.write(DATA_ADDR, &init).unwrap();
    worker.report_page(2, DATA_ADDR, page_size as u32);

    let mut after = vec![0u8; page_size];
    worker.ram_bus.read(DATA_ADDR, &mut after).unwrap();
    assert_eq!(after, init);

    worker.shutdown();
}

#[test]
fn test_balloon_free_reporting_with_page_poison_zero() {
    let page_size = host_page_size();

    let mut dev = Balloon::new_inner(
        BalloonSpec {
            free_page_reporting: true,
        },
        "balloon".into(),
    );
    dev.driver_feature = BalloonFeature::PAGE_REPORTING | BalloonFeature::PAGE_POISON;
    dev.config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0)
        .unwrap();
    assert!(dev.should_reclaim_reported_pages());

    let mut pages = ArcMemPages::from_anonymous(page_size, None, None).unwrap();
    pages.as_slice_mut().fill(0x55);
    dev.free_reporting(&mut [IoSliceMut::new(pages.as_slice_mut())]);
    #[cfg(target_os = "linux")]
    assert!(pages.as_slice().iter().all(|&b| b == 0));

    let mut worker = BalloonWorker::spawn(BalloonSpec {
        free_page_reporting: true,
    });
    worker
        .config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0)
        .unwrap();
    worker.start(BalloonFeature::PAGE_REPORTING | BalloonFeature::PAGE_POISON);

    worker
        .ram_bus
        .write(DATA_ADDR, &vec![0x55u8; page_size])
        .unwrap();
    worker.report_page(2, DATA_ADDR, page_size as u32);

    #[cfg(target_os = "linux")]
    {
        let mut after = vec![0xffu8; page_size];
        worker.ram_bus.read(DATA_ADDR, &mut after).unwrap();
        assert!(after.iter().all(|&b| b == 0));
    }

    worker.shutdown();
}

#[test]
fn test_balloon_free_reporting_without_page_poison() {
    let page_size = host_page_size();

    let mut dev = Balloon::new_inner(
        BalloonSpec {
            free_page_reporting: true,
        },
        "balloon".into(),
    );
    // Even if `poison_val` was written, without PAGE_POISON negotiated, reported pages are reclaimed.
    dev.config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0xaaaa_aaaa)
        .unwrap();
    dev.driver_feature = BalloonFeature::PAGE_REPORTING;
    assert!(dev.should_reclaim_reported_pages());

    let mut pages = ArcMemPages::from_anonymous(page_size, None, None).unwrap();
    pages.as_slice_mut().fill(0xaa);
    dev.free_reporting(&mut [IoSliceMut::new(pages.as_slice_mut())]);
    #[cfg(target_os = "linux")]
    assert!(pages.as_slice().iter().all(|&b| b == 0));

    let mut worker = BalloonWorker::spawn(BalloonSpec {
        free_page_reporting: true,
    });
    worker
        .config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0xaaaa_aaaa)
        .unwrap();
    worker.start(BalloonFeature::PAGE_REPORTING);

    worker
        .ram_bus
        .write(DATA_ADDR, &vec![0xaau8; page_size])
        .unwrap();
    worker.report_page(2, DATA_ADDR, page_size as u32);

    #[cfg(target_os = "linux")]
    {
        let mut after = vec![0xffu8; page_size];
        worker.ram_bus.read(DATA_ADDR, &mut after).unwrap();
        assert!(after.iter().all(|&b| b == 0));
    }

    worker.shutdown();
}

#[test]
fn test_balloon_reset_clears_state() {
    let page_size = host_page_size();

    // Direct check on VirtioMio::reset.
    let mut dev = Balloon::new_inner(
        BalloonSpec {
            free_page_reporting: true,
        },
        "balloon".into(),
    );
    dev.config.config.write().num_pages = 0x20;
    dev.config
        .write(BalloonConfig::OFFSET_ACTUAL as u64, 4, 0x10)
        .unwrap();
    dev.config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0xdead_beef)
        .unwrap();
    dev.driver_feature = BalloonFeature::PAGE_POISON | BalloonFeature::PAGE_REPORTING;
    dev.queues[0] = BalloonQueue::Inflate;
    dev.queues[1] = BalloonQueue::Deflate;
    dev.queues[2] = BalloonQueue::Reporting;

    let poll = Poll::new().unwrap();
    dev.reset(poll.registry());

    assert_eq!(dev.driver_feature, BalloonFeature::empty());
    assert_eq!(dev.queues, [BalloonQueue::NotExist; 5]);
    assert_eq!(
        dev.config
            .read(BalloonConfig::OFFSET_NUM_PAGES as u64, 4)
            .unwrap(),
        0x20
    );
    assert_eq!(
        dev.config
            .read(BalloonConfig::OFFSET_ACTUAL as u64, 4)
            .unwrap(),
        0
    );
    assert_eq!(
        dev.config
            .read(BalloonConfig::OFFSET_POISON_VAL as u64, 4)
            .unwrap(),
        0
    );

    // End-to-end worker reset and re-activation.
    let mut worker = BalloonWorker::spawn(BalloonSpec {
        free_page_reporting: true,
    });
    worker
        .config
        .write(BalloonConfig::OFFSET_ACTUAL as u64, 4, 0x10)
        .unwrap();
    worker
        .config
        .write(BalloonConfig::OFFSET_POISON_VAL as u64, 4, 0xaaaa_aaaa)
        .unwrap();
    worker.start(
        BalloonFeature::STATS_VQ
            | BalloonFeature::FREE_PAGE_HINT
            | BalloonFeature::PAGE_REPORTING
            | BalloonFeature::PAGE_POISON,
    );

    // With STATS_VQ and FREE_PAGE_HINT negotiated, Reporting is queue index 4.
    let init = vec![0xaau8; page_size];
    worker.ram_bus.write(DATA_ADDR, &init).unwrap();
    worker.report_page(4, DATA_ADDR, page_size as u32);
    let mut after = vec![0u8; page_size];
    worker.ram_bus.read(DATA_ADDR, &mut after).unwrap();
    assert_eq!(after, init);

    worker.reset();
    assert_eq!(
        worker
            .config
            .read(BalloonConfig::OFFSET_ACTUAL as u64, 4)
            .unwrap(),
        0
    );
    assert_eq!(
        worker
            .config
            .read(BalloonConfig::OFFSET_POISON_VAL as u64, 4)
            .unwrap(),
        0
    );

    // Re-activate with only PAGE_REPORTING: Reporting moves to queue index 2 and reclaims pages.
    worker.start(BalloonFeature::PAGE_REPORTING);
    worker
        .ram_bus
        .write(DATA_ADDR, &vec![0x55u8; page_size])
        .unwrap();
    worker.report_page(2, DATA_ADDR, page_size as u32);
    #[cfg(target_os = "linux")]
    {
        let mut reclaimed = vec![0xffu8; page_size];
        worker.ram_bus.read(DATA_ADDR, &mut reclaimed).unwrap();
        assert!(reclaimed.iter().all(|&b| b == 0));
    }

    worker.shutdown();
}

#[test]
fn test_balloon_spec_and_metadata() {
    let dev_no_report = Balloon::new_inner(BalloonSpec::default(), "balloon-default".into());
    assert_eq!(dev_no_report.id(), DeviceId::BALLOON);
    assert_eq!(dev_no_report.name(), "balloon-default");
    assert_eq!(dev_no_report.num_queues(), 5);
    assert_eq!(
        dev_no_report.feature(),
        FEATURE_BUILT_IN | (BalloonFeature::all() - BalloonFeature::PAGE_REPORTING).bits()
    );

    let dev_report = Balloon::new_inner(
        BalloonSpec {
            free_page_reporting: true,
        },
        "balloon-report".into(),
    );
    assert_eq!(
        dev_report.feature(),
        FEATURE_BUILT_IN | BalloonFeature::all().bits()
    );

    let build_res = BalloonSpec::default().build("balloon");
    if host_page_size() == 1 << 12 {
        assert_matches!(build_res, Ok(_));
    } else {
        assert_matches!(build_res, Err(_));
    }
}
