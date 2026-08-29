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

use std::io::ErrorKind;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use assert_matches::assert_matches;
use flume::Receiver;
use parking_lot::{Mutex, RwLock};
use rstest::rstest;

use crate::hv::IoeventFd;
use crate::hv::tests::{
    RegisteredAddr, TestIoeventFd, TestIoeventFdRegistry, TestIrqFd, TestMsiSender,
};
use crate::mem::emulated::{Action, Mmio};
use crate::mem::{self, MemRange, MemRegion, MemRegionEntry, MemRegionType};
use crate::pci::cap::{
    MsixTableEntry, MsixTableMmio, MsixTableMmioEntry, MsixVectorCtrl, PciCap, PciCapId,
};
use crate::pci::config::{BAR_MEM32, BAR_MEM64, BAR_PREFETCHABLE, PciConfigArea};
use crate::pci::{Pci, PciBar};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{Register, VirtioDevice, WakeEvent};
use crate::virtio::pci::{
    PciIrqSender, VIRTIO_MSI_NO_VECTOR, VirtioCommonCfg, VirtioPciCap, VirtioPciCap64,
    VirtioPciDevice, VirtioPciMsixVector, VirtioPciNotifyCap, VirtioPciRegister,
    VirtioPciRegisterMmio,
};
use crate::virtio::queue::{QUEUE_SIZE_MAX, QueueReg};
use crate::virtio::tests::FakeIoeventFd;
use crate::virtio::{DevStatus, DeviceId, IrqSender, VirtioFeature};

type TestMmio = VirtioPciRegisterMmio<TestMsiSender, FakeIoeventFd>;
type TestWakeReceiver = flume::Receiver<WakeEvent<PciIrqSender<TestMsiSender>, FakeIoeventFd>>;

fn create_test_mmio(queues: Arc<[QueueReg]>) -> (TestMmio, TestWakeReceiver) {
    let (event_tx, event_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let msi_sender = TestMsiSender::default();
    let msix_table = Arc::new(MsixTableMmio {
        entries: RwLock::new(vec![].into_boxed_slice()),
    });
    let num_queues = queues.len();
    let irq_sender = Arc::new(PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            queues: (0..num_queues)
                .map(|_| AtomicU16::new(VIRTIO_MSI_NO_VECTOR))
                .collect(),
        },
        msix_table,
        msi_sender,
    });
    let mmio = VirtioPciRegisterMmio {
        name: "test-virtio-pci".into(),
        reg: Register {
            device_feature: [u32::MAX; 4],
            ..Default::default()
        },
        queues,
        irq_sender,
        ioeventfds: None,
        event_tx,
        notifier,
    };
    (mmio, event_rx)
}

#[rstest]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 0x5566_7788)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 0x1122_3344)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 0xeeff_0011)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 0xaabb_ccdd)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 0x89ab_cdef)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 0x0123_4567)]
fn test_queue_address_reads(#[case] offset: usize, #[case] expected: u64) {
    let queues = Arc::new([QueueReg {
        desc: AtomicU64::new(0x1122_3344_5566_7788),
        driver: AtomicU64::new(0xaabb_ccdd_eeff_0011),
        device: AtomicU64::new(0x0123_4567_89ab_cdef),
        ..Default::default()
    }]);
    let (mmio, _) = create_test_mmio(queues);
    assert_matches!(mmio.read(offset as u64, 4), Ok(val) if val == expected);
}

#[rstest]
// QUEUE_DESC_LO: must be 16-byte aligned
#[case(false, VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 0x1008, 0x1000_0000)]
#[case(false, VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 0x1010, 0x1010)]
// QUEUE_DEVICE_LO: must be 4-byte aligned
#[case(false, VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 0x3002, 0x3000_0000)]
#[case(false, VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 0x3004, 0x3004)]
// split queue: QUEUE_DRIVER_LO: must be 2-byte aligned
#[case(false, VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 0x2001, 0x2000_0000)]
#[case(false, VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 0x2002, 0x2002)]
// packed queue: QUEUE_DRIVER_LO: must be 4-byte aligned
#[case(true, VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 0x4002, 0x2000_0000)]
#[case(true, VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 0x4004, 0x4004)]
fn test_queue_alignment(
    #[case] packed: bool,
    #[case] offset: usize,
    #[case] input: u64,
    #[case] expected: u64,
) {
    let queues = Arc::new([QueueReg {
        desc: AtomicU64::new(0x1000_0000),
        driver: AtomicU64::new(0x2000_0000),
        device: AtomicU64::new(0x3000_0000),
        ..Default::default()
    }]);
    let (mmio, _event_rx) = create_test_mmio(queues);
    if packed {
        assert_matches!(
            mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 1),
            Ok(Action::None)
        );
        assert_matches!(
            mmio.write(
                VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
                4,
                VirtioFeature::RING_PACKED.bits() as u64 >> 32
            ),
            Ok(Action::None)
        );
    }
    assert_matches!(mmio.write(offset as u64, 4, input), Ok(Action::None));
    assert_matches!(mmio.read(offset as u64, 4), Ok(val) if val == expected);
}

#[rstest]
#[case(VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 128)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 4, 0x1122_3344)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 4, 0x5566_7788)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 4, 0x99aa_bbcc)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 1)]
fn test_queue_registers_write_read(#[case] offset: usize, #[case] size: u8, #[case] val: u64) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);

    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(mmio.write(offset as u64, size, val), Ok(Action::None));
    assert_matches!(mmio.read(offset as u64, size), Ok(v) if v == val);
}

#[rstest]
#[case(false, 64, 64)]
#[case(false, 80, 128)]
#[case(true, 80, 80)]
#[case(true, 0, 128)]
fn test_queue_size_write_read(#[case] packed: bool, #[case] input: u64, #[case] expected: u64) {
    let queues = Arc::new([QueueReg {
        size: AtomicU16::new(128),
        ..Default::default()
    }]);
    let (mmio, _event_rx) = create_test_mmio(queues);
    if packed {
        assert_matches!(
            mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 1),
            Ok(Action::None)
        );
        assert_matches!(
            mmio.write(
                VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
                4,
                VirtioFeature::RING_PACKED.bits() as u64 >> 32
            ),
            Ok(Action::None)
        );
    }
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SIZE as u64, 2, input),
        Ok(Action::None)
    );
    assert_matches!(mmio.read(VirtioCommonCfg::OFFSET_QUEUE_SIZE as u64, 2), Ok(val) if val == expected);
}

#[test]
fn test_queue_size_locked_when_enabled() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);

    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_ENABLE as u64, 2, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SIZE as u64, 2, 0xffff),
        Ok(Action::None)
    );
    assert_ne!(
        mmio.read(VirtioCommonCfg::OFFSET_QUEUE_SIZE as u64, 2)
            .unwrap(),
        0xffff
    );
}

#[rstest]
#[case(VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 64)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 4, 0x1000)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 4, 0x1000)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 4, 0x2000)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 4, 0x2000)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 4, 0x3000)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 4, 0x3000)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 1)]
fn test_out_of_bounds_queue_writes(#[case] offset: usize, #[case] size: u8, #[case] val: u64) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);

    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, 99),
        Ok(Action::None)
    );
    assert_matches!(mmio.write(offset as u64, size, val), Ok(Action::None));
}

#[rstest]
// Queue size
#[case(0, VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 128)]
#[case(1, VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 256)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 0)]
// Queue enable
#[case(0, VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 1)]
#[case(1, VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 0)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 0)]
// Queue MSI-X vector
#[case(0, VirtioCommonCfg::OFFSET_QUEUE_MSIX_VECTOR, 2, VIRTIO_MSI_NO_VECTOR as u64)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_MSIX_VECTOR, 2, VIRTIO_MSI_NO_VECTOR as u64)]
// Queue notify offset: valid index vs capped/out-of-bounds
#[case(0, VirtioCommonCfg::OFFSET_QUEUE_NOTIFY_OFF, 2, 0)]
#[case(1, VirtioCommonCfg::OFFSET_QUEUE_NOTIFY_OFF, 2, 1)]
#[case(5, VirtioCommonCfg::OFFSET_QUEUE_NOTIFY_OFF, 2, 2)]
// Out-of-bounds queue reads for descriptor / driver / device areas
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 4, 0)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 4, 0)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 4, 0)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 4, 0)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 4, 0)]
#[case(99, VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 4, 0)]
fn test_common_cfg_queue_reads(
    #[case] q_sel: u64,
    #[case] offset: usize,
    #[case] size: u8,
    #[case] expected: u64,
) {
    let queues = Arc::new([
        QueueReg {
            size: AtomicU16::new(128),
            enabled: AtomicBool::new(true),
            ..Default::default()
        },
        QueueReg {
            size: AtomicU16::new(256),
            ..Default::default()
        },
    ]);
    let (mmio, _) = create_test_mmio(queues);

    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, q_sel),
        Ok(Action::None)
    );
    assert_matches!(mmio.read(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2), Ok(val) if val == q_sel);
    assert_matches!(mmio.read(offset as u64, size), Ok(val) if val == expected);
}

#[rstest]
#[case(VirtioCommonCfg::OFFSET_NUM_QUEUES, 2, 2)]
#[case(VirtioCommonCfg::OFFSET_CONFIG_GENERATION, 1, 0)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_NOTIFY_DATA, 2, 0)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_RESET, 2, 0)]
fn test_common_cfg_misc_reads(#[case] offset: usize, #[case] size: u8, #[case] expected: u64) {
    let queues = Arc::new([QueueReg::default(), QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);
    assert_matches!(mmio.read(offset as u64, size), Ok(val) if val == expected);
}

#[rstest]
#[case(0, 0x1111_2222)]
#[case(1, 0x3333_4444)]
#[case(10, 0)]
fn test_device_feature_reads(#[case] sel: u64, #[case] expected_feature: u64) {
    let queues = Arc::new([QueueReg::default()]);
    let (mut mmio, _) = create_test_mmio(queues);
    mmio.reg.device_feature = [0x1111_2222, 0x3333_4444, 0, 0];

    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DEVICE_FEATURE_SELECT as u64, 4, sel),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_FEATURE_SELECT as u64, 4),
        Ok(s) if s == sel
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_FEATURE as u64, 4),
        Ok(f) if f == expected_feature
    );
}

#[rstest]
// Bank 0: only offered device features are accepted
#[case(0, 0xffff_ffff, 0x1234_5678)]
// Bank 1: only offered device features are accepted
#[case(1, 0xffff_ffff, 0x0000_0005)]
// Bank 2 (no device features offered): writes are masked to 0
#[case(2, 0xffff_ffff, 0)]
// Out-of-bounds bank selection does not store and does not panic
#[case(10, 0x1234, 0)]
fn test_driver_features(#[case] bank: u64, #[case] write_val: u64, #[case] expected: u64) {
    let queues = Arc::new([QueueReg::default()]);
    let (mut mmio, _event_rx) = create_test_mmio(queues);
    mmio.reg.device_feature = [0x1234_5678, 0x0000_0005, 0, 0];

    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64,
            4,
            bank
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4,),
        Ok(val) if val == bank
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64, 4, write_val),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64, 4),
        Ok(val) if val == expected
    );
}

#[test]
fn test_driver_features_locked_after_features_ok() {
    let queues = Arc::new([QueueReg::default()]);
    let (mut mmio, _event_rx) = create_test_mmio(queues);
    mmio.reg.device_feature = [0x1234_5678, 0x0000_0005, 0, 0];

    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
            4,
            0xffff_ffff
        ),
        Ok(Action::None)
    );

    // Set status to ACK | DRIVER | FEATURES_OK
    let features_ok = DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            features_ok.bits() as u64
        ),
        Ok(Action::None)
    );

    // Feature writes after FEATURES_OK must be ignored
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64, 4),
        Ok(0x1234_5678)
    );
}

#[test]
fn test_device_status_valid_transitions() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues.clone());

    // Initially status is 0 (empty)
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(0)
    );

    // Transition 0 -> ACK
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            DevStatus::ACK.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == DevStatus::ACK.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Transition ACK -> ACK | DRIVER
    let ack_driver = DevStatus::ACK | DevStatus::DRIVER;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            ack_driver.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Set driver features
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
            4,
            0x1234_5678
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
            4,
            0x9abc_def0
        ),
        Ok(Action::None)
    );

    // Transition ACK | DRIVER -> ACK | DRIVER | FEATURES_OK
    let ack_driver_features = ack_driver | DevStatus::FEATURES_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            ack_driver_features.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == ack_driver_features.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Transition ACK | DRIVER | FEATURES_OK -> ACK | DRIVER | FEATURES_OK | DRIVER_OK
    let all_ok = ack_driver_features | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert_matches!(
        event_rx.try_recv(),
        Ok(WakeEvent::Start { param }) => {
            assert_eq!(param.feature, ((0x9abc_def0u128) << 32) | 0x1234_5678);
        }
    );
    assert!(event_rx.is_empty());

    // Rewriting same status is idempotent and does not send duplicate WakeEvent::Start
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Additional status flag: FAILED (contains old status)
    let failed = all_ok | DevStatus::FAILED;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            failed.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == failed.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Additional status flag: NEEDS_RESET (contains old status)
    let needs_reset = failed | DevStatus::NEEDS_RESET;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            needs_reset.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == needs_reset.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Enable queue and set MSI-X config vector
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_ENABLE as u64, 2, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR as u64, 2, 0),
        Ok(Action::None)
    );
    assert!(queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR as u64, 2),
        Ok(0)
    );

    // Reset device: write status = 0
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(0)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Reset));
    assert!(event_rx.is_empty());
    assert!(!queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR as u64, 2),
        Ok(vector) if vector == VIRTIO_MSI_NO_VECTOR as u64
    );
}

#[rstest]
// Invalid transitions from empty state (skipping ACK or invalid combinations)
#[case(DevStatus::empty(), DevStatus::DRIVER.bits() as u64)]
#[case(DevStatus::empty(), DevStatus::FEATURES_OK.bits() as u64)]
#[case(DevStatus::empty(), DevStatus::DRIVER_OK.bits() as u64)]
#[case(DevStatus::empty(), (DevStatus::ACK | DevStatus::FEATURES_OK).bits() as u64)]
#[case(DevStatus::empty(), (DevStatus::ACK | DevStatus::DRIVER | DevStatus::DRIVER_OK).bits() as u64)]
// Unknown status bits from empty state are ignored
#[case(DevStatus::empty(), 0x10)]
#[case(DevStatus::empty(), 0x20)]
#[case(DevStatus::empty(), 0x30)]
#[case(DevStatus::empty(), 0xff)]
// Unknown status bits while in ACK state are ignored
#[case(DevStatus::ACK, DevStatus::ACK.bits() as u64 | 0x10)]
// Invalid transition: skipping DRIVER
#[case(DevStatus::ACK, (DevStatus::ACK | DevStatus::FEATURES_OK).bits() as u64)]
#[case(DevStatus::ACK, (DevStatus::ACK | DevStatus::DRIVER_OK).bits() as u64)]
// Invalid transition: clearing DRIVER bit without resetting to 0
#[case(DevStatus::ACK | DevStatus::DRIVER, DevStatus::ACK.bits() as u64)]
// Invalid transition: setting DRIVER_OK without retaining ACK | DRIVER
#[case(DevStatus::ACK | DevStatus::DRIVER, DevStatus::DRIVER_OK.bits() as u64)]
// Invalid transition: skipping FEATURES_OK
#[case(DevStatus::ACK | DevStatus::DRIVER, (DevStatus::ACK | DevStatus::DRIVER | DevStatus::DRIVER_OK).bits() as u64)]
// Invalid transition: clearing bits from DRIVER_OK without resetting to 0
#[case(DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK, (DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK).bits() as u64)]
#[case(DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK, (DevStatus::ACK | DevStatus::DRIVER | DevStatus::DRIVER_OK).bits() as u64)]
#[case(DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK, (DevStatus::ACK | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK).bits() as u64)]
// Invalid transition: clearing FAILED flag without resetting to 0
#[case(
    DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK | DevStatus::FAILED,
    (DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK).bits() as u64
)]
fn test_device_status_invalid_transitions(#[case] initial: DevStatus, #[case] invalid_write: u64) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues);

    if !initial.is_empty() {
        assert_matches!(
            mmio.write(
                VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
                1,
                initial.bits() as u64
            ),
            Ok(Action::None)
        );
        while event_rx.try_recv().is_ok() {}
    }

    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            invalid_write
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == initial.bits() as u64
    );
    assert!(event_rx.is_empty());
}

#[rstest]
// Multi-step transition: 0 -> ACK | DRIVER
#[case(
    DevStatus::empty(),
    DevStatus::ACK | DevStatus::DRIVER,
    false
)]
// Multi-step transition: 0 -> ACK | DRIVER | FEATURES_OK | DRIVER_OK
#[case(
    DevStatus::empty(),
    DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK,
    true
)]
// Multi-step transition: ACK | DRIVER -> ACK | DRIVER | FEATURES_OK | DRIVER_OK
#[case(
    DevStatus::ACK | DevStatus::DRIVER,
    DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK,
    true
)]
fn test_device_status_multistep_transition(
    #[case] initial: DevStatus,
    #[case] target: DevStatus,
    #[case] expect_start: bool,
) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues);

    // Set driver features
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
            4,
            0x1234_5678
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DRIVER_FEATURE_SELECT as u64, 4, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DRIVER_FEATURE as u64,
            4,
            0x9abc_def0
        ),
        Ok(Action::None)
    );

    if !initial.is_empty() {
        assert_matches!(
            mmio.write(
                VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
                1,
                initial.bits() as u64
            ),
            Ok(Action::None)
        );
    }

    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            target.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(status) if status == target.bits() as u64
    );

    if expect_start {
        assert_matches!(
            event_rx.try_recv(),
            Ok(WakeEvent::Start { param }) => {
                assert_eq!(param.feature, ((0x9abc_def0u128) << 32) | 0x1234_5678);
            }
        );
    }
    assert!(event_rx.is_empty());
}

#[test]
fn test_device_status_reset_without_driver_ok() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues.clone());

    // Set status to ACK | DRIVER
    let ack_driver = DevStatus::ACK | DevStatus::DRIVER;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            ack_driver.bits() as u64
        ),
        Ok(Action::None)
    );

    // Enable queue and set MSI-X config vector before reset
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_QUEUE_ENABLE as u64, 2, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR as u64, 2, 0),
        Ok(Action::None)
    );
    assert!(queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR as u64, 2),
        Ok(0)
    );

    // Reset status to 0 before DRIVER_OK is set
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1),
        Ok(0)
    );
    // No WakeEvent::Reset since DRIVER_OK was not set
    assert!(event_rx.is_empty());
    // self.reset() should still disable queues and reset MSI-X vectors
    assert!(!queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR as u64, 2),
        Ok(vector) if vector == VIRTIO_MSI_NO_VECTOR as u64
    );
}

#[test]
fn test_device_reset_queue_registers() {
    let queues = Arc::new([
        QueueReg {
            size: AtomicU16::new(QUEUE_SIZE_MAX),
            ..Default::default()
        },
        QueueReg {
            size: AtomicU16::new(QUEUE_SIZE_MAX),
            ..Default::default()
        },
    ]);
    let (mmio, event_rx) = create_test_mmio(queues.clone());

    // Initialize MSI-X table with 2 Entry slots
    *mmio.irq_sender.msix_table.entries.write() = vec![
        MsixTableMmioEntry::Entry(MsixTableEntry::default()),
        MsixTableMmioEntry::Entry(MsixTableEntry::default()),
    ]
    .into_boxed_slice();

    for (offset, size, val) in [
        // Configure queue 0
        (VirtioCommonCfg::OFFSET_QUEUE_SELECT, 2, 0),
        (VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 128),
        (VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 4, 0x1000),
        (VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 4, 0x1111),
        (VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 4, 0x2000),
        (VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 4, 0x2222),
        (VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 4, 0x3000),
        (VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 4, 0x3333),
        (VirtioCommonCfg::OFFSET_QUEUE_MSIX_VECTOR, 2, 0),
        (VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 1),
        // Configure queue 1
        (VirtioCommonCfg::OFFSET_QUEUE_SELECT, 2, 1),
        (VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, 128),
        (VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 4, 0x4000),
        (VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 4, 0x4444),
        (VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 4, 0x5000),
        (VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 4, 0x5555),
        (VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 4, 0x6000),
        (VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 4, 0x6666),
        (VirtioCommonCfg::OFFSET_QUEUE_MSIX_VECTOR, 2, 1),
        (VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 1),
    ] {
        assert_matches!(mmio.write(offset as u64, size, val), Ok(Action::None));
    }

    // Set device status to DRIVER_OK
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64,
            1,
            (DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK)
                .bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Start { .. }));

    // Reset device: write status = 0
    assert_matches!(
        mmio.write(VirtioCommonCfg::OFFSET_DEVICE_STATUS as u64, 1, 0),
        Ok(Action::None)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Reset));
    assert!(event_rx.is_empty());

    // Verify all queue registers are reset
    for (q_index, _) in queues.iter().enumerate() {
        assert_matches!(
            mmio.write(
                VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64,
                2,
                q_index as u64
            ),
            Ok(Action::None)
        );
        for (offset, size, expected) in [
            (VirtioCommonCfg::OFFSET_QUEUE_SIZE, 2, QUEUE_SIZE_MAX as u64),
            (VirtioCommonCfg::OFFSET_QUEUE_DESC_LO, 4, 0),
            (VirtioCommonCfg::OFFSET_QUEUE_DESC_HI, 4, 0),
            (VirtioCommonCfg::OFFSET_QUEUE_DRIVER_LO, 4, 0),
            (VirtioCommonCfg::OFFSET_QUEUE_DRIVER_HI, 4, 0),
            (VirtioCommonCfg::OFFSET_QUEUE_DEVICE_LO, 4, 0),
            (VirtioCommonCfg::OFFSET_QUEUE_DEVICE_HI, 4, 0),
            (
                VirtioCommonCfg::OFFSET_QUEUE_MSIX_VECTOR,
                2,
                VIRTIO_MSI_NO_VECTOR as u64,
            ),
            (VirtioCommonCfg::OFFSET_QUEUE_ENABLE, 2, 0),
        ] {
            assert_matches!(
                mmio.read(offset as u64, size),
                Ok(val) if val == expected
            );
        }
    }
}

#[rstest]
#[case(VirtioCommonCfg::OFFSET_CONFIG_MSIX_VECTOR, None)]
#[case(VirtioCommonCfg::OFFSET_QUEUE_MSIX_VECTOR, Some(0))]
fn test_msix_vector_configuration(#[case] offset: usize, #[case] queue_sel: Option<u16>) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);

    // Initialize MSI-X table with 2 Entry slots
    *mmio.irq_sender.msix_table.entries.write() = vec![
        MsixTableMmioEntry::Entry(MsixTableEntry::default()),
        MsixTableMmioEntry::Entry(MsixTableEntry::default()),
    ]
    .into_boxed_slice();

    if let Some(q) = queue_sel {
        assert_matches!(
            mmio.write(VirtioCommonCfg::OFFSET_QUEUE_SELECT as u64, 2, q as u64),
            Ok(Action::None)
        );
    }

    // Configure MSI-X vector from VIRTIO_MSI_NO_VECTOR -> 0 -> 1
    assert_matches!(mmio.write(offset as u64, 2, 0), Ok(Action::None));
    assert_matches!(mmio.read(offset as u64, 2), Ok(0));
    assert_matches!(mmio.write(offset as u64, 2, 1), Ok(Action::None));
    assert_matches!(mmio.read(offset as u64, 2), Ok(1));

    // Assign vector 1 to an IrqFd
    mmio.irq_sender.msix_table.entries.write()[1] = MsixTableMmioEntry::IrqFd(TestIrqFd::default());

    // Attempt to change vector from 1 to 0 should be rejected
    assert_matches!(mmio.write(offset as u64, 2, 0), Ok(Action::None));
    assert_matches!(mmio.read(offset as u64, 2), Ok(1));
}

#[rstest]
// Valid queue notify (to valid queue offset) wakes up queue 0
#[case(VirtioPciRegister::OFFSET_QUEUE_NOTIFY, true)]
// Queue notify to reserved invalid slot (at queues.len()) does not wake up any queue
#[case(VirtioPciRegister::OFFSET_QUEUE_NOTIFY + size_of::<u32>(), false)]
fn test_queue_notify(#[case] offset: usize, #[case] expect_wake: bool) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues);

    assert_matches!(mmio.write(offset as u64, 2, 0), Ok(Action::None));
    if expect_wake {
        assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Notify { q_index: 0 }));
    }
    assert!(event_rx.is_empty());
}

#[test]
fn test_notify_with_ioeventfds() {
    let queues = Arc::new([QueueReg::default()]);
    let (event_tx, event_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let msi_sender = TestMsiSender::default();
    let msix_table = Arc::new(MsixTableMmio {
        entries: RwLock::new(vec![].into_boxed_slice()),
    });
    let irq_sender = Arc::new(PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            queues: vec![AtomicU16::new(VIRTIO_MSI_NO_VECTOR)],
        },
        msix_table,
        msi_sender,
    });
    let mmio = VirtioPciRegisterMmio {
        name: "test-virtio-pci-ioeventfd".into(),
        reg: Register {
            device_feature: [u32::MAX; 4],
            ..Default::default()
        },
        queues,
        irq_sender,
        ioeventfds: Some(Arc::new([FakeIoeventFd])),
        event_tx,
        notifier,
    };

    assert_matches!(
        mmio.write(VirtioPciRegister::OFFSET_QUEUE_NOTIFY as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Notify { q_index: 0 }));
}

#[test]
fn test_wake_up_dev_channel_error() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues);

    // Drop receiver so send will fail
    drop(event_rx);

    // Trigger notify event
    assert_matches!(
        mmio.write(VirtioPciRegister::OFFSET_QUEUE_NOTIFY as u64, 2, 0),
        Ok(Action::None)
    );
}

#[rstest]
// Invalid register write with offset < OFFSET_QUEUE_NOTIFY
#[case(0x3c, 4, 0x1234)]
// Invalid register write with offset >= OFFSET_QUEUE_NOTIFY
#[case(0xdead_beef, 4, 0x1234)]
fn test_invalid_register_writes(#[case] offset: u64, #[case] size: u8, #[case] val: u64) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);
    assert_matches!(mmio.write(offset, size, val), Ok(Action::None));
}

#[rstest]
#[case(0x1234, 4)]
#[case(0, 3)]
fn test_invalid_register_reads(#[case] offset: u64, #[case] size: u8) {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, _) = create_test_mmio(queues);
    assert_matches!(mmio.read(offset, size), Ok(0));
}

#[rstest]
#[case(1, (size_of::<VirtioPciRegister>() + size_of::<u32>() * 2) as u64)]
#[case(3, (size_of::<VirtioPciRegister>() + size_of::<u32>() * 4) as u64)]
fn test_mmio_size(#[case] num_queues: usize, #[case] expected_size: u64) {
    let queues = (0..num_queues).map(|_| QueueReg::default()).collect();
    let (mmio, _) = create_test_mmio(queues);
    assert_eq!(mmio.size(), expected_size);
}

#[derive(Debug, Clone)]
struct TestDevConfig {
    size: u64,
}

impl Mmio for TestDevConfig {
    fn size(&self) -> u64 {
        self.size
    }

    fn read(&self, _offset: u64, _size: u8) -> mem::Result<u64> {
        Ok(0x42)
    }

    fn write(&self, _offset: u64, _size: u8, _val: u64) -> mem::Result<Action> {
        Ok(Action::None)
    }
}

fn create_test_virtio_device<S, E>(
    id: DeviceId,
    config_size: u64,
    shared_mem: Option<Arc<MemRegion>>,
    num_queues: usize,
) -> (VirtioDevice<S, E>, Receiver<WakeEvent<S, E>>)
where
    S: IrqSender,
    E: IoeventFd,
{
    let (event_tx, event_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let queue_regs = (0..num_queues)
        .map(|_| QueueReg::default())
        .collect::<Arc<[_]>>();
    let dev = VirtioDevice {
        name: "test-dev".into(),
        id,
        device_config: Arc::new(TestDevConfig { size: config_size }),
        device_feature: (VirtioFeature::VERSION_1 | VirtioFeature::RING_PACKED).bits(),
        queue_regs,
        shared_mem_regions: shared_mem,
        notifier,
        event_tx,
        worker_handle: None,
    };
    (dev, event_rx)
}

#[test]
fn test_pci_irq_sender_config_and_queue_irq() {
    let msix_table = Arc::new(MsixTableMmio {
        entries: RwLock::new(
            vec![
                MsixTableMmioEntry::Entry(MsixTableEntry {
                    addr_lo: 0xfee0_0000,
                    addr_hi: 0,
                    data: 0x20,
                    control: MsixVectorCtrl(0), // unmasked
                }),
                MsixTableMmioEntry::Entry(MsixTableEntry {
                    addr_lo: 0xfee0_0000,
                    addr_hi: 0,
                    data: 0x21,
                    control: MsixVectorCtrl(1), // masked
                }),
                MsixTableMmioEntry::Entry(MsixTableEntry {
                    addr_lo: 0xfee0_0000,
                    addr_hi: 0x1,
                    data: 0x22,
                    control: MsixVectorCtrl(0), // unmasked 64-bit
                }),
            ]
            .into_boxed_slice(),
        ),
    });
    let messages = Arc::new(Mutex::new(Vec::new()));
    let msi_sender = TestMsiSender {
        messages: messages.clone(),
        ..Default::default()
    };
    let irq_sender = PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            queues: vec![
                AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
                AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            ],
        },
        msix_table: msix_table.clone(),
        msi_sender,
    };

    // Config IRQ when VIRTIO_MSI_NO_VECTOR: no send
    irq_sender.config_irq();
    assert!(messages.lock().is_empty());

    // Config IRQ to vector 0: sends MSI
    irq_sender.msix_vector.config.store(0, Ordering::Release);
    irq_sender.config_irq();
    assert_eq!(*messages.lock(), vec![(0xfee0_0000, 0x20)]);
    messages.lock().clear();

    // Config IRQ to vector 1 (masked): no send
    irq_sender.msix_vector.config.store(1, Ordering::Release);
    irq_sender.config_irq();
    assert!(messages.lock().is_empty());

    // Config IRQ to vector 2 (64-bit high address): sends to 0x1_fee0_0000
    irq_sender.msix_vector.config.store(2, Ordering::Release);
    irq_sender.config_irq();
    assert_eq!(*messages.lock(), vec![(0x1_fee0_0000, 0x22)]);
    messages.lock().clear();

    // Config IRQ to vector 99 (invalid / out of bounds): logs error, does not send
    irq_sender.msix_vector.config.store(99, Ordering::Release);
    irq_sender.config_irq();
    assert!(messages.lock().is_empty());

    // Queue IRQ when invalid index (e.g. 5): logs error
    irq_sender.queue_irq(5);
    assert!(messages.lock().is_empty());

    // Queue IRQ when queue vector is VIRTIO_MSI_NO_VECTOR: does nothing
    irq_sender.queue_irq(0);
    assert!(messages.lock().is_empty());

    // Queue IRQ for queue 0 with vector 0: sends MSI
    irq_sender.msix_vector.queues[0].store(0, Ordering::Release);
    irq_sender.queue_irq(0);
    assert_eq!(*messages.lock(), vec![(0xfee0_0000, 0x20)]);
    messages.lock().clear();

    // Queue IRQ for queue 1 with vector 1 (masked): does not send
    irq_sender.msix_vector.queues[1].store(1, Ordering::Release);
    irq_sender.queue_irq(1);
    assert!(messages.lock().is_empty());
}

#[test]
fn test_pci_irq_sender_error_sending() {
    let msix_table = Arc::new(MsixTableMmio {
        entries: RwLock::new(
            vec![MsixTableMmioEntry::Entry(MsixTableEntry {
                addr_lo: 0xfee0_0000,
                addr_hi: 0,
                data: 0x20,
                control: MsixVectorCtrl(0),
            })]
            .into_boxed_slice(),
        ),
    });
    let irq_sender = PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(0),
            queues: vec![],
        },
        msix_table,
        msi_sender: TestMsiSender {
            fail_mode: Some(std::io::ErrorKind::Other),
            ..Default::default()
        },
    };
    // Should handle error gracefully without panicking
    irq_sender.config_irq();
}

#[test]
fn test_pci_irq_sender_irqfd() {
    let msix_table = Arc::new(MsixTableMmio {
        entries: RwLock::new(
            vec![
                MsixTableMmioEntry::Entry(MsixTableEntry {
                    addr_lo: 0xfee0_0000,
                    addr_hi: 0,
                    data: 0x20,
                    control: MsixVectorCtrl(0),
                }),
                MsixTableMmioEntry::Entry(MsixTableEntry {
                    addr_lo: 0xfee0_1000,
                    addr_hi: 0,
                    data: 0x21,
                    control: MsixVectorCtrl(0),
                }),
            ]
            .into_boxed_slice(),
        ),
    });
    let irq_sender = PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            queues: vec![AtomicU16::new(VIRTIO_MSI_NO_VECTOR), AtomicU16::new(1)],
        },
        msix_table: msix_table.clone(),
        msi_sender: TestMsiSender::default(),
    };

    // config_irqfd with invalid vector returns Err
    assert!(irq_sender.config_irqfd(|_| Ok(())).is_err());

    // config_irqfd with valid vector 0 transforms Entry into IrqFd
    irq_sender.msix_vector.config.store(0, Ordering::Release);
    let r = irq_sender.config_irqfd(|fd| Ok(fd.as_raw_fd()));
    assert_matches!(r, Ok(_));
    assert_matches!(msix_table.entries.read()[0], MsixTableMmioEntry::IrqFd(_));

    // Subsequent config_irqfd call reuses existing IrqFd
    let r2 = irq_sender.config_irqfd(|fd| Ok(fd.as_raw_fd()));
    assert_matches!(r2, Ok(_));

    // queue_irqfd with invalid queue index returns Err
    assert!(irq_sender.queue_irqfd(99, |_| Ok(())).is_err());

    // queue_irqfd for queue 0 (vector VIRTIO_MSI_NO_VECTOR) returns Err
    assert!(irq_sender.queue_irqfd(0, |_| Ok(())).is_err());

    // queue_irqfd for queue 1 (vector 1) transforms Entry into IrqFd
    let qr = irq_sender.queue_irqfd(1, |fd| Ok(fd.as_raw_fd()));
    assert_matches!(qr, Ok(_));
    assert_matches!(msix_table.entries.read()[1], MsixTableMmioEntry::IrqFd(_));

    // config_irqfd when create_irqfd fails returns Err
    let msix_table_entry_only = Arc::new(MsixTableMmio {
        entries: RwLock::new(
            vec![MsixTableMmioEntry::Entry(MsixTableEntry::default())].into_boxed_slice(),
        ),
    });
    let fail_sender = PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(0),
            queues: vec![],
        },
        msix_table: msix_table_entry_only,
        msi_sender: TestMsiSender {
            fail_mode: Some(std::io::ErrorKind::Other),
            ..Default::default()
        },
    };
    assert!(fail_sender.config_irqfd(|_| Ok(())).is_err());
}

#[rstest]
#[case(DeviceId::NET, 0x02, 0x00, 0x1041)]
#[case(DeviceId::BLOCK, 0x01, 0x00, 0x1042)]
#[case(DeviceId::FILE_SYSTEM, 0x01, 0x80, 0x105a)]
#[case(DeviceId::SOCKET, 0x02, 0x80, 0x1053)]
#[case(DeviceId::ENTROPY, 0xff, 0x00, 0x1044)]
#[case(DeviceId(99), 0xff, 0x00, 0x1040 + 99)]
fn test_virtio_pci_device_classes(
    #[case] id: DeviceId,
    #[case] expected_class: u8,
    #[case] expected_subclass: u8,
    #[case] expected_dev_id: u16,
) {
    let (dev, _rx) =
        create_test_virtio_device::<PciIrqSender<TestMsiSender>, TestIoeventFd>(id, 0, None, 2);
    let pci_dev = VirtioPciDevice::new(
        dev,
        TestMsiSender::default(),
        TestIoeventFdRegistry::default(),
    )
    .unwrap();

    let config = pci_dev.config();
    // Vendor ID
    assert_matches!(config.read(0x00, 2), Ok(0x1af4));
    // Device ID
    assert_matches!(config.read(0x02, 2), Ok(val) if val == expected_dev_id as u64);
    // Revision
    assert_matches!(config.read(0x08, 1), Ok(1));
    // Class and subclass
    let class_code = ((expected_class as u64) << 8) | (expected_subclass as u64);
    assert_matches!(config.read(0x0a, 2), Ok(val) if val == class_code);
    // Header Type
    assert_matches!(config.read(0x0e, 1), Ok(0x00));
    // Subsystem Vendor & ID
    assert_matches!(
        config.read(0x2c, 4),
        Ok(val) if val == ((expected_dev_id as u64) << 16)
    );
    // Name
    assert_eq!(Pci::name(&pci_dev), "test-dev");

    // Queue reset write
    assert_matches!(
        pci_dev
            .registers
            .write(VirtioCommonCfg::OFFSET_QUEUE_RESET as u64, 2, 1,),
        Ok(Action::None)
    );
}

#[test]
fn test_virtio_pci_device_with_config_and_shared_memory_prefetchable() {
    let shared_mem = Arc::new(MemRegion {
        ranges: vec![MemRange::Span(0x1000), MemRange::Span(0x2_0000_0000)],
        entries: vec![
            MemRegionEntry {
                size: 0x1000,
                type_: MemRegionType::Hidden,
            },
            MemRegionEntry {
                size: 0x2_0000_0000,
                type_: MemRegionType::Hidden,
            },
        ],
        callbacks: Mutex::new(vec![]),
    });
    let (dev, _rx) = create_test_virtio_device::<PciIrqSender<TestMsiSender>, TestIoeventFd>(
        DeviceId::FILE_SYSTEM,
        32,
        Some(shared_mem),
        2,
    );
    let pci_dev = VirtioPciDevice::new(
        dev,
        TestMsiSender::default(),
        TestIoeventFdRegistry::default(),
    )
    .unwrap();

    // BAR 0 should be MEM32
    assert_matches!(pci_dev.config.header.bars[0], PciBar::Mem(_));
    assert_matches!(pci_dev.config.read(0x10, 4), Ok(val) if val as u32 == BAR_MEM32);

    // BAR 2 should be MEM64 | PREFETCHABLE
    assert_matches!(pci_dev.config.header.bars[2], PciBar::Mem(_));
    assert_matches!(
        pci_dev.config.read(0x18, 4),
        Ok(val) if val as u32 == (BAR_MEM64 | BAR_PREFETCHABLE)
    );

    // Caps list should contain MSI-X, Common, ISR, Notify, Device Config, and 2 Shared Memory caps
    let mut cap_offset = pci_dev.config.read(0x34, 1).unwrap();
    let mut cap_types = Vec::new();
    while cap_offset != 0 {
        let cap_id = pci_dev.config.read(cap_offset, 1).unwrap();
        let next = pci_dev.config.read(cap_offset + 1, 1).unwrap();
        let cfg_type = if cap_id == PciCapId::VENDOR.raw() as u64 {
            Some(pci_dev.config.read(cap_offset + 3, 1).unwrap())
        } else {
            None
        };
        cap_types.push((cap_id, cfg_type));
        cap_offset = next;
    }

    assert_eq!(cap_types.len(), 7); // MSIX, Common, ISR, Notify, Device, SharedMem0, SharedMem1
}

#[test]
fn test_virtio_pci_device_shared_memory_non_prefetchable() {
    let shared_mem = Arc::new(MemRegion {
        ranges: vec![MemRange::Emulated(Arc::new(TestDevConfig { size: 0x1000 }))],
        entries: vec![MemRegionEntry {
            size: 0x1000,
            type_: MemRegionType::Hidden,
        }],
        callbacks: Mutex::new(vec![]),
    });
    let (dev, _rx) = create_test_virtio_device::<PciIrqSender<TestMsiSender>, TestIoeventFd>(
        DeviceId::FILE_SYSTEM,
        0,
        Some(shared_mem),
        1,
    );
    let pci_dev = VirtioPciDevice::new(
        dev,
        TestMsiSender::default(),
        TestIoeventFdRegistry::default(),
    )
    .unwrap();

    // BAR 2 should be MEM32 when non-prefetchable (emulated ranges)
    assert_matches!(pci_dev.config.read(0x18, 4), Ok(val) if val as u32 == BAR_MEM32);
}

#[test]
fn test_virtio_pci_device_ioeventfd_callback() {
    let (dev, _rx) = create_test_virtio_device::<PciIrqSender<TestMsiSender>, TestIoeventFd>(
        DeviceId::NET,
        0,
        None,
        2,
    );
    let registry = TestIoeventFdRegistry::default();
    let registered = registry.registered.clone();
    let deregistered = registry.deregistered.clone();
    let pci_dev = VirtioPciDevice::new(dev, TestMsiSender::default(), registry).unwrap();

    let PciBar::Mem(bar0) = &pci_dev.config.header.bars[0] else {
        panic!("expected Mem BAR");
    };

    let callbacks = bar0.callbacks.lock();
    assert_eq!(callbacks.len(), 2);

    // Test mapped callback
    let base_addr = 0x2000_0000;
    assert_matches!(callbacks[0].mapped(base_addr), Ok(()));
    let registered = registered.lock();
    assert_eq!(registered.len(), 2);
    let expected_notify_base =
        base_addr + (12 << 10) + VirtioPciRegister::OFFSET_QUEUE_NOTIFY as u64;
    assert_eq!(
        registered[0],
        RegisteredAddr {
            gpa: expected_notify_base,
            len: 0,
            data: None
        }
    );
    assert_eq!(
        registered[1],
        RegisteredAddr {
            gpa: expected_notify_base + 4,
            len: 0,
            data: None
        }
    );

    // Test unmapped callback
    assert_matches!(callbacks[0].unmapped(), Ok(()));
    assert_eq!(*deregistered.lock(), 2);
}

#[rstest]
#[case(Some(ErrorKind::Unsupported))]
#[case(Some(ErrorKind::PermissionDenied))]
fn test_virtio_pci_device_ioeventfd_fallback(#[case] fail_mode: Option<ErrorKind>) {
    let (dev, _rx) = create_test_virtio_device::<PciIrqSender<TestMsiSender>, TestIoeventFd>(
        DeviceId::NET,
        0,
        None,
        1,
    );
    let registry = TestIoeventFdRegistry {
        fail_mode,
        ..Default::default()
    };
    let pci_dev = VirtioPciDevice::new(dev, TestMsiSender::default(), registry).unwrap();

    assert!(pci_dev.registers.ioeventfds.is_none());
}

#[test]
fn test_virtio_pci_device_pci_reset() {
    let (dev, event_rx) = create_test_virtio_device::<PciIrqSender<TestMsiSender>, TestIoeventFd>(
        DeviceId::NET,
        0,
        None,
        1,
    );
    let pci_dev = VirtioPciDevice::new(
        dev,
        TestMsiSender::default(),
        TestIoeventFdRegistry::default(),
    )
    .unwrap();

    // Set queue enabled and device status
    pci_dev.registers.queues[0]
        .enabled
        .store(true, Ordering::Release);
    pci_dev
        .registers
        .reg
        .status
        .store(DevStatus::DRIVER_OK.bits(), Ordering::Release);

    // Call Pci::reset
    assert_matches!(pci_dev.reset(), Ok(()));

    // Device status should be cleared
    assert_eq!(pci_dev.registers.reg.status.load(Ordering::Acquire), 0);
    // Queue should be disabled
    assert!(!pci_dev.registers.queues[0].enabled.load(Ordering::Acquire));
    // Reset event sent
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Reset));
}

#[test]
fn test_virtio_pci_cap_traits() {
    let mut cap = VirtioPciCap::default();
    PciCap::set_next(&mut cap, 0x50);
    assert_eq!(cap.header.next, 0x50);
    assert_matches!(PciConfigArea::reset(&cap), Ok(()));
    assert_matches!(cap.read(0, 1), Ok(0));
    assert_matches!(cap.write(0, 1, 0), Ok(Action::None));

    let mut cap64 = VirtioPciCap64::default();
    PciCap::set_next(&mut cap64, 0x60);
    assert_eq!(cap64.cap.header.next, 0x60);
    assert_matches!(PciConfigArea::reset(&cap64), Ok(()));
    assert_matches!(cap64.read(0, 1), Ok(0));
    assert_matches!(cap64.write(0, 1, 0), Ok(Action::None));

    let mut notify_cap = VirtioPciNotifyCap::default();
    PciCap::set_next(&mut notify_cap, 0x70);
    assert_eq!(notify_cap.cap.header.next, 0x70);
    assert_matches!(PciConfigArea::reset(&notify_cap), Ok(()));
    assert_matches!(notify_cap.read(0, 1), Ok(0));
    assert_matches!(notify_cap.write(0, 1, 0), Ok(Action::None));
}
