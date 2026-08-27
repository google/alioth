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
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use assert_matches::assert_matches;
use parking_lot::RwLock;

use crate::hv::tests::TestMsiSender;
use crate::mem::emulated::{Action, Mmio};
use crate::pci::cap::MsixTableMmio;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::{Register, WakeEvent};
use crate::virtio::pci::{
    PciIrqSender, VIRTIO_MSI_NO_VECTOR, VirtioCommonCfg, VirtioPciMsixVector, VirtioPciRegister,
    VirtioPciRegisterMmio,
};
use crate::virtio::queue::QueueReg;
use crate::virtio::tests::FakeIoeventFd;
use crate::virtio::{DevStatus, VirtioFeature};

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

#[test]
fn test_virtio_pci_queue_registers() {
    let queues = Arc::new([QueueReg {
        desc: AtomicU64::new(0x1122_3344_5566_7788),
        driver: AtomicU64::new(0xaabb_ccdd_eeff_0011),
        device: AtomicU64::new(0x0123_4567_89ab_cdef),
        ..Default::default()
    }]);
    let (mmio, event_rx) = create_test_mmio(queues.clone());

    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO.0 as u64, 4),
        Ok(0x5566_7788)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DESC_HI.0 as u64, 4),
        Ok(0x1122_3344)
    );

    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4),
        Ok(0xeeff_0011)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_HI.0 as u64, 4),
        Ok(0xaabb_ccdd)
    );

    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO.0 as u64, 4),
        Ok(0x89ab_cdef)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_HI.0 as u64, 4),
        Ok(0x0123_4567)
    );

    // Feature select 32-bit round trip
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT.0 as u64,
            4,
            0xdead_beef
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT.0 as u64, 4),
        Ok(0xdead_beef)
    );

    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_NOTIFY_DATA.0 as u64, 2),
        Ok(0)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_RESET.0 as u64, 2),
        Ok(0)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_RESET.0 as u64, 2, 1),
        Ok(Action::None)
    );

    // Queue size cannot be modified while queue is enabled
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_SELECT.0 as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_ENABLE.0 as u64, 2, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_SIZE.0 as u64, 2, 0xffff),
        Ok(Action::None)
    );
    assert_ne!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_SIZE.0 as u64, 2)
            .unwrap(),
        0xffff
    );

    // Valid queue notify (to valid queue offset) wakes up the queue
    assert_matches!(
        mmio.write(VirtioPciRegister::OFFSET_QUEUE_NOTIFY as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Notify { q_index: 0 }));

    // Queue notify offset for out of bounds queue returns the reserved slot (queues.len())
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_SELECT.0 as u64, 2, 0xffff),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_NOTIFY_OFF.0 as u64, 2),
        Ok(1)
    );

    // Queue notify to reserved invalid slot does not wake up any queue
    let invalid_notify_offset =
        VirtioPciRegister::OFFSET_QUEUE_NOTIFY + size_of::<u32>() * queues.len();
    assert_matches!(
        mmio.write(invalid_notify_offset as u64, 2, 0),
        Ok(Action::None)
    );
    assert!(event_rx.is_empty());
}

#[test]
fn test_virtio_pci_device_status_valid_transitions() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues.clone());

    // Initially status is 0 (empty)
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(0)
    );

    // Transition 0 -> ACK
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            DevStatus::ACK.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == DevStatus::ACK.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Transition ACK -> ACK | DRIVER
    let ack_driver = DevStatus::ACK | DevStatus::DRIVER;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            ack_driver.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Set driver features
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0x1234_5678
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0x9abc_def0
        ),
        Ok(Action::None)
    );

    // Transition ACK | DRIVER -> ACK | DRIVER | FEATURES_OK
    let ack_driver_features = ack_driver | DevStatus::FEATURES_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            ack_driver_features.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver_features.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Transition ACK | DRIVER | FEATURES_OK -> ACK | DRIVER | FEATURES_OK | DRIVER_OK
    let all_ok = ack_driver_features | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
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
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Additional status flag: FAILED (contains old status)
    let failed = all_ok | DevStatus::FAILED;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            failed.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == failed.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Additional status flag: NEEDS_RESET (contains old status)
    let needs_reset = failed | DevStatus::NEEDS_RESET;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            needs_reset.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == needs_reset.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Enable queue and set MSI-X config vector
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_SELECT.0 as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_ENABLE.0 as u64, 2, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR.0 as u64, 2, 0),
        Ok(Action::None)
    );
    assert!(queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR.0 as u64, 2),
        Ok(0)
    );

    // Reset device: write status = 0
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(0)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Reset));
    assert!(event_rx.is_empty());
    assert!(!queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR.0 as u64, 2),
        Ok(vector) if vector == VIRTIO_MSI_NO_VECTOR as u64
    );
}

#[test]
fn test_virtio_pci_device_status_invalid_transitions() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues);

    // Invalid transitions from empty state (skipping ACK or invalid combinations)
    for invalid in [
        DevStatus::DRIVER,
        DevStatus::FEATURES_OK,
        DevStatus::DRIVER_OK,
        DevStatus::ACK | DevStatus::FEATURES_OK,
        DevStatus::ACK | DevStatus::DRIVER | DevStatus::DRIVER_OK,
    ] {
        assert_matches!(
            mmio.write(
                VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
                1,
                invalid.bits() as u64
            ),
            Ok(Action::None)
        );
        assert_matches!(
            mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
            Ok(0)
        );
        assert!(event_rx.is_empty());
    }

    // Unknown status bits from empty state are ignored
    for unknown in [0x10u64, 0x20, 0x30, 0xff] {
        assert_matches!(
            mmio.write(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1, unknown),
            Ok(Action::None)
        );
        assert_matches!(
            mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
            Ok(0)
        );
        assert!(event_rx.is_empty());
    }

    // Advance to ACK
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            DevStatus::ACK.bits() as u64
        ),
        Ok(Action::None)
    );

    // Unknown status bits while in ACK state are ignored
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            DevStatus::ACK.bits() as u64 | 0x10
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == DevStatus::ACK.bits() as u64
    );

    // Invalid transition: skipping DRIVER (writing ACK | FEATURES_OK)
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            (DevStatus::ACK | DevStatus::FEATURES_OK).bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == DevStatus::ACK.bits() as u64
    );

    // Invalid transition: skipping DRIVER (writing ACK | DRIVER_OK)
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            (DevStatus::ACK | DevStatus::DRIVER_OK).bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == DevStatus::ACK.bits() as u64
    );

    // Advance to ACK | DRIVER
    let ack_driver = DevStatus::ACK | DevStatus::DRIVER;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            ack_driver.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );

    // Invalid transition: clearing DRIVER bit (writing ACK only) without resetting to 0
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            DevStatus::ACK.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Invalid transition: setting DRIVER_OK without retaining ACK | DRIVER
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            DevStatus::DRIVER_OK.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Invalid transition: skipping FEATURES_OK (writing ACK | DRIVER | DRIVER_OK)
    let skipping_features_ok = ack_driver | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            skipping_features_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Advance to DRIVER_OK
    let all_ok = ack_driver | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Start { .. }));

    // Invalid transition: clearing DRIVER_OK without resetting to 0
    let without_driver_ok = ack_driver | DevStatus::FEATURES_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            without_driver_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Invalid transition: clearing FEATURES_OK without resetting to 0
    let without_features_ok = ack_driver | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            without_features_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Invalid transition: clearing DRIVER without resetting to 0
    let without_driver = DevStatus::ACK | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            without_driver.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Add FAILED flag
    let failed = all_ok | DevStatus::FAILED;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            failed.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == failed.bits() as u64
    );

    // Invalid transition: clearing FAILED flag without resetting to 0
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == failed.bits() as u64
    );
    assert!(event_rx.is_empty());
}

#[test]
fn test_virtio_pci_device_status_multistep_transition() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues);

    // Set driver features
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0x1234_5678
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0x9abc_def0
        ),
        Ok(Action::None)
    );

    // Multi-step transition: 0 -> ACK | DRIVER | FEATURES_OK | DRIVER_OK in a single write
    let all_ok = DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK | DevStatus::DRIVER_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert_matches!(
        event_rx.try_recv(),
        Ok(WakeEvent::Start { param }) => {
            assert_eq!(param.feature, ((0x9abc_def0u128) << 32) | 0x1234_5678);
        }
    );
    assert!(event_rx.is_empty());

    // Reset to 0
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1, 0),
        Ok(Action::None)
    );
    assert_matches!(event_rx.try_recv(), Ok(WakeEvent::Reset));

    // Multi-step transition: 0 -> ACK | DRIVER in a single write
    let ack_driver = DevStatus::ACK | DevStatus::DRIVER;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            ack_driver.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == ack_driver.bits() as u64
    );
    assert!(event_rx.is_empty());

    // Multi-step transition: ACK | DRIVER -> ACK | DRIVER | FEATURES_OK | DRIVER_OK in a single write
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            all_ok.bits() as u64
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(status) if status == all_ok.bits() as u64
    );
    assert_matches!(
        event_rx.try_recv(),
        Ok(WakeEvent::Start { param }) => {
            assert_eq!(param.feature, ((0x9abc_def0u128) << 32) | 0x1234_5678);
        }
    );
    assert!(event_rx.is_empty());
}

#[test]
fn test_virtio_pci_device_status_reset_without_driver_ok() {
    let queues = Arc::new([QueueReg::default()]);
    let (mmio, event_rx) = create_test_mmio(queues.clone());

    // Set status to ACK | DRIVER
    let ack_driver = DevStatus::ACK | DevStatus::DRIVER;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            ack_driver.bits() as u64
        ),
        Ok(Action::None)
    );

    // Enable queue and set MSI-X config vector before reset
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_SELECT.0 as u64, 2, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_ENABLE.0 as u64, 2, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR.0 as u64, 2, 0),
        Ok(Action::None)
    );
    assert!(queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR.0 as u64, 2),
        Ok(0)
    );

    // Reset status to 0 before DRIVER_OK is set
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64, 1),
        Ok(0)
    );
    // No WakeEvent::Reset since DRIVER_OK was not set
    assert!(event_rx.is_empty());
    // self.reset() should still disable queues and reset MSI-X vectors
    assert!(!queues[0].enabled.load(Ordering::Acquire));
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR.0 as u64, 2),
        Ok(vector) if vector == VIRTIO_MSI_NO_VECTOR as u64
    );
}

#[test]
fn test_virtio_pci_driver_features() {
    let queues = Arc::new([QueueReg::default()]);
    let (mut mmio, _event_rx) = create_test_mmio(queues);
    mmio.reg.device_feature = [0x1234_5678, 0x0000_0005, 0, 0];

    // Bank 0: only offered device features are accepted
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0xffff_ffff
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4),
        Ok(0x1234_5678)
    );

    // Bank 1: only offered device features are accepted
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0xffff_ffff
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4),
        Ok(0x0000_0005)
    );

    // Bank 2 (no device features offered): writes are masked to 0
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 2),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            0xffff_ffff
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4),
        Ok(0)
    );

    // Out-of-bounds bank selection does not store and does not panic
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64,
            4,
            10
        ),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4, 0x1234),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4),
        Ok(0)
    );

    // Set status to ACK | DRIVER | FEATURES_OK
    let features_ok = DevStatus::ACK | DevStatus::DRIVER | DevStatus::FEATURES_OK;
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS.0 as u64,
            1,
            features_ok.bits() as u64
        ),
        Ok(Action::None)
    );

    // Feature writes after FEATURES_OK must be ignored
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4, 0),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64, 4),
        Ok(0x1234_5678)
    );
}

#[test]
fn test_virtio_pci_queue_alignment() {
    let queues = Arc::new([QueueReg {
        desc: AtomicU64::new(0x1000_0000),
        driver: AtomicU64::new(0x2000_0000),
        device: AtomicU64::new(0x3000_0000),
        ..Default::default()
    }]);
    let (mmio, _event_rx) = create_test_mmio(queues);

    // Select queue 0
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_SELECT.0 as u64, 2, 0),
        Ok(Action::None)
    );

    // LAYOUT_QUEUE_DESC_LO: must be 16-byte aligned
    // Unaligned write (e.g. offset 8) should be ignored
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO.0 as u64, 4, 0x1008),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO.0 as u64, 4),
        Ok(0x1000_0000)
    );
    // Aligned write (16-byte aligned) should succeed
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO.0 as u64, 4, 0x1010),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO.0 as u64, 4),
        Ok(0x1010)
    );

    // LAYOUT_QUEUE_DEVICE_LO: must be 4-byte aligned
    // Unaligned write (e.g. 2) should be ignored
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO.0 as u64, 4, 0x3002),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO.0 as u64, 4),
        Ok(0x3000_0000)
    );
    // Aligned write (4-byte aligned) should succeed
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO.0 as u64, 4, 0x3004),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO.0 as u64, 4),
        Ok(0x3004)
    );

    // LAYOUT_QUEUE_DRIVER_LO without RING_PACKED (split queue):
    // 2-byte aligned is allowed, unaligned 1-byte is rejected
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4, 0x2001),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4),
        Ok(0x2000_0000)
    );
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4, 0x2002),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4),
        Ok(0x2002)
    );

    // Enable RING_PACKED in driver feature
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT.0 as u64, 4, 1),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.write(
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE.0 as u64,
            4,
            (VirtioFeature::RING_PACKED.bits() >> 32) as u64
        ),
        Ok(Action::None)
    );

    // LAYOUT_QUEUE_DRIVER_LO with RING_PACKED:
    // 2-byte aligned (not 4-byte aligned) must now be rejected
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4, 0x4002),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4),
        Ok(0x2002)
    );
    // 4-byte aligned is accepted
    assert_matches!(
        mmio.write(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4, 0x4004),
        Ok(Action::None)
    );
    assert_matches!(
        mmio.read(VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO.0 as u64, 4),
        Ok(0x4004)
    );
}
