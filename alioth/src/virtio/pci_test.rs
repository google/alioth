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
use std::sync::atomic::{AtomicU16, AtomicU64};

use assert_matches::assert_matches;
use parking_lot::RwLock;

use crate::hv::tests::TestMsiSender;
use crate::mem::emulated::{Action, Mmio};
use crate::pci::cap::MsixTableMmio;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::Register;
use crate::virtio::pci::{
    PciIrqSender, VirtioCommonCfg, VirtioPciMsixVector, VirtioPciRegisterMmio,
};
use crate::virtio::queue::QueueReg;
use crate::virtio::tests::FakeIoeventFd;

#[test]
fn test_virtio_pci_queue_registers() {
    let queues = Arc::new([QueueReg {
        desc: AtomicU64::new(0x1122_3344_5566_7788),
        driver: AtomicU64::new(0xaabb_ccdd_eeff_0011),
        device: AtomicU64::new(0x0123_4567_89ab_cdef),
        ..Default::default()
    }]);
    let (event_tx, _event_rx) = flume::unbounded();
    let notifier = Arc::new(Notifier::new().unwrap());
    let msi_sender = TestMsiSender::default();
    let msix_table = Arc::new(MsixTableMmio {
        entries: RwLock::new(vec![].into_boxed_slice()),
    });
    let irq_sender = Arc::new(PciIrqSender {
        msix_vector: VirtioPciMsixVector {
            config: AtomicU16::new(0xffff),
            queues: vec![AtomicU16::new(0xffff)],
        },
        msix_table,
        msi_sender,
    });
    let mmio = VirtioPciRegisterMmio::<_, FakeIoeventFd> {
        name: "test-virtio-pci".into(),
        reg: Register::default(),
        queues,
        irq_sender,
        ioeventfds: None,
        event_tx,
        notifier,
    };

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
}
