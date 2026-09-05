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
use std::sync::atomic::Ordering;

use assert_matches::assert_matches;
use rstest::rstest;
use zerocopy::{FromBytes, IntoBytes};

use crate::hv::tests::TestMsiSender;
use crate::mem::MemRange;
use crate::mem::emulated::{Action, Mmio};
use crate::pci::cap::{
    MsiCapHdr, MsiMsgCtrl, MsixCap, MsixCapOffset, MsixMsgCtrl, PciCapHdr, PciCapId,
};
use crate::pci::config::{
    BAR_IO, BAR_MEM32, Command, CommonHeader, DeviceHeader, HeaderType, Status,
};
use crate::pci::{Pci, PciBar};
use crate::sys::vfio::{VfioDeviceInfoFlag, VfioPciIrq, VfioPciRegion, VfioRegionInfoFlag};
use crate::vfio::Error;
use crate::vfio::device::tests::MockVfioDevice;
use crate::vfio::pci::{PthBarRegion, VfioDev, VfioPciDev};

fn create_mock_pci_config_space() -> Vec<u8> {
    let mut config = vec![0u8; 4096];

    let header = DeviceHeader {
        common: CommonHeader {
            vendor: 0x8086,
            device: 0x1234,
            command: Command::empty(),
            status: Status::CAP,
            revision: 0x01,
            prog_if: 0,
            subclass: 0x00,
            class: 0x02, // Network controller
            cache_line_size: 0,
            latency_timer: 0,
            header_type: HeaderType::DEVICE,
            bist: 0,
        },
        bars: [0; 6],
        cardbus_cis_pointer: 0,
        subsystem_vendor: 0x8086,
        subsystem: 0x5678,
        expansion_rom: 0,
        capability_pointer: 0x40,
        reserved: [0; 7],
        intx_line: 0,
        intx_pin: 1,
        min_gnt: 0,
        max_lat: 0,
    };
    config[0..64].copy_from_slice(header.as_bytes());

    // MSI-X capability at offset 0x40
    let msix_cap = MsixCap {
        header: PciCapHdr {
            id: PciCapId::MSIX,
            next: 0,
        },
        control: MsixMsgCtrl::new(4),             // 4 entries
        table_offset: MsixCapOffset::new(0, 0),   // BAR 0, offset 0
        pba_offset: MsixCapOffset::new(0x800, 0), // BAR 0, offset 0x800
    };
    config[0x40..0x40 + std::mem::size_of::<MsixCap>()].copy_from_slice(msix_cap.as_bytes());

    config
}

#[test]
fn test_vfio_pci_dev_creation_and_config() {
    let mock = Arc::new(MockVfioDevice::default());
    let config_bytes = create_mock_pci_config_space();
    mock.add_config(config_bytes);
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x10000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0x1_0000,
    );

    let msi_sender = TestMsiSender::default();
    let dev = VfioPciDev::new(Arc::from("test-vfio-pci"), mock.clone(), msi_sender).unwrap();

    // Verify name
    assert_eq!(dev.name(), "test-vfio-pci");

    // Verify device reset was called
    assert_eq!(mock.resets.load(Ordering::SeqCst), 1);

    // Verify PCI config reads
    let config = dev.config();
    assert_matches!(config.read(0x00, 2), Ok(0x8086)); // Vendor ID
    assert_matches!(config.read(0x02, 2), Ok(0x1234)); // Device ID
    assert_matches!(config.read(0x08, 1), Ok(0x01)); // Revision
    assert_matches!(config.read(0x0a, 2), Ok(0x0200)); // Class / Subclass

    // Verify command register was initialized with INTX_DISABLE on backend
    let cmd_val = {
        let regions = mock.regions.read();
        let config_data = &regions[&VfioPciRegion::CONFIG.raw()].1;
        u16::from_le_bytes(config_data[4..6].try_into().unwrap())
    };
    let expected_cmd = Command::IO | Command::MEM | Command::BUS_MASTER | Command::INTX_DISABLE;
    assert_eq!(cmd_val, expected_cmd.bits());

    // Config space write and read (extra config area)
    assert_matches!(config.write(0x100, 4, 0xcafe_babe), Ok(Action::None));
    assert_matches!(config.read(0x100, 4), Ok(0xcafe_babe));

    // Reset via Pci trait
    assert_matches!(dev.reset(), Ok(()));
    assert_eq!(mock.resets.load(Ordering::SeqCst), 2);
}

#[test]
fn test_vfio_pci_dev_unsupported_header_type() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config_bytes = create_mock_pci_config_space();
    // Set header type to PCI-to-PCI bridge (0x01)
    config_bytes[0x0e] = 0x01;

    mock.add_config(config_bytes);

    let res = VfioPciDev::new(Arc::from("test-vfio"), mock, TestMsiSender::default());
    assert_matches!(res, Err(Error::NotSupportedHeader { ty: 1, .. }));
}

#[test]
fn test_vfio_pci_dev_msix_bar_and_irqfd() {
    let mock = Arc::new(MockVfioDevice::default());
    let config_bytes = create_mock_pci_config_space();
    mock.add_config(config_bytes);
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x10000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0x1_0000,
    );

    let msi_sender = TestMsiSender::default();
    let dev = VfioPciDev::new(Arc::from("test-vfio"), mock.clone(), msi_sender).unwrap();

    let PciBar::Mem(bar0) = &dev.config.header.bars[0] else {
        panic!("expected Mem BAR for BAR 0");
    };

    // BAR 0 should have Emulated range for MSI-X table & PBA (page 0) and Emulated/DevMem for remainder
    let MemRange::Emulated(msix_bar_mmio) = &bar0.ranges[0] else {
        panic!("expected Emulated range for MSI-X table in BAR 0");
    };

    // Test writing to MSI-X table: entry 0
    // addr_lo = 0xfee0_0000, addr_hi = 0, data = 0x20, control = 0 (unmasked)
    assert_matches!(msix_bar_mmio.write(0x00, 4, 0xfee0_0000), Ok(Action::None));
    assert_matches!(msix_bar_mmio.write(0x04, 4, 0), Ok(Action::None));
    assert_matches!(msix_bar_mmio.write(0x08, 4, 0x20), Ok(Action::None));
    // Unmasking triggers irqfd enablement
    assert_matches!(msix_bar_mmio.write(0x0c, 4, 0), Ok(Action::None));

    // Verify MSI-X eventfd was set on mock device
    let events = mock.irq_eventfds.lock().clone();
    assert!(!events.is_empty());
    assert_eq!(events.last().unwrap().0, VfioPciIrq::MSIX.raw());
    assert_eq!(events.last().unwrap().1, 0); // start = 0
    assert_eq!(events.last().unwrap().2.len(), 1); // 1 active entry

    // Test reading back from MSI-X table
    assert_matches!(msix_bar_mmio.read(0x00, 4), Ok(0xfee0_0000));
    assert_matches!(msix_bar_mmio.read(0x08, 4), Ok(0x20));

    // Test reading / writing PBA area (offset 0x800)
    assert_matches!(msix_bar_mmio.read(0x800, 4), Ok(0));
    assert_matches!(msix_bar_mmio.write(0x800, 4, 0), Ok(Action::None));

    // Test reading / writing emulated region outside table/PBA within page 0 (e.g. offset 0x900)
    assert_matches!(msix_bar_mmio.write(0x900, 4, 0x1122_3344), Ok(Action::None));
    assert_matches!(msix_bar_mmio.read(0x900, 4), Ok(0x1122_3344));

    // Test reset disables active MSI-X IRQs
    assert_matches!(dev.reset(), Ok(()));
    let disabled = mock.disabled_irqs.lock().clone();
    assert!(disabled.contains(&VfioPciIrq::MSIX.raw()));
}

#[test]
fn test_vfio_pci_dev_msi_only() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = vec![0u8; 4096];

    let header = DeviceHeader {
        common: CommonHeader {
            vendor: 0x10ec,
            device: 0x8168,
            status: Status::CAP,
            header_type: HeaderType::DEVICE,
            ..Default::default()
        },
        capability_pointer: 0x50,
        ..Default::default()
    };
    config[0..64].copy_from_slice(header.as_bytes());

    // MSI capability at offset 0x50 (Id: 0x05, next: 0)
    let mut msi_cap = MsiCapHdr {
        header: PciCapHdr {
            id: PciCapId::MSI,
            next: 0,
        },
        control: MsiMsgCtrl(0),
    };
    msi_cap.control.set_multi_msg_cap(2); // 4 messages
    config[0x50..0x50 + std::mem::size_of::<MsiCapHdr>()].copy_from_slice(msi_cap.as_bytes());

    mock.add_config(config);

    let msi_sender = TestMsiSender::default();
    let dev = VfioPciDev::new(Arc::from("test-msi"), mock.clone(), msi_sender).unwrap();

    // Verify MSI irq eventfds were registered
    let events = mock.irq_eventfds.lock().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, VfioPciIrq::MSI.raw());
    assert_eq!(events[0].2.len(), 4); // 4 messages

    // Verify MSI capability MMIO at offset 0x50
    let config = dev.config();
    assert_matches!(config.read(0x50, 1), Ok(val) if val == PciCapId::MSI.raw() as u64);
}

#[test]
fn test_vfio_pci_dev_both_msi_and_msix() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = vec![0u8; 4096];

    let header = DeviceHeader {
        common: CommonHeader {
            vendor: 0x1af4,
            device: 0x1000,
            status: Status::CAP,
            header_type: HeaderType::DEVICE,
            ..Default::default()
        },
        capability_pointer: 0x40,
        ..Default::default()
    };
    config[0..64].copy_from_slice(header.as_bytes());

    // MSI at 0x40 -> points to MSI-X at 0x60
    let msi_cap = MsiCapHdr {
        header: PciCapHdr {
            id: PciCapId::MSI,
            next: 0x60,
        },
        control: MsiMsgCtrl(0),
    };
    config[0x40..0x40 + std::mem::size_of::<MsiCapHdr>()].copy_from_slice(msi_cap.as_bytes());

    // MSI-X at 0x60 -> next 0
    let msix_cap = MsixCap {
        header: PciCapHdr {
            id: PciCapId::MSIX,
            next: 0,
        },
        control: MsixMsgCtrl::new(4),
        table_offset: MsixCapOffset::new(0, 0),
        pba_offset: MsixCapOffset::new(0x1000, 0),
    };
    config[0x60..0x60 + std::mem::size_of::<MsixCap>()].copy_from_slice(msix_cap.as_bytes());

    mock.add_config(config);
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x10000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0,
    );

    let dev = VfioPciDev::new(Arc::from("test-both"), mock, TestMsiSender::default()).unwrap();

    let config = dev.config();
    // MSI at 0x40 was masked with NullCap (id reads 0, next reads 0x60)
    assert_matches!(config.read(0x40, 1), Ok(0));
    assert_matches!(config.read(0x41, 1), Ok(0x60));
    // MSI-X at 0x60 is active
    assert_matches!(config.read(0x60, 1), Ok(val) if val == PciCapId::MSIX.raw() as u64);
}

#[test]
fn test_vfio_pci_dev_bar_types_and_splitting() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = create_mock_pci_config_space();

    // Set BAR 0 as Mem32, BAR 1 as IO BAR
    let (mut header, _) = DeviceHeader::read_from_prefix(&config).unwrap();
    header.bars[0] = BAR_MEM32;
    header.bars[1] = BAR_IO;
    config[0..64].copy_from_slice(header.as_bytes());

    mock.add_config(config);
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x10000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0,
    );
    mock.add_bar(
        VfioPciRegion::BAR1.raw(),
        0x100,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0,
    );

    let dev = VfioPciDev::new(Arc::from("test-bars"), mock, TestMsiSender::default()).unwrap();

    // BAR 0 should be PciBar::Mem with 2 ranges (page 0 emulated table/PBA, and remaining range)
    let PciBar::Mem(bar0) = &dev.config.header.bars[0] else {
        panic!("expected Mem BAR for BAR 0");
    };
    assert_eq!(bar0.ranges.len(), 2);

    // BAR 1 should be PciBar::Io
    assert_matches!(dev.config.header.bars[1], PciBar::Io(_));
}

#[test]
fn test_pth_bar_region_mmio() {
    let mock = Arc::new(MockVfioDevice::default());
    let region_info = mock.add_bar(
        0,
        0x1000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0x1000,
    );

    let vfio_dev = Arc::new(VfioDev {
        name: Arc::from("test-dev"),
        dev: mock.clone(),
        flags: VfioDeviceInfoFlag::empty(),
    });

    let pth = PthBarRegion {
        cdev: vfio_dev,
        size: 0x1000,
        offset: 0,
        region: Arc::new(region_info),
    };

    assert_eq!(pth.size(), 0x1000);
    assert_matches!(pth.write(0x10, 4, 0x1234_5678), Ok(Action::None));
    assert_matches!(pth.read(0x10, 4), Ok(0x1234_5678));
}

#[test]
fn test_vfio_pci_dev_mmap_bar() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = create_mock_pci_config_space();
    // Clear MSI-X capability so BAR 0 is not split
    let (mut header, _) = DeviceHeader::read_from_prefix(&config).unwrap();
    header.common.status = Status::empty();
    header.capability_pointer = 0;
    config[0..64].copy_from_slice(header.as_bytes());

    mock.add_config(config);

    // Create temp file for mmap
    let tmp_file = tempfile::tempfile().unwrap();
    tmp_file.set_len(0x10000).unwrap();
    mock.mmap_fds.write().insert(0, tmp_file.into());

    // BAR 0 with MMAP flag
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x10000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE | VfioRegionInfoFlag::MMAP,
        0,
    );

    let dev = VfioPciDev::new(Arc::from("test-mmap"), mock, TestMsiSender::default()).unwrap();
    assert_eq!(dev.config.header.bars.len(), 6);
    let PciBar::Mem(bar0) = &dev.config.header.bars[0] else {
        panic!("expected Mem BAR");
    };
    assert_matches!(bar0.ranges[0], MemRange::DevMem { .. });
}

#[test]
fn test_vfio_pci_dev_bar_mem64() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = create_mock_pci_config_space();

    let (mut header, _) = DeviceHeader::read_from_prefix(&config).unwrap();
    header.bars[0] = crate::pci::config::BAR_MEM64;
    header.bars[1] = 0;
    config[0..64].copy_from_slice(header.as_bytes());

    mock.add_config(config);
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x20000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0,
    );

    let dev = VfioPciDev::new(Arc::from("test-bar64"), mock, TestMsiSender::default()).unwrap();
    assert_matches!(dev.config.header.bars[0], PciBar::Mem(_));
    assert_matches!(dev.config.header.bars[1], PciBar::Empty);
}

#[rstest]
#[case(0x82)] // offset beyond config space
#[case(0x7f)] // insufficient config space
fn test_vfio_pci_cap_parsing_malformed(#[case] offset: u8) {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = create_mock_pci_config_space();
    config.resize(0x80, 0);

    let (mut header, _) = DeviceHeader::read_from_prefix(&config).unwrap();
    header.capability_pointer = offset;
    config[0..64].copy_from_slice(header.as_bytes());

    mock.add_config(config);

    // Should complete successfully without infinite loop or panic
    let dev = VfioPciDev::new(
        Arc::from("test-malformed-cap"),
        mock,
        TestMsiSender::default(),
    )
    .unwrap();
    assert_eq!(dev.name(), "test-malformed-cap");
}

#[test]
fn test_vfio_pci_disjoint_and_reversed_msix_bar() {
    let mock = Arc::new(MockVfioDevice::default());
    let mut config = create_mock_pci_config_space();

    // Table at 0x20000, PBA at 0x10000 on BAR 0 of size 0x40000
    let msix_cap = MsixCap {
        header: PciCapHdr {
            id: PciCapId::MSIX,
            next: 0,
        },
        control: MsixMsgCtrl::new(4),                 // 4 entries
        table_offset: MsixCapOffset::new(0x20000, 0), // BAR 0, offset 0x20000
        pba_offset: MsixCapOffset::new(0x10000, 0),   // BAR 0, offset 0x10000
    };
    config[0x40..0x40 + std::mem::size_of::<MsixCap>()].copy_from_slice(msix_cap.as_bytes());

    mock.add_config(config);
    mock.add_bar(
        VfioPciRegion::BAR0.raw(),
        0x40000,
        VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
        0,
    );

    let dev = VfioPciDev::new(
        Arc::from("test-disjoint-bar"),
        mock.clone(),
        TestMsiSender::default(),
    )
    .unwrap();
    let PciBar::Mem(bar0) = &dev.config.header.bars[0] else {
        panic!("expected Mem BAR");
    };

    // BAR 0 should be split: [PthBarRegion, Emulated(PBA), PthBarRegion, Emulated(Table), PthBarRegion]
    assert_eq!(bar0.ranges.len(), 5);

    let MemRange::Emulated(table_mmio) = &bar0.ranges[3] else {
        panic!("expected Emulated table mmio");
    };
    assert!(table_mmio.size() > 0);

    // 1. Write masked entry (control = 1) -> does not activate irqfd
    table_mmio.write(0x20000 - 0x20000, 4, 0xfee0_0000).unwrap(); // addr_lo
    table_mmio.write(0x20004 - 0x20000, 4, 0x0).unwrap(); // addr_hi
    table_mmio.write(0x20008 - 0x20000, 4, 0x40).unwrap(); // data
    table_mmio.write(0x2000c - 0x20000, 4, 0x1).unwrap(); // control (masked)
    assert!(mock.irq_eventfds.lock().is_empty());

    // 2. Unmask entry (control = 0) -> activates irqfd
    table_mmio.write(0x2000c - 0x20000, 4, 0x0).unwrap();
    assert_eq!(mock.irq_eventfds.lock().len(), 1);

    // 3. Write again while already IrqFd (control = 0)
    table_mmio.write(0x2000c - 0x20000, 4, 0x0).unwrap();
    assert_eq!(mock.irq_eventfds.lock().len(), 1);
}
