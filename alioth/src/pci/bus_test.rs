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

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use assert_matches::assert_matches;

use crate::device::pvpanic::{PVPANIC_DEVICE_ID, PVPANIC_VENDOR_ID, PvPanic};
use crate::mem::emulated::{Action, Mmio};
use crate::pci::bus::{Address, PciBus, PciIoBus};
use crate::pci::config::{BAR_MEM64, BAR_PREFETCHABLE, CommonHeader, offset_bar};
use crate::pci::segment::PciSegment;
use crate::pci::{Bdf, PciDevice};

#[test]
fn test_pci_bus() {
    let pci_bus = PciBus::default();

    assert_eq!(
        pci_bus.reserve(Some(Bdf::new(0, 1, 0))),
        Some(Bdf::new(0, 1, 0))
    );
    let test_dev = PciDevice {
        name: "test".into(),
        dev: Arc::new(PvPanic::new()),
    };
    assert_matches!(pci_bus.add(Bdf::new(0, 1, 0), test_dev), None);
}

#[test]
fn test_pci_io_bus() {
    let test_dev = PciDevice {
        name: "test".into(),
        dev: Arc::new(PvPanic::new()),
    };

    let segment = PciSegment::new();
    assert_matches!(segment.add(Bdf::new(0, 1, 0), test_dev), None);

    let io_bus = PciIoBus {
        address: AtomicU32::new(0),
        segment: Arc::new(segment),
    };
    assert_eq!(io_bus.size(), 8);

    let reg_addr = Address::new(true, 0, 1, 0, CommonHeader::OFFSET_VENDOR as u8);
    assert_matches!(io_bus.write(0, 4, reg_addr.0 as u64), Ok(Action::None));
    assert_eq!(io_bus.read(0, 4).unwrap(), reg_addr.0 as u64);

    assert_eq!(io_bus.read(4, 2).unwrap(), PVPANIC_VENDOR_ID as u64);
    assert_eq!(io_bus.read(6, 2).unwrap(), PVPANIC_DEVICE_ID as u64);

    let reg_addr = Address::new(true, 0, 1, 0, offset_bar(0) as u8);
    assert_matches!(io_bus.write(0, 4, reg_addr.0 as u64), Ok(Action::None));
    assert_matches!(io_bus.write(4, 4, 0xec00_0000), Ok(Action::None));
    assert_eq!(
        io_bus.read(4, 4).unwrap(),
        (0xec00_0000 | BAR_MEM64 | BAR_PREFETCHABLE) as u64
    );

    assert_matches!(io_bus.read(8, 1), Ok(0));
    assert_matches!(io_bus.write(8, 1, 1), Ok(Action::None));
}

#[test]
fn test_pci_io_bus_unaligned_address_access() {
    let io_bus = PciIoBus {
        address: AtomicU32::new(0),
        segment: Arc::new(PciSegment::new()),
    };

    let reg_addr = Address::new(true, 0, 1, 0, offset_bar(0) as u8);
    assert_matches!(io_bus.write(0, 4, reg_addr.0 as u64), Ok(Action::None));

    assert_matches!(io_bus.write(0, 2, 0x12345678), Ok(Action::None));
    assert_matches!(io_bus.read(0, 2), Ok(0));

    assert_eq!(io_bus.read(0, 4).unwrap(), reg_addr.0 as u64);
}

#[test]
fn test_pci_io_bus_disabled_address() {
    let test_dev = PciDevice {
        name: "test".into(),
        dev: Arc::new(PvPanic::new()),
    };

    let segment = PciSegment::new();
    assert_matches!(segment.add(Bdf::new(0, 1, 0), test_dev), None);

    let io_bus = PciIoBus {
        address: AtomicU32::new(0),
        segment: Arc::new(segment),
    };

    let reg_addr = Address::new(false, 0, 1, 0, offset_bar(0) as u8);

    assert_matches!(io_bus.write(0, 4, reg_addr.0 as u64), Ok(Action::None));
    assert_matches!(io_bus.read(4, 4), Ok(0));
    assert_matches!(io_bus.write(4, 4, 0), Ok(Action::None));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_host_bridge() {
    let bus = PciBus::new();

    let offset = CommonHeader::OFFSET_CLASS;
    let reg_addr = Address::new(true, 0, 0, 0, offset as u8);
    assert_matches!(bus.io_bus.write(0, 4, reg_addr.0 as u64), Ok(Action::None));
    assert_matches!(bus.io_bus.read(4 + (offset as u64 & 0b11), 1), Ok(0x06));
}
