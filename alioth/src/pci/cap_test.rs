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

use assert_matches::assert_matches;
use parking_lot::RwLock;
use rstest::rstest;

use crate::hv::IrqFd;
use crate::hv::tests::TestIrqFd;
use crate::mem::emulated::{Action, Mmio};
use crate::pci::cap::{
    MsiCapMmio, MsiMsgCtrl, MsixCap, MsixCapMmio, MsixCapOffset, MsixMsgCtrl, MsixTableEntry,
    MsixTableMmio, MsixTableMmioEntry, MsixVectorCtrl, NullCap, PciCap, PciCapHdr, PciCapId,
    PciCapList,
};
use crate::pci::config::PciConfigArea;

#[rstest]
#[case(0x0, 1, 0x0)]
#[case(0x0, 2, 0x60_00)]
#[case(0x0, 4, 0x60_00)]
#[case(0x1, 1, 0x60)]
#[case(0x1, 2, 0x60)]
#[case(0x1, 2, 0x60)]
#[case(0x2, 1, 0x0)]
#[case(0x2, 2, 0x0)]
#[case(0xb, 1, 0x0)]
fn test_null_cap(#[case] offset: u64, #[case] size: u8, #[case] val: u64) {
    let null_cap = NullCap {
        next: 0x60,
        size: 0xc,
    };
    assert_matches!(null_cap.read(offset, size), Ok(v) if v == val);
}

#[rstest]
#[case(false, false, 12)]
#[case(true, false, 16)]
#[case(false, true, 20)]
#[case(true, true, 24)]
fn test_msi_msg_ctrl_cap_size(
    #[case] addr_64_cap: bool,
    #[case] per_vector_masking_cap: bool,
    #[case] expected_size: u8,
) {
    let mut ctrl = MsiMsgCtrl::default();
    ctrl.set_addr_64_cap(addr_64_cap);
    ctrl.set_per_vector_masking_cap(per_vector_masking_cap);
    assert_eq!(ctrl.cap_size(), expected_size);
}
#[test]
fn test_msi_cap_mmio_32() {
    let mut ctrl = MsiMsgCtrl::default();
    ctrl.set_multi_msg_cap(3);
    ctrl.set_addr_64_cap(false);
    ctrl.set_per_vector_masking_cap(false);
    ctrl.set_ext_msg_data_cap(false);
    let irqfds = (0..8).map(|_| TestIrqFd::default()).collect();
    let mut msi_cap = MsiCapMmio::new(ctrl, irqfds);

    msi_cap.set_next(0x80);
    assert_matches!(msi_cap.read(1, 1), Ok(0x80));

    assert_eq!(msi_cap.size(), 12);

    assert_matches!(msi_cap.write(0xc, 4, 0xaabb_ccdd), Ok(_));

    assert_matches!(msi_cap.write(0x4, 4, 0xc000_d000), Ok(_));
    assert_matches!(msi_cap.read(0x4, 4), Ok(0xc000_d000));

    let mut ctrl = MsiMsgCtrl(0);
    ctrl.set_enable(true);
    ctrl.set_multi_msg(5);
    ctrl.set_ext_msg_data(true);
    assert_matches!(msi_cap.write(0x2, 2, ctrl.0 as u64), Ok(_));
    assert_matches!(msi_cap.read(2, 2), Ok(v) => {
        let ctrl = MsiMsgCtrl(v as u16);
        assert_eq!(ctrl.enable(), true);
        assert_eq!(ctrl.multi_msg(), 3);
        assert_eq!(ctrl.ext_msg_data(), false);
    });

    assert_matches!(msi_cap.write(0x8, 4, 0xaa_cc00), Ok(_));
    assert_matches!(msi_cap.read(0x8, 4), Ok(0xcc00));

    for (index, irqfd) in msi_cap.irqfds.iter().enumerate() {
        assert_eq!(irqfd.get_addr_hi(), 0x0);
        assert_eq!(irqfd.get_addr_lo(), 0xc000_d000);
        assert_eq!(irqfd.get_data(), 0xcc00 + index as u32);
        assert_eq!(irqfd.get_masked(), false);
    }

    ctrl.set_enable(false);
    assert_matches!(msi_cap.write(0x2, 2, ctrl.0 as u64), Ok(_));
    for irqfd in &msi_cap.irqfds {
        assert!(irqfd.get_masked());
    }
}

#[test]
fn test_msi_cap_mmio_32_pvm() {
    let mut ctrl = MsiMsgCtrl::default();
    ctrl.set_multi_msg_cap(4);
    ctrl.set_addr_64_cap(false);
    ctrl.set_per_vector_masking_cap(true);
    ctrl.set_ext_msg_data_cap(true);
    let irqfds = (0..16).map(|_| TestIrqFd::default()).collect();
    let msi_cap = MsiCapMmio::new(ctrl, irqfds);

    assert_eq!(msi_cap.size(), 20);

    assert_matches!(msi_cap.write(0x4, 4, 0xc000_d000), Ok(_));
    assert_matches!(msi_cap.read(0x4, 4), Ok(0xc000_d000));

    let mut ctrl = MsiMsgCtrl(0);
    ctrl.set_enable(true);
    ctrl.set_multi_msg(3);
    ctrl.set_ext_msg_data(false);
    assert_matches!(msi_cap.write(0x0, 4, (ctrl.0 as u64) << 16), Ok(_));
    assert_matches!(msi_cap.read(2, 2), Ok(v) => {
        let ctrl = MsiMsgCtrl(v as u16);
        assert_eq!(ctrl.enable(), true);
        assert_eq!(ctrl.multi_msg(), 3);
        assert_eq!(ctrl.ext_msg_data(), false);
    });

    assert_matches!(msi_cap.write(0x8, 4, 0xaa_cc00), Ok(_));
    assert_matches!(msi_cap.read(0x8, 4), Ok(0xaa_cc00));

    assert_matches!(msi_cap.write(0xc, 4, 0b1), Ok(_));
    for (index, irqfd) in msi_cap.irqfds.iter().enumerate() {
        if index == 0 || index >= 8 {
            assert!(irqfd.get_masked());
            continue;
        }
        assert_eq!(irqfd.get_addr_hi(), 0x0);
        assert_eq!(irqfd.get_addr_lo(), 0xc000_d000);
        assert_eq!(irqfd.get_data(), 0xcc00 + index as u32);
        assert_eq!(irqfd.get_masked(), false);
    }
}

#[test]
fn test_msi_cap_mmio_64_pvm() {
    let mut ctrl = MsiMsgCtrl::default();
    ctrl.set_multi_msg_cap(4);
    ctrl.set_addr_64_cap(true);
    ctrl.set_per_vector_masking_cap(true);
    ctrl.set_ext_msg_data_cap(true);
    let irqfds = (0..16).map(|_| TestIrqFd::default()).collect();
    let msi_cap = MsiCapMmio::new(ctrl, irqfds);

    assert_eq!(msi_cap.size(), 24);

    assert_matches!(msi_cap.write(0x4, 4, 0xc000_d000), Ok(_));
    assert_matches!(msi_cap.write(0x8, 4, 0x1), Ok(_));

    let mut ctrl = MsiMsgCtrl(0);
    ctrl.set_enable(true);
    ctrl.set_multi_msg(3);
    ctrl.set_ext_msg_data(true);
    assert_matches!(msi_cap.write(0x2, 2, ctrl.0 as u64), Ok(_));
    assert_matches!(msi_cap.read(2, 2), Ok(v) => {
        let ctrl = MsiMsgCtrl(v as u16);
        assert_eq!(ctrl.enable(), true);
        assert_eq!(ctrl.multi_msg(), 3);
        assert_eq!(ctrl.ext_msg_data(), true);
    });

    assert_matches!(msi_cap.write(0xc, 4, 0xaa_cc00), Ok(_));
    assert_matches!(msi_cap.write(0x10, 4, 0b10), Ok(_));

    for (index, irqfd) in msi_cap.irqfds.iter().enumerate() {
        if index == 1 || index >= 8 {
            assert!(irqfd.get_masked());
            continue;
        }
        assert_eq!(irqfd.get_addr_hi(), 0x1);
        assert_eq!(irqfd.get_addr_lo(), 0xc000_d000);
        assert_eq!(irqfd.get_data(), 0xaa_cc00 + index as u32);
        assert_eq!(irqfd.get_masked(), false);
    }

    assert_matches!(msi_cap.reset(), Ok(_));
    assert_matches!(msi_cap.read(2, 2), Ok(v) if !MsiMsgCtrl(v as u16).enable());
    for irqfd in &msi_cap.irqfds {
        assert!(irqfd.get_masked());
    }
}

#[rstest]
#[case(1, 0x0)]
#[case(2, 0x1)]
fn test_msix_msg_ctrl(#[case] len: u16, #[case] val: u16) {
    let ctrl = MsixMsgCtrl::new(len);
    assert_eq!(ctrl.0, val);
}

#[test]
fn test_msix_cap_mmio() {
    let table_offset = MsixCapOffset::new(0x1000, 1);
    let pba_offset = MsixCapOffset::new(0x2000, 2);

    assert_eq!(table_offset.offset(), 0x1000);
    assert_eq!(table_offset.bar(), 1);
    assert_eq!(pba_offset.offset(), 0x2000);
    assert_eq!(pba_offset.bar(), 2);

    let mut msix = MsixCapMmio {
        cap: RwLock::new(MsixCap {
            header: PciCapHdr {
                id: PciCapId::MSIX,
                ..Default::default()
            },
            control: MsixMsgCtrl::new(2),
            table_offset,
            pba_offset,
        }),
    };
    msix.set_next(0x80);

    assert_eq!(msix.size(), 12);
    assert_matches!(msix.read(0, 1), Ok(0x11));
    assert_matches!(msix.read(1, 1), Ok(0x80));
    assert_matches!(msix.write(2, 2, 0b11 << 14), Ok(Action::None));
    assert_matches!(msix.read(2, 2), Ok(0b1100000000000001));
    assert_matches!(msix.read(4, 4), Ok(0x1001));
    assert_matches!(msix.read(8, 4), Ok(0x2002));

    // Unknown writes are ignored
    assert_matches!(msix.write(0, 1, 0), Ok(Action::None));
    assert_matches!(msix.write(2, 1, 0), Ok(Action::None));

    assert_matches!(msix.reset(), Ok(()));
    assert_matches!(msix.read(2, 2), Ok(0b1));
}

#[test]
fn test_msix_table_mmio() {
    let entries = Box::new([
        MsixTableMmioEntry::default(),
        MsixTableMmioEntry::IrqFd(TestIrqFd::default()),
    ]);
    let table = MsixTableMmio {
        entries: RwLock::new(entries),
    };
    assert_eq!(table.size(), 32);

    // MSI-X are masked by default
    assert_matches!(table.read(12, 4), Ok(0x1));
    assert_matches!(table.read(16 + 12, 4), Ok(0x1));

    // Unaligned access are ignored
    assert_matches!(table.read(0, 2), Ok(0x0));
    assert_matches!(table.write(0, 2, 0), Ok(Action::None));
    assert_matches!(table.read(12 + 2, 4), Ok(0x0));
    assert_matches!(table.write(16 + 2, 4, 0), Ok(Action::None));

    // Access out of bounds are ignored
    assert_matches!(table.read(32, 4), Ok(0x0));
    assert_matches!(table.write(32, 4, 0), Ok(Action::None));

    assert_matches!(table.write(0, 4, 0xff00_0000), Ok(Action::None));
    assert_matches!(table.write(4, 4, 0x01), Ok(Action::None));
    assert_matches!(table.write(8, 4, 0xabcd), Ok(Action::None));
    assert_matches!(table.write_val(12, 4, 0x0), Ok(true));

    assert_matches!(table.read(0, 4), Ok(0xff00_0000));
    assert_matches!(table.read(4, 4), Ok(0x01));
    assert_matches!(table.read(8, 4), Ok(0xabcd));
    assert_matches!(table.read(12, 4), Ok(0x0));

    assert_matches!(table.write(16 + 0, 4, 0xff00_0000), Ok(Action::None));
    assert_matches!(table.write(16 + 4, 4, 0x01), Ok(Action::None));
    assert_matches!(table.write(16 + 8, 4, 0xabcd), Ok(Action::None));
    assert_matches!(table.write_val(16 + 12, 4, 0x0), Ok(true));

    assert_matches!(table.read(16 + 0, 4), Ok(0xff00_0000));
    assert_matches!(table.read(16 + 4, 4), Ok(0x01));
    assert_matches!(table.read(16 + 8, 4), Ok(0xabcd));
    assert_matches!(table.read(16 + 12, 4), Ok(0x0));

    table.reset();
    assert_matches!(
        **table.entries.read(),
        [
            MsixTableMmioEntry::Entry(MsixTableEntry {
                addr_hi: 0,
                addr_lo: 0,
                data: 0,
                control: MsixVectorCtrl(1),
            }),
            MsixTableMmioEntry::Entry(MsixTableEntry {
                addr_hi: 0,
                addr_lo: 0,
                data: 0,
                control: MsixVectorCtrl(1),
            })
        ]
    );
}

#[test]
fn test_pci_cap_list() {
    let caps: Vec<Box<dyn PciCap>> = vec![
        Box::new(MsixCapMmio::new(MsixCap {
            header: PciCapHdr {
                id: PciCapId::MSIX,
                next: 0,
            },
            ..Default::default()
        })),
        Box::new(NullCap { size: 16, next: 0 }),
    ];

    let cap_list = PciCapList::try_from(caps).unwrap();

    assert_eq!(cap_list.is_empty(), false);

    assert_eq!(cap_list.size(), 4096);
    assert_matches!(cap_list.read(0x40, 1), Ok(0x11));
    assert_matches!(cap_list.read(0x41, 1), Ok(0x4c));
    assert_matches!(cap_list.write(0x42, 2, 0xc001), Ok(Action::None));
    assert_matches!(cap_list.read(0x42, 2), Ok(0xc000));

    assert_matches!(cap_list.read(0x4c, 1), Ok(0x0));
    assert_matches!(cap_list.read(0x4d, 1), Ok(0x0));

    assert_matches!(cap_list.reset(), Ok(()));
    assert_matches!(cap_list.read(0x42, 2), Ok(0));
}

#[test]
fn test_pci_cap_list_default() {
    let cap_list = PciCapList::default();
    assert!(cap_list.is_empty());
}
