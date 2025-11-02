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

use crate::hv::IrqFd;
use crate::hv::tests::TestIrqFd;
use crate::mem::emulated::Mmio;
use crate::pci::cap::{MsiCapHdr, MsiMsgCtrl};
use crate::pci::config::PciConfigArea;
use crate::vfio::pci::MsiCapMmio;

#[test]
fn test_msi_cap_mmio_32() {
    let mut hdr = MsiCapHdr::default();
    hdr.control.set_multi_msg_cap(3);
    hdr.control.set_addr_64_cap(false);
    hdr.control.set_per_vector_masking_cap(false);
    hdr.control.set_ext_msg_data_cap(false);
    let irqfds = (0..8).map(|_| TestIrqFd::default()).collect();
    let msi_cap = MsiCapMmio::new("test".into(), hdr, irqfds);

    assert_eq!(msi_cap.size(), 12);

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
    assert_matches!(msi_cap.read(0x8, 4), Ok(0xaa_cc00));

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
    let mut hdr = MsiCapHdr::default();
    hdr.control.set_multi_msg_cap(4);
    hdr.control.set_addr_64_cap(false);
    hdr.control.set_per_vector_masking_cap(true);
    hdr.control.set_ext_msg_data_cap(true);
    let irqfds = (0..16).map(|_| TestIrqFd::default()).collect();
    let msi_cap = MsiCapMmio::new("test".into(), hdr, irqfds);

    assert_eq!(msi_cap.size(), 20);

    assert_matches!(msi_cap.write(0x4, 4, 0xc000_d000), Ok(_));
    assert_matches!(msi_cap.read(0x4, 4), Ok(0xc000_d000));

    let mut ctrl = MsiMsgCtrl(0);
    ctrl.set_enable(true);
    ctrl.set_multi_msg(3);
    ctrl.set_ext_msg_data(false);
    assert_matches!(msi_cap.write(0x2, 2, ctrl.0 as u64), Ok(_));
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
    let mut hdr = MsiCapHdr::default();
    hdr.control.set_multi_msg_cap(4);
    hdr.control.set_addr_64_cap(true);
    hdr.control.set_per_vector_masking_cap(true);
    hdr.control.set_ext_msg_data_cap(true);
    let irqfds = (0..16).map(|_| TestIrqFd::default()).collect();
    let msi_cap = MsiCapMmio::new("test".into(), hdr, irqfds);

    assert_eq!(msi_cap.size(), 24);

    assert_matches!(msi_cap.write(0x4, 4, 0xc000_d000), Ok(_));

    assert_matches!(msi_cap.write(0x8, 4, 0x1), Ok(_));
    assert_matches!(msi_cap.write(0xc, 4, 0xcc00), Ok(_));

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

    assert_matches!(msi_cap.write(0x10, 4, 0b1), Ok(_));
    for (index, irqfd) in msi_cap.irqfds.iter().enumerate() {
        if index == 0 || index >= 8 {
            assert!(irqfd.get_masked());
            continue;
        }
        assert_eq!(irqfd.get_addr_hi(), 0x1);
        assert_eq!(irqfd.get_addr_lo(), 0xc000_d000);
        assert_eq!(irqfd.get_data(), 0xcc00 + index as u32);
        assert_eq!(irqfd.get_masked(), false);
    }

    msi_cap.reset();
    assert_matches!(msi_cap.read(2, 2), Ok(v) if !MsiMsgCtrl(v as u16).enable());
    for irqfd in &msi_cap.irqfds {
        assert!(irqfd.get_masked());
    }
}
