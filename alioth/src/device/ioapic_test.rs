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

use assert_matches::assert_matches;
use parking_lot::Mutex;

use crate::hv::tests::TestIrqFd;
use crate::hv::{Error as HvError, MsiSender};
use crate::mem::emulated::Mmio;

use super::{IOREGSEL, IOWIN, IoApic};

#[derive(Debug, Default)]
struct TestMsiSender {
    messages: Arc<Mutex<Vec<(u64, u32)>>>,
}

impl MsiSender for TestMsiSender {
    type IrqFd = TestIrqFd;

    fn send(&self, addr: u64, data: u32) -> Result<(), HvError> {
        self.messages.lock().push((addr, data));
        Ok(())
    }

    fn create_irqfd(&self) -> Result<Self::IrqFd, HvError> {
        Ok(TestIrqFd::default())
    }
}

#[test]
fn test_ioapic_read_write() {
    let io_apic = IoApic::new(TestMsiSender::default());

    // Write to select register
    io_apic.write(IOREGSEL, 4, 0x10).unwrap();
    assert_eq!(io_apic.read(IOREGSEL, 4).unwrap(), 0x10);

    // Write to window register
    io_apic.write(IOWIN, 4, 0x12345678).unwrap();

    // Read back from window register
    assert_eq!(io_apic.read(IOWIN, 4).unwrap(), 0x12345678);

    // Select upper part of redirection table entry
    io_apic.write(IOREGSEL, 4, 0x11).unwrap();

    // Write to window register
    io_apic.write(IOWIN, 4, 0xabcdef00).unwrap();

    // Read back from window register
    assert_eq!(io_apic.read(IOWIN, 4).unwrap(), 0xabcdef00);

    // Check redirection table entry
    let regs = io_apic.regs.lock();
    assert_eq!(regs.redirtbl[0].0, 0xabcdef0012345678);
}

#[test]
fn test_ioapic_service_pin() {
    let msi_sender = TestMsiSender::default();
    let messages = msi_sender.messages.clone();
    let io_apic = IoApic::new(msi_sender);

    // Configure redirection table entry for pin 4
    // Vector 0x24, destination 2, physical, edge triggered
    let redirtbl_entry = (2u64 << 56) | 0x24;

    // IOREDTBL for pin 4 is at registers 0x10 + 4*2 = 0x18 and 0x19
    io_apic.write(IOREGSEL, 4, 0x18).unwrap();
    io_apic
        .write(IOWIN, 4, (redirtbl_entry & 0xFFFFFFFF) as u64)
        .unwrap();
    io_apic.write(IOREGSEL, 4, 0x19).unwrap();
    io_apic
        .write(IOWIN, 4, (redirtbl_entry >> 32) as u64)
        .unwrap();

    // Service pin 4
    io_apic.service_pin(4).unwrap();

    // Check that an MSI was sent
    let messages = messages.lock();
    // Expected addr: 0xfee00000 | (dest << 12) = 0xFEE02000
    // Expected data: (trigger_mode=0 << 15) | (delivery_mode=0 << 8) | vector=0x24 = 0x24
    assert_matches!(messages.as_slice(), [(0xfee02000, 0x24)]);
}
