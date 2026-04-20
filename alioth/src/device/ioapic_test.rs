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

use assert_matches::assert_matches;

use crate::arch::x86_64::ioapic::{IOREGSEL, IOWIN, RedirectEntry};
use crate::hv::MsiSender;
use crate::hv::tests::TestMsiSender;
use crate::mem::emulated::Mmio;

use super::IoApic;

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

/// Configure redirection table entry for pin `pin` with `vector` and `dest`.
/// physical, edge triggered.
pub(crate) fn enable_pin<M: MsiSender>(io_apci: &IoApic<M>, pin: u8, vector: u8, dest: u8) {
    let mut redirtbl_entry = RedirectEntry(0);
    redirtbl_entry.set_vector(vector);
    redirtbl_entry.set_dest_id(dest);
    // IOREDTBL for pin 4 is at registers 0x10 + pin * 2
    let offset = 0x10 + (pin as u64 * 2);
    io_apci.write(IOREGSEL, 4, offset).unwrap();
    io_apci
        .write(IOWIN, 4, redirtbl_entry.0 & 0xffffffff)
        .unwrap();
    io_apci.write(IOREGSEL, 4, offset + 1).unwrap();
    io_apci.write(IOWIN, 4, redirtbl_entry.0 >> 32).unwrap();
}

#[test]
fn test_ioapic_service_pin() {
    let msi_sender = TestMsiSender::default();
    let messages = msi_sender.messages.clone();
    let io_apic = IoApic::new(msi_sender);

    enable_pin(&io_apic, 4, 0x24, 2);

    // Service pin 4
    io_apic.service_pin(4).unwrap();

    // Check that an MSI was sent
    let messages = messages.lock();
    // Expected addr: 0xfee00000 | (dest << 12) = 0xFEE02000
    // Expected data: (trigger_mode=0 << 15) | (delivery_mode=0 << 8) | vector=0x24 = 0x24
    assert_matches!(messages.as_slice(), [(0xfee02000, 0x24)]);
}
