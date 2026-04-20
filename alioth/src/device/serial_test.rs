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
use std::thread::sleep;
use std::time::{Duration, Instant};

use assert_matches::assert_matches;
use parking_lot::Mutex;

use crate::device::console::tests::TestConsole;
use crate::device::ioapic::IoApic;
use crate::device::ioapic::tests::enable_pin;
use crate::device::serial::{
    DIVISOR_LATCH_LSB, DIVISOR_LATCH_MSB, FIFO_CONTROL_REGISTER, INTERRUPT_ENABLE_REGISTER,
    INTERRUPT_IDENTIFICATION_REGISTER, LINE_CONTROL_REGISTER, LINE_STATUS_REGISTER,
    MODEM_CONTROL_REGISTER, MODEM_STATUS_REGISTER, RX_BUFFER_REGISTER, SCRATCH_REGISTER, Serial,
    TX_HOLDING_REGISTER,
};
use crate::hv::tests::TestMsiSender;
use crate::mem::emulated::Mmio;

#[allow(clippy::type_complexity)]
fn fixture_serial() -> (
    Serial<TestMsiSender, TestConsole>,
    Arc<IoApic<TestMsiSender>>,
    Arc<Mutex<Vec<(u64, u32)>>>,
) {
    let msi_sender = TestMsiSender::default();
    let messages = msi_sender.messages.clone();
    let ioapic = Arc::new(IoApic::new(msi_sender));
    let console = TestConsole::new().unwrap();
    let serial = Serial::new(0x3f8, ioapic.clone(), 4, console).unwrap();
    (serial, ioapic, messages)
}

#[test]
fn test_serial_basic() {
    let (serial, _, _) = fixture_serial();

    assert_eq!(serial.size(), 8);

    // Default LCR should be 0b00000011 (8 data bits)
    assert_matches!(serial.read(LINE_CONTROL_REGISTER, 1), Ok(0x03));

    // Write LCR to enable DLAB (Divisor Latch Access Bit)
    assert_matches!(serial.write(LINE_CONTROL_REGISTER, 1, 0x83), Ok(_));
    assert_matches!(serial.read(LINE_CONTROL_REGISTER, 1), Ok(0x83));

    // Write divisor latches
    assert_matches!(serial.write(DIVISOR_LATCH_LSB, 1, 0x12), Ok(_));
    assert_matches!(serial.write(DIVISOR_LATCH_MSB, 1, 0x34), Ok(_));

    // Read divisor latches
    assert_matches!(serial.read(DIVISOR_LATCH_LSB, 1), Ok(0x12));
    assert_matches!(serial.read(DIVISOR_LATCH_MSB, 1), Ok(0x34));

    // Disable DLAB
    assert_matches!(serial.write(LINE_CONTROL_REGISTER, 1, 0x03), Ok(_));

    // Scratch register
    assert_matches!(serial.write(SCRATCH_REGISTER, 1, 0x5a), Ok(_));
    assert_matches!(serial.read(SCRATCH_REGISTER, 1), Ok(0x5a));

    // Default IIR
    assert_matches!(serial.read(INTERRUPT_IDENTIFICATION_REGISTER, 1), Ok(0x01));

    // Modem Control Register
    assert_matches!(serial.write(MODEM_CONTROL_REGISTER, 1, 0x1f), Ok(_));
    assert_matches!(serial.read(MODEM_CONTROL_REGISTER, 1), Ok(0x1f));

    // Modem Status Register (read-only in real hardware, but we just check it returns 0 as it's uninitialized default)
    assert_matches!(serial.read(MODEM_STATUS_REGISTER, 1), Ok(0x00));
    // Writing should be a no-op but shouldn't panic
    assert_matches!(serial.write(MODEM_STATUS_REGISTER, 1, 0xff), Ok(_));

    // FIFO Control Register (write-only)
    assert_matches!(serial.write(FIFO_CONTROL_REGISTER, 1, 0xc7), Ok(_));

    // Unreachable offsets
    assert_matches!(serial.read(0x100, 1), Ok(0x00));
    assert_matches!(serial.write(0x100, 1, 0x00), Ok(_));
}

#[test]
fn test_serial_tx() {
    let (serial, ioapic, messages) = fixture_serial();

    // Enable TX empty interrupt
    assert_matches!(serial.write(INTERRUPT_ENABLE_REGISTER, 1, 0x02), Ok(_));

    enable_pin(&ioapic, 4, 0x24, 2);

    // Write a character
    assert_matches!(serial.write(TX_HOLDING_REGISTER, 1, b'A' as u64), Ok(_));

    // Check if character is pushed to outbound console
    let mut outbound = serial.console.outbound.lock();
    assert_eq!(outbound.pop_front(), Some(b'A'));
    drop(outbound);

    // TX should send an IRQ through IOAPIC
    let messages_lock = messages.lock();
    assert_matches!(messages_lock.as_slice(), [(0xfee02000, 0x24)]);
}

#[test]
fn test_serial_rx() {
    let (serial, ioapic, messages) = fixture_serial();

    // Enable RX available interrupt
    assert_matches!(serial.write(INTERRUPT_ENABLE_REGISTER, 1, 0x01), Ok(_));
    assert_matches!(serial.read(INTERRUPT_ENABLE_REGISTER, 4), Ok(0x01));

    enable_pin(&ioapic, 4, 0x24, 2);

    {
        serial.console.inbound.lock().push_back(b'B');
        serial.console.notifier.lock().notify().unwrap();
    }

    let now = Instant::now();
    while !matches!(serial.read(LINE_STATUS_REGISTER, 1), Ok(s) if s & 1 == 1)
        && now.elapsed() < Duration::from_secs(5)
    {
        sleep(Duration::from_millis(100));
    }

    // Check if data is available
    assert_matches!(
        serial.read(LINE_STATUS_REGISTER, 1),
        Ok(s) if s & 1 == 1
    );

    // Check IIR for RX data available
    assert_matches!(serial.read(INTERRUPT_IDENTIFICATION_REGISTER, 1), Ok(0x04));

    // Read the character
    assert_matches!(
        serial.read(RX_BUFFER_REGISTER, 1),
        Ok(b) if b == b'B' as u64
    );

    // RX should send an IRQ through IOAPIC
    let messages_lock = messages.lock();
    assert_eq!(messages_lock.len(), 1);
    assert_matches!(messages_lock.as_slice(), [(0xfee02000, 0x24)]);

    // IIR should be cleared after read
    assert_matches!(serial.read(INTERRUPT_IDENTIFICATION_REGISTER, 1), Ok(0x01));
}

#[test]
fn test_serial_rx_no_interrupt() {
    let (serial, _ioapic, messages) = fixture_serial();

    // Disable all interrupts
    assert_matches!(serial.write(INTERRUPT_ENABLE_REGISTER, 1, 0x00), Ok(_));

    {
        serial.console.inbound.lock().push_back(b'B');
        serial.console.notifier.lock().notify().unwrap();
    }

    let now = Instant::now();
    while !matches!(serial.read(LINE_STATUS_REGISTER, 1), Ok(s) if s & 1 == 1)
        && now.elapsed() < Duration::from_secs(5)
    {
        sleep(Duration::from_millis(100));
    }

    // Check if data is available
    assert_matches!(
        serial.read(LINE_STATUS_REGISTER, 1),
        Ok(s) if s & 1 == 1
    );

    // Read the character
    assert_matches!(
        serial.read(RX_BUFFER_REGISTER, 1),
        Ok(b) if b == b'B' as u64
    );

    // No IRQ should have been sent
    let messages_lock = messages.lock();
    assert_eq!(messages_lock.len(), 0);
}

#[test]
fn test_serial_loopback() {
    let (serial, ioapic, messages) = fixture_serial();

    // Enable RX available interrupt
    assert_matches!(serial.write(INTERRUPT_ENABLE_REGISTER, 1, 0x01), Ok(_));

    enable_pin(&ioapic, 4, 0x24, 2);

    // Enable loopback mode (bit 4)
    assert_matches!(serial.write(MODEM_CONTROL_REGISTER, 1, 0x10), Ok(_));

    // Write a character
    assert_matches!(serial.write(TX_HOLDING_REGISTER, 1, b'C' as u64), Ok(_));

    // The character should be looped back into RX
    assert_matches!(
        serial.read(LINE_STATUS_REGISTER, 1),
        Ok(s) if s & 1 == 1
    );
    assert_matches!(
        serial.read(RX_BUFFER_REGISTER, 1),
        Ok(b) if b == b'C' as u64
    );

    let messages_lock = messages.lock();
    assert_matches!(messages_lock.as_slice(), [(0xfee02000, 0x24)]);
}

#[test]
fn test_serial_pause_resume() {
    use crate::device::Pause;
    let (serial, _, _) = fixture_serial();
    assert_matches!(serial.pause(), Ok(()));
    assert_matches!(serial.resume(), Ok(()));
}
