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

use std::thread::sleep;
use std::time::{Duration, Instant};

use assert_matches::assert_matches;

use crate::arch::aarch64::layout::PL011_START;
use crate::device::console::tests::TestConsole;
use crate::device::pl011::{
    Flag, Interrupt, Pl011, UART_DR, UART_FR, UART_IMSC, UART_MIS, UART_PCELL_ID0, UART_PCELL_ID1,
    UART_PCELL_ID2, UART_PCELL_ID3, UART_PERIPH_ID0, UART_PERIPH_ID1, UART_PERIPH_ID2,
    UART_PERIPH_ID3, UART_RIS,
};
use crate::hv::tests::TestIrqSender;
use crate::mem::emulated::Mmio;

fn fixture_pl011() -> Pl011<TestIrqSender, TestConsole> {
    let irq_sender = TestIrqSender::new();
    let console = TestConsole::new().unwrap();
    Pl011::new(PL011_START, irq_sender, console).unwrap()
}

#[test]
fn test_pl011_basic() {
    let pl011 = fixture_pl011();

    assert_eq!(pl011.size(), 0x1000);

    assert_matches!(pl011.read(UART_PERIPH_ID0, 4), Ok(0x11));
    assert_matches!(pl011.read(UART_PERIPH_ID1, 4), Ok(0x10));
    assert_matches!(pl011.read(UART_PERIPH_ID2, 4), Ok(0x14));
    assert_matches!(pl011.read(UART_PERIPH_ID3, 4), Ok(0x00));

    assert_matches!(pl011.read(UART_PCELL_ID0, 4), Ok(0x0d));
    assert_matches!(pl011.read(UART_PCELL_ID1, 4), Ok(0xf0));
    assert_matches!(pl011.read(UART_PCELL_ID2, 4), Ok(0x05));
    assert_matches!(pl011.read(UART_PCELL_ID3, 4), Ok(0xb1));
}

#[test]
fn test_pl011_rx_interrupt_disabled() {
    let pl011 = fixture_pl011();

    assert_matches!(pl011.write(UART_FR, 4, 0), Ok(_)); // ignored
    assert_matches!(
        pl011.read(UART_FR, 4),
        Ok(f) if Flag(f as u16).contains(Flag::RXFE | Flag::TXFE)
    );

    // No data is available in the UART_DR register
    assert_matches!(pl011.read(UART_DR, 4), Ok(0x00));

    // Write data to the console without enabling interrupts
    assert_matches!(pl011.write(UART_IMSC, 4, 0), Ok(_));
    {
        pl011.console.inbound.lock().extend([97, 98, 99]);
        pl011.console.notifier.lock().notify().unwrap();
    }
    let now = Instant::now();
    while !matches!(pl011.read(UART_DR, 4), Ok(97)) && now.elapsed() < Duration::from_secs(5) {
        sleep(Duration::from_millis(500));
    }
    assert_matches!(pl011.read(UART_DR, 4), Ok(98));
    assert_matches!(
        pl011.read(UART_FR, 4),
        Ok(f) if !Flag(f as u16).contains(Flag::RXFE)
    );
    assert_matches!(
        pl011.read(UART_RIS, 4),
        Ok(s) if Interrupt(s as u16).contains(Interrupt::RXRIS)
    );
    assert_matches!(pl011.read(UART_MIS, 4), Ok(0));
    assert_matches!(pl011.read(UART_DR, 4), Ok(99));
    assert_matches!(
        pl011.read(UART_FR, 4),
        Ok(f) if Flag(f as u16).contains(Flag::RXFE)
    );
    assert_matches!(
        pl011.read(UART_RIS, 4),
        Ok(s) if !Interrupt(s as u16).contains(Interrupt::RXRIS)
    );
}

#[test]
fn test_pl011_rx_interrupt_enabled() {
    let pl011 = fixture_pl011();

    assert_matches!(
        pl011.write(UART_IMSC, 4, Interrupt::RXRIS.bits() as u64),
        Ok(_)
    );
    {
        pl011.console.inbound.lock().push_back(100);
        pl011.console.notifier.lock().notify().unwrap();
    }
    {
        let mut count = pl011.irq_line.count.lock();
        if *count == 0 {
            let time_out = Duration::from_secs(5);
            let wait = pl011.irq_line.condvar.wait_for(&mut count, time_out);
            assert!(!wait.timed_out());
        }
        assert_eq!(*count, 1); // one interrupt should have been raised
    }
    assert_matches!(
        pl011.read(UART_RIS, 4),
        Ok(s) if Interrupt(s as u16).contains(Interrupt::RXRIS)
    );
    assert_matches!(
        pl011.read(UART_MIS, 4),
        Ok(s) if Interrupt(s as u16).contains(Interrupt::RXRIS)
    );
    assert_matches!(
        pl011.read(UART_FR, 4),
        Ok(s) if !Flag(s as u16).contains(Flag::RXFE)
    );
    assert_matches!(pl011.read(UART_DR, 4), Ok(100));
    assert_matches!(
        pl011.read(UART_FR, 4),
        Ok(f) if Flag(f as u16).contains(Flag::RXFE)
    );
    assert_matches!(
        pl011.read(UART_RIS, 4),
        Ok(s) if !Interrupt(s as u16).contains(Interrupt::RXRIS)
    );
    assert_matches!(
        pl011.read(UART_MIS, 4),
        Ok(s) if !Interrupt(s as u16).contains(Interrupt::RXRIS)
    );
}

#[test]
fn test_pl011_tx() {
    let pl011 = fixture_pl011();

    assert_matches!(pl011.write(UART_DR, 4, 0x11), Ok(_));
    assert_matches!(pl011.console.outbound.lock().pop_back(), Some(0x11));
}
