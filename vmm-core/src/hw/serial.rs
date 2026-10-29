// Copyright 2024 Google LLC
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

use std::collections::VecDeque;
use std::fmt::{self, Debug, Formatter};
use std::io;
use std::sync::Arc;

use bitfield::bitfield;
use bitflags::bitflags;

use crate::host::abi::{CORE_MSG_SERIAL_TX, CoreToIoEntry};
use crate::host::{VmmCoreBridge, VmmHostCore};
use crate::hw::ioapic::IoApic;
use crate::mem;
use crate::mem::mmio::Mmio;
use crate::sync::Mutex;

const TX_HOLDING_REGISTER: u16 = 0x0;
const RX_BUFFER_REGISTER: u16 = 0x0;
const DIVISOR_LATCH_LSB: u16 = 0x0;
const DIVISOR_LATCH_MSB: u16 = 0x1;
const INTERRUPT_ENABLE_REGISTER: u16 = 0x1;
const FIFO_CONTROL_REGISTER: u16 = 0x2;
const INTERRUPT_IDENTIFICATION_REGISTER: u16 = 0x2;
const LINE_CONTROL_REGISTER: u16 = 0x3;
const MODEM_CONTROL_REGISTER: u16 = 0x4;
const LINE_STATUS_REGISTER: u16 = 0x5;
const MODEM_STATUS_REGISTER: u16 = 0x6;
const SCRATCH_REGISTER: u16 = 0x7;

// offset 0x1, Interrupt Enable Register (IER)
bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InterruptEnable: u8 {
        const MODEM_STATUS = 1 << 3;
        const RECEIVER_LINE_STATUS = 1 << 2;
        const TX_HOLDING_REGISTER_EMPTY = 1 << 1;
        const RECEIVED_DATA_AVAILABLE = 1 << 0;
    }
}

// offset 0x2, write, FIFO Control Register (FCR)
bitfield! {
    #[derive(Copy, Clone, Default)]
    pub struct FifoControl(u8);
    impl Debug;
    rx_trigger_size_bits, _: 7, 6;
    dma_mode, _: 3;
    tx_reset, _: 2;
    rx_reset, _: 1;
    fifo_enabled, _: 0;
}

impl FifoControl {
    pub fn rx_trigger_size(&self) -> usize {
        match self.rx_trigger_size_bits() {
            0b00 => 1,
            0b01 => 4,
            0b10 => 8,
            0b11 => 14,
            _ => unreachable!(),
        }
    }
}

// offset 0x2, read, Interrupt Identification Register
bitfield! {
    #[derive(Copy, Clone)]
    pub struct InterruptIdentification(u8);
    impl Debug;
    fifo_enabled, _: 7, 6;
    interrupt_id, set_interrupt_id: 3,1;
    no_pending, set_no_pending: 0; // Interrupt Pending Bit
}

impl InterruptIdentification {
    pub fn set_fifo_enabled(&mut self) {
        self.0 |= 0b11 << 6;
    }

    pub fn clear_fifi_enabled(&mut self) {
        self.0 &= !(0b11 << 6);
    }

    pub fn set_rx_data_available(&mut self) {
        self.0 = (self.0 & !0b1111) | 0b0100;
    }

    pub fn set_tx_room_empty(&mut self) {
        self.0 = (self.0 & !0b1111) | 0b0010;
    }

    pub fn clear_interrupt(&mut self) {
        self.0 = (self.0 & !0b1111) | 1;
    }
}

impl Default for InterruptIdentification {
    fn default() -> Self {
        let mut val = InterruptIdentification(0);
        val.clear_interrupt();
        val
    }
}

// offset 0x3, Line Control Register (LCR)
bitfield! {
    #[derive(Copy, Clone)]
    pub struct LineControl(u8);
    impl Debug;
    divisor_latch_access, _: 7;
    break_, _: 6;
    stick_parity, _: 5;
    even_parity, _: 4;
    parity_enabled, _: 3;
    step_bits, _: 2;
    word_length, _: 1, 0;
}

impl Default for LineControl {
    fn default() -> Self {
        LineControl(0b00000011) // 8 data bits as default
    }
}

// offset 0x4, Modem Control Register
bitfield! {
    #[derive(Copy, Clone, Default)]
    pub struct ModemControl(u8);
    impl Debug;
    loop_back, _: 4;
    out_2, _: 3;
    out_1, _: 2;
    request_to_send, _: 1;
    data_terminal_ready, _: 0; // Data Terminal Ready
}

// offset 0x5, Line Status Register (LSR)
bitflags! {
    #[derive(Debug)]
    pub struct LineStatus: u8 {
        const ERROR_IN_RX_FIFO = 1 << 7;
        const TX_EMPTY = 1 << 6;
        const TX_HOLDING_REGISTER_EMPTY = 1 << 5;
        const BREAK_INTERRUPT = 1 << 4;
        const FRAMING_ERROR = 1 << 3;
        const PARITY_ERROR = 1 << 2;
        const OVERRUN_ERROR = 1 << 1;
        const DATA_READY = 1 << 0;
    }
}

impl Default for LineStatus {
    fn default() -> Self {
        LineStatus::TX_EMPTY | LineStatus::TX_HOLDING_REGISTER_EMPTY
    }
}

#[derive(Default, Debug)]
struct SerialReg {
    interrupt_enable: InterruptEnable, // 0x1, Interrupt Enable Register (IER)
    #[allow(dead_code)]
    fifo_control: FifoControl, // 0x2, write, FIFO Control Register (FCR)
    interrupt_identification: InterruptIdentification, // 0x2, read, Interrupt Identification Register
    line_control: LineControl,                         // 0x3, Line Control Register (LCR)
    modem_control: ModemControl,                       // 0x4, Modem Control Register (MCR)
    line_status: LineStatus,
    modem_status: u8, // 0x6, Modem Status Register (MSR)
    scratch: u8,      // 0x7, Scratch Register (SCR)
    divisor: u16,
    data: VecDeque<u8>,
}

pub struct Serial {
    base_port: u16,
    gsi: u32,
    hv: Arc<dyn VmmHostCore>,
    ioapic: Option<Arc<IoApic>>,
    bridge: Arc<dyn VmmCoreBridge>,
    reg: Arc<Mutex<SerialReg>>,
}

impl Debug for Serial {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Serial")
            .field("base_port", &self.base_port)
            .field("gsi", &self.gsi)
            .field("reg", &self.reg)
            .finish()
    }
}

impl Mmio for Serial {
    fn size(&self) -> usize {
        8
    }

    fn read(&self, offset: usize, _size: u8) -> Result<u64, mem::Error> {
        let mut reg = self.reg.lock();
        let ret = match offset as u16 {
            DIVISOR_LATCH_LSB if reg.line_control.divisor_latch_access() => reg.divisor as u8,
            DIVISOR_LATCH_MSB if reg.line_control.divisor_latch_access() => {
                (reg.divisor >> 8) as u8
            }
            RX_BUFFER_REGISTER => {
                if reg.data.len() <= 1 {
                    reg.line_status &= !LineStatus::DATA_READY;
                }
                reg.data.pop_front().unwrap_or(0xff)
            }
            INTERRUPT_ENABLE_REGISTER => reg.interrupt_enable.bits(),
            INTERRUPT_IDENTIFICATION_REGISTER => {
                let ret = reg.interrupt_identification.0;
                reg.interrupt_identification.clear_interrupt();
                ret
            }
            LINE_CONTROL_REGISTER => reg.line_control.0,
            MODEM_CONTROL_REGISTER => reg.modem_control.0,
            LINE_STATUS_REGISTER => reg.line_status.bits(),
            MODEM_STATUS_REGISTER => reg.modem_status,
            SCRATCH_REGISTER => reg.scratch,
            _ => {
                log::error!(
                    "Serial {:#x}: read unreachable port {:#x}",
                    self.base_port,
                    offset as u16 + self.base_port
                );
                0x0
            }
        };
        Ok(ret as u64)
    }

    fn write(&self, offset: usize, _size: u8, val: u64) -> Result<(), mem::Error> {
        let byte = val as u8;
        let mut reg = self.reg.lock();
        match offset as u16 {
            DIVISOR_LATCH_LSB if reg.line_control.divisor_latch_access() => {
                reg.divisor = (reg.divisor & 0xff00) | byte as u16;
            }
            DIVISOR_LATCH_MSB if reg.line_control.divisor_latch_access() => {
                reg.divisor = (reg.divisor & 0x00ff) | (byte as u16) << 8;
            }
            TX_HOLDING_REGISTER => {
                if reg.modem_control.loop_back() {
                    reg.data.push_back(byte);
                    if reg
                        .interrupt_enable
                        .contains(InterruptEnable::RECEIVED_DATA_AVAILABLE)
                    {
                        reg.interrupt_identification.set_rx_data_available();
                        self.send_irq();
                    }
                    reg.line_status |= LineStatus::DATA_READY;
                } else {
                    let mut entry = CoreToIoEntry {
                        msg_type: CORE_MSG_SERIAL_TX,
                        aux_u16: 1,
                        ..Default::default()
                    };
                    entry.data[0] = byte;
                    if let Err(e) = self.bridge.send_io_cmd(&entry) {
                        log::error!(
                            "Serial {:#x}: cannot write byte {:#02x}: {:?}",
                            self.base_port,
                            byte,
                            e
                        )
                    }
                    if reg
                        .interrupt_enable
                        .contains(InterruptEnable::TX_HOLDING_REGISTER_EMPTY)
                    {
                        reg.interrupt_identification.set_tx_room_empty();
                        self.send_irq()
                    }
                }
            }
            INTERRUPT_ENABLE_REGISTER => {
                reg.interrupt_enable = InterruptEnable::from_bits_truncate(byte);
            }
            FIFO_CONTROL_REGISTER => {}
            LINE_CONTROL_REGISTER => {
                reg.line_control = LineControl(byte);
            }
            MODEM_CONTROL_REGISTER => {
                reg.modem_control = ModemControl(byte);
            }
            LINE_STATUS_REGISTER => {}
            MODEM_STATUS_REGISTER => {}
            SCRATCH_REGISTER => {
                reg.scratch = byte;
            }
            _ => log::error!(
                "Serial {:#x}: write unreachable offset {:#x}",
                self.base_port,
                offset as u16 + self.base_port
            ),
        }
        Ok(())
    }
}

impl Serial {
    pub fn new(
        base_port: u16,
        gsi: u32,
        hv: Arc<dyn VmmHostCore>,
        ioapic: Option<Arc<IoApic>>,
        bridge: Arc<dyn VmmCoreBridge>,
    ) -> io::Result<Self> {
        let reg = Arc::new(Mutex::new(SerialReg::default()));
        Ok(Serial {
            reg,
            base_port,
            gsi,
            hv,
            ioapic,
            bridge,
        })
    }

    pub fn push_rx(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut reg = self.reg.lock();
        reg.data.extend(bytes);
        if reg
            .interrupt_enable
            .contains(InterruptEnable::RECEIVED_DATA_AVAILABLE)
        {
            reg.interrupt_identification.set_rx_data_available();
            self.send_irq();
        }
        reg.line_status |= LineStatus::DATA_READY;
    }

    fn send_irq(&self) {
        if let Some(ioapic) = &self.ioapic {
            ioapic.pulse_irq(self.gsi);
        } else if let Err(e) = self
            .hv
            .set_gsi_level(self.gsi, true)
            .and_then(|()| self.hv.set_gsi_level(self.gsi, false))
        {
            log::error!("Serial {:#x}: sending interrupt: {:?}", self.base_port, e);
        }
    }
}
