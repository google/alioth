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
use std::io;
use std::sync::Arc;

use bitflags::bitflags;
use parking_lot::Mutex;

use crate::device::console::{Console, UartRecv};
use crate::hv::IrqSender;
use crate::mem::emulated::{Action, Mmio};
use crate::{hv, mem};

/// RW width 12/8 Data Register
const UART_DR: u64 = 0x0;
/// RO width 4 Receive Status Register
const UART_RSR: u64 = 0x4;
/// WO width 0  Error Clear Register
const UART_ECR: u64 = 0x4;
/// RO width 9 Flag Register
const UART_FR: u64 = 0x18;
/// RW width 8 IrDA Low-Power Counter Register
const UART_ILPR: u64 = 0x20;
/// RW width 16 Integer Baud Rate Register
const UART_IBRD: u64 = 0x24;
/// RW width 6 Fractional Baud Rate Register
const UART_FBRD: u64 = 0x28;
/// RW width 8 Line Control Register
const UART_LCR_H: u64 = 0x2C;
/// RW width 16 Control Register
const UART_CR: u64 = 0x30;
/// RW width 6 Interrupt FIFO Level Select Register
const UART_IFLS: u64 = 0x34;
/// RW width 11 Interrupt Mask Set/Clear Register
const UART_IMSC: u64 = 0x38;
/// RO width 11 Raw Interrupt Status Register
const UART_RIS: u64 = 0x3C;
/// RO width 11 Masked Interrupt Status Register
const UART_MIS: u64 = 0x40;
/// WO width 11 Interrupt Clear Register
const UART_ICR: u64 = 0x44;
/// RW width 3 DMA Control Register
const UART_DMACR: u64 = 0x48;
/// RO width 8 UARTPeriphID0 Register
const UART_PERIPH_ID0: u64 = 0xFE0;
/// RO width 8 UARTPeriphID1 Register
const UART_PERIPH_ID1: u64 = 0xFE4;
/// RO width 8 UARTPeriphID2 Register
const UART_PERIPH_ID2: u64 = 0xFE8;
/// RO width 8 UARTPeriphID3 Register
const UART_PERIPH_ID3: u64 = 0xFEC;
/// RO width 8 UARTPCellID0 Register
const UART_PCELL_ID0: u64 = 0xFF0;
/// RO width 8 UARTPCellID1 Register
const UART_PCELL_ID1: u64 = 0xFF4;
/// RO width 8 UARTPCellID2 Register
const UART_PCELL_ID2: u64 = 0xFF8;
/// RO width 8 UARTPCellID3 Register
const UART_PCELL_ID3: u64 = 0xFFC;

// https://developer.arm.com/documentation/ddi0183/g/programmers-model/register-descriptions/peripheral-identification-registers--uartperiphid0-3
const PERIPH_ID: [u32; 4] = [0x11, 0x10, 0x14, 0x00];

// https://developer.arm.com/documentation/ddi0183/g/programmers-model/register-descriptions/primecell-identification-registers--uartpcellid0-3
const PCELL_ID: [u32; 4] = [0x0d, 0xf0, 0x05, 0xb1];

bitflags! {
    #[derive(Default, Debug, Clone, Copy)]
    pub struct Flag: u16 {
        const RI = 1 << 8;
        /// Transmit FIFO empty
        const TXFE = 1 << 7;
        /// Receive FIFO full
        const RXFF = 1 << 6;
        /// Transmit FIFO full.
        const TXFF = 1 << 5;
        /// Receive FIFO empty
        const RXFE = 1 << 4;
        const BUSY = 1 << 3;
        const DCD = 1 << 2;
        const DSR = 1 << 1;
        const CTS = 1 << 0;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy)]
    pub struct Interrupt: u16 {
        /// Overrun error interrupt status.
        const OERIS = 1 << 10;
        /// Break error interrupt status.
        const BERIS = 1 << 9;
        /// Parity error interrupt status.
        const PERIS = 1 << 8;
        /// Framing error interrupt status.
        const FERIS = 1 << 7;
        /// Receive timeout interrupt status.
        const RTRIS = 1 << 6;
        /// Transmit interrupt status.
        const TXRIS = 1 << 5;
        /// Receive interrupt status.
        const RXRIS = 1 << 4;
        /// nUARTDSR modem interrupt status.
        const DSRRMIS = 1 << 3;
        /// nUARTDCD modem interrupt status.
        const DCDRMIS = 1 << 2;
        /// nUARTCTS modem interrupt status.
        const CTSRMIS = 1 << 1;
        /// nUARTRI modem interrupt status.
        const RIRMIS = 1 << 0;
    }
}

#[derive(Debug, Default)]
struct Pl011Reg {
    data: VecDeque<u8>,
    flag: Flag,
    lcr: u32,
    rsr: u32,
    cr: u32,
    dmacr: u32,
    ilpr: u32,
    ibrd: u32,
    fbrd: u32,
    ifl: u32,
    interrupt_mask: Interrupt,
    interrupt_status: Interrupt,
}

///  https://developer.arm.com/documentation/ddi0183/g
#[derive(Debug)]
pub struct Pl011<I> {
    name: Arc<str>,
    irq_line: Arc<I>,
    reg: Arc<Mutex<Pl011Reg>>,
    console: Console,
}

impl<I> Pl011<I>
where
    I: IrqSender,
{
    pub fn new(base_addr: u64, irq_line: I) -> io::Result<Self> {
        let irq_line = Arc::new(irq_line);
        let reg = Arc::new(Mutex::new(Pl011Reg::default()));
        let name: Arc<str> = Arc::from(format!("pl011@{base_addr:#x}"));
        let pl011_recv = Pl011Recv {
            irq_line: irq_line.clone(),
            reg: reg.clone(),
        };
        let console = Console::new(name.clone(), pl011_recv)?;
        let pl011 = Pl011 {
            name,
            irq_line,
            reg,
            console,
        };
        Ok(pl011)
    }

    fn update_interrupt(&self, reg: &Pl011Reg) -> Result<(), hv::Error> {
        if (reg.interrupt_status & reg.interrupt_mask).bits() != 0 {
            self.irq_line.send().unwrap();
        }
        Ok(())
    }
}

impl<I> Mmio for Pl011<I>
where
    I: IrqSender,
{
    fn size(&self) -> u64 {
        0x1000
    }

    fn read(&self, offset: u64, _size: u8) -> mem::Result<u64> {
        let mut reg = self.reg.lock();
        let ret = match offset {
            UART_DR => {
                let byte = reg.data.pop_front().unwrap_or(0);
                if reg.data.is_empty() {
                    reg.flag.insert(Flag::RXFE);
                    reg.interrupt_status.remove(Interrupt::RXRIS);
                }
                self.update_interrupt(&reg)?;
                byte as u32
            }
            UART_RSR => reg.rsr,
            UART_FR => reg.flag.bits() as u32,
            UART_ILPR => reg.ilpr,
            UART_IBRD => reg.ibrd,
            UART_FBRD => reg.fbrd,
            UART_LCR_H => reg.lcr,
            UART_CR => reg.cr,
            UART_IFLS => reg.ifl,
            UART_IMSC => reg.interrupt_mask.bits() as u32,
            UART_RIS => reg.interrupt_status.bits() as u32,
            UART_MIS => (reg.interrupt_mask & reg.interrupt_status).bits() as u32,
            UART_ICR => {
                log::error!("{}: UART_ICR is write only", self.name);
                0
            }
            UART_DMACR => reg.dmacr,
            UART_PERIPH_ID0 => PERIPH_ID[0],
            UART_PERIPH_ID1 => PERIPH_ID[1],
            UART_PERIPH_ID2 => PERIPH_ID[2],
            UART_PERIPH_ID3 => PERIPH_ID[3],
            UART_PCELL_ID0 => PCELL_ID[0],
            UART_PCELL_ID1 => PCELL_ID[1],
            UART_PCELL_ID2 => PCELL_ID[2],
            UART_PCELL_ID3 => PCELL_ID[3],
            _ => 0,
        };
        Ok(ret as u64)
    }

    fn write(&self, offset: u64, _size: u8, val: u64) -> mem::Result<Action> {
        let mut reg = self.reg.lock();
        match offset {
            UART_DR => {
                self.console.transmit(&[val as u8]);
                reg.interrupt_status.insert(Interrupt::TXRIS);
                reg.flag.insert(Flag::TXFE);
                self.update_interrupt(&reg)?;
            }
            UART_ECR => reg.rsr = 0,
            UART_FR => log::error!("{}: UART_FR is read only", self.name),
            UART_ILPR => reg.ilpr = val as u32,
            UART_IBRD => reg.ibrd = val as u32,
            UART_FBRD => reg.fbrd = val as u32,
            UART_LCR_H => reg.lcr = val as u32,
            UART_CR => reg.cr = val as u32,
            UART_IFLS => reg.ifl = val as u32,
            UART_IMSC => {
                reg.interrupt_mask = Interrupt::from_bits_truncate(val as u16);
            }
            UART_RIS => log::error!("{}, UART_RIS is read only", self.name),
            UART_MIS => log::error!("{}, UART_MIS is read only", self.name),
            UART_ICR => reg.interrupt_status &= !Interrupt::from_bits_truncate(val as u16),
            UART_DMACR => reg.dmacr = val as u32,
            _ => {}
        }
        Ok(Action::None)
    }
}

struct Pl011Recv<I: IrqSender> {
    irq_line: Arc<I>,
    reg: Arc<Mutex<Pl011Reg>>,
}

impl<I: IrqSender> UartRecv for Pl011Recv<I> {
    fn receive(&self, bytes: &[u8]) {
        let mut reg = self.reg.lock();
        reg.data.extend(bytes);
        reg.interrupt_status.insert(Interrupt::RXRIS);
        reg.flag.remove(Flag::RXFE);

        if (reg.interrupt_status & reg.interrupt_mask).bits() != 0 {
            self.irq_line.send().unwrap();
        }
    }
}
