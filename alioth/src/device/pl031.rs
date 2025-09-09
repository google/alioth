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

//! Emulated PL031 Real Time Clock (RTC) device.
//! See: https://developer.arm.com/documentation/ddi0224/c

use std::time::{SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use parking_lot::Mutex;

use crate::mem;
use crate::mem::emulated::{Action, Mmio};

const RTC_DR: u64 = 0x000;
const RTC_MR: u64 = 0x004;
const RTC_LR: u64 = 0x008;
const RTC_CR: u64 = 0x00C;
const RTC_IMSC: u64 = 0x010;
const RTC_RIS: u64 = 0x014;
const RTC_MIS: u64 = 0x018;
const RTC_ICR: u64 = 0x01C;

const RTC_PERIPH_ID0: u64 = 0xFE0;
const RTC_PERIPH_ID1: u64 = 0xFE4;
const RTC_PERIPH_ID2: u64 = 0xFE8;
const RTC_PERIPH_ID3: u64 = 0xFEC;
const RTC_PCELL_ID0: u64 = 0xFF0;
const RTC_PCELL_ID1: u64 = 0xFF4;
const RTC_PCELL_ID2: u64 = 0xFF8;
const RTC_PCELL_ID3: u64 = 0xFFC;

const PERIPH_ID: [u8; 4] = [0x31, 0x10, 0x04, 0x00];
const PCELL_ID: [u8; 4] = [0x0d, 0xf0, 0x05, 0xb1];

bitflags! {
    #[derive(Default, Debug, Clone, Copy)]
    struct Interrupt: u32 {
        const RTCINTR = 1 << 0;
    }
}

#[derive(Debug, Default)]
struct Pl031Reg {
    mr: u32,
    lr: u32,
    offset: u32,
}

#[derive(Debug)]
pub struct Pl031 {
    name: Box<str>,
    reg: Mutex<Pl031Reg>,
}

impl Pl031 {
    pub fn new(base_addr: u64) -> Self {
        Self {
            name: Box::from(format!("pl031@{base_addr:x}")),
            reg: Mutex::new(Pl031Reg::default()),
        }
    }

    fn now() -> u32 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as u32,
            Err(_) => {
                log::error!("System clock is before UNIX_EPOCH. PL031 won't work!");
                0
            }
        }
    }
}

impl Mmio for Pl031 {
    fn size(&self) -> u64 {
        0x1000
    }

    fn read(&self, offset: u64, _size: u8) -> mem::Result<u64> {
        let reg = self.reg.lock();
        let val = match offset {
            RTC_DR => reg.offset.wrapping_add(Self::now()),
            RTC_MR => reg.mr,
            RTC_LR => reg.lr,
            RTC_CR => 1,                       // RTC is always enabled
            RTC_IMSC | RTC_RIS | RTC_MIS => 0, // Interrupts are not supported
            RTC_PERIPH_ID0 => PERIPH_ID[0] as u32,
            RTC_PERIPH_ID1 => PERIPH_ID[1] as u32,
            RTC_PERIPH_ID2 => PERIPH_ID[2] as u32,
            RTC_PERIPH_ID3 => PERIPH_ID[3] as u32,
            RTC_PCELL_ID0 => PCELL_ID[0] as u32,
            RTC_PCELL_ID1 => PCELL_ID[1] as u32,
            RTC_PCELL_ID2 => PCELL_ID[2] as u32,
            RTC_PCELL_ID3 => PCELL_ID[3] as u32,
            _ => {
                log::warn!("{}: read from unknown offset {offset:#x}", self.name);
                0
            }
        };
        log::trace!("{}: read {val:#x} from offset {offset:#x}", self.name);
        Ok(val as u64)
    }

    fn write(&self, offset: u64, _size: u8, val: u64) -> mem::Result<Action> {
        let mut reg = self.reg.lock();
        let val = val as u32;
        match offset {
            RTC_MR => reg.mr = val,
            RTC_LR => {
                reg.offset = val.wrapping_sub(Self::now());
                reg.lr = val;
            }
            RTC_CR => {} // RTC is always enabled
            RTC_IMSC => {
                // Interrupt is alwasy masked
                if Interrupt::from_bits_retain(val).contains(Interrupt::RTCINTR) {
                    log::warn!("{}: guest tries to unmask interrupt", self.name);
                }
            }
            RTC_ICR => {} // Interrupts are not supported
            _ => {
                log::warn!(
                    "{}: write {val:#x} to unknown offset {offset:#x}",
                    self.name,
                );
            }
        };
        log::trace!("{}: write {val:#x} to offset {offset:#x}", self.name);
        Ok(Action::None)
    }
}
