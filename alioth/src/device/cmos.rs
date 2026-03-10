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

use std::sync::atomic::{AtomicU8, Ordering};

use bitfield::bitfield;
use chrono::{DateTime, Datelike, Timelike};

use crate::device::clock::Clock;
use crate::device::{MmioDev, Pause, Result};
use crate::mem::emulated::{Action, Mmio};
use crate::{bitflags, consts, mem};

bitfield! {
    pub struct CmosReg(u8);
    pub disable_nmi, set_disable_nmi: 7;
    pub reg, set_reg: 6, 0;
}

consts! {
    pub struct CmosIntrFreq(u8) {
        HZ_1024 = 0b0110;
    }
}

consts! {
    pub struct CmosTimeBase(u8) {
        HZ_32768 = 0b010;
    }
}

bitfield! {
    pub struct CmosRegA(u8);
    impl new;
    pub u8, from into CmosIntrFreq, intr_freq, set_intr_freq: 3, 0;
    pub u8, from into CmosTimeBase, time_base, set_time_base: 6, 4;
    pub update_in_progress, set_update_in_progress: 7;
}

impl Default for CmosRegA {
    fn default() -> Self {
        CmosRegA::new(CmosIntrFreq::HZ_1024, CmosTimeBase::HZ_32768, false)
    }
}

bitflags! {
    pub struct CmosRegB(u8) {
        HOUR_24 = 1 << 1;
        BINARY_FORMAT = 1 << 2;
    }
}

bitflags! {
    pub struct CmosRegD(u8) {
        POWER = 1 << 7;
    }
}

/// CMOS RTC device.
///
/// https://stanislavs.org/helppc/cmos_ram.html
/// https://wiki.osdev.org/CMOS
#[derive(Debug)]
pub struct Cmos<C> {
    reg: AtomicU8,
    clock: C,
}

impl<C> Cmos<C> {
    pub fn new(clock: C) -> Self {
        Self {
            reg: AtomicU8::new(0),
            clock,
        }
    }
}

impl<C: Clock> Mmio for Cmos<C> {
    fn size(&self) -> u64 {
        2
    }

    fn read(&self, offset: u64, _size: u8) -> mem::Result<u64> {
        let reg = self.reg.load(Ordering::Relaxed);
        if offset == 0 {
            return Ok(reg as u64);
        }
        let nanos = self.clock.now().as_nanos();
        let now = DateTime::from_timestamp_nanos(nanos as i64);
        let ret = match CmosReg(reg).reg() {
            0x00 => now.second(),
            0x02 => now.minute(),
            0x04 => now.hour(),
            0x06 => now.weekday().number_from_sunday(),
            0x07 => now.day(),
            0x08 => now.month(),
            0x09 => now.year() as u32 % 100,
            0x32 => now.year() as u32 / 100 + 1,
            0x0a => {
                // Assuming the hardware takes 8 crystal cycles to update
                // the 8 registers above.
                // 1 / 32768 Hz * 8 = 244140 ns
                let mut r = CmosRegA::default();
                if now.nanosecond() < 244140 {
                    r.set_update_in_progress(true);
                }
                r.0 as u32
            }
            0x0b => (CmosRegB::HOUR_24 | CmosRegB::BINARY_FORMAT).bits() as u32,
            0x0d => CmosRegD::POWER.bits() as u32,
            _ => {
                log::debug!("cmos: read from reg {reg:#x}: ignored");
                0
            }
        };
        Ok(ret as u64)
    }

    fn write(&self, offset: u64, _size: u8, val: u64) -> mem::Result<Action> {
        if offset == 0 {
            self.reg.store(val as u8, Ordering::Relaxed);
        } else {
            log::debug!(
                "cmos: write {val:#x} to reg {:#x}: ignored",
                self.reg.load(Ordering::Relaxed)
            );
        }
        Ok(Action::None)
    }
}

impl<C: Clock> Pause for Cmos<C> {
    fn pause(&self) -> Result<()> {
        todo!()
    }

    fn resume(&self) -> Result<()> {
        todo!()
    }
}

impl<C: Clock> MmioDev for Cmos<C> {}

#[cfg(test)]
#[path = "cmos_test.rs"]
mod tests;
