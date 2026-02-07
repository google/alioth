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

//! Emulated x86 IO APIC device.
//! See: https://download.intel.com/design/chipsets/datashts/29056601.pdf chapter 3.2

use parking_lot::Mutex;

use crate::arch::intr::{DestinationMode, MsiAddrLo, MsiData, TriggerMode};
use crate::arch::ioapic::{
    IOAPIC_VER, IOAPICARB, IOAPICID, IOAPICVER, IOREDTBL_BASE, IOREDTBL_MAX, IOREGSEL, IOWIN,
    NUM_PINS, RedirectEntry, RegId, RegVer,
};
use crate::arch::layout::{APIC_START, IOAPIC_END, IOAPIC_START};
use crate::device::{self, MmioDev, Pause};
use crate::hv::MsiSender;
use crate::mem;
use crate::mem::emulated::{Action, Mmio};

#[derive(Debug, Default)]
struct IoApicRegs {
    id: RegId,
    redirtbl: [RedirectEntry; NUM_PINS as usize],
    select: u8,
}

#[derive(Debug)]
pub struct IoApic<M: MsiSender> {
    regs: Mutex<IoApicRegs>,
    msi_sender: M,
}

impl<M: MsiSender> IoApic<M> {
    pub fn new(msi_sender: M) -> Self {
        Self {
            regs: Mutex::new(IoApicRegs::default()),
            msi_sender,
        }
    }

    pub fn service_pin(&self, pin: u8) -> crate::hv::Result<()> {
        let regs = self.regs.lock();
        let Some(entry) = regs.redirtbl.get(pin as usize) else {
            log::warn!("IOAPIC: invalid pin {pin}");
            return Ok(());
        };

        if entry.masked() {
            return Ok(());
        }

        if entry.dest_mode() == DestinationMode::LOGICAL.raw() {
            log::warn!("IOAPIC: logical destination is not supported");
            return Ok(());
        }
        if entry.trigger_mode() == TriggerMode::LEVEL.raw() {
            log::warn!("IOAPIC: level-triggered interrupts are not supported");
            return Ok(());
        }

        let mut addr_lo = MsiAddrLo(APIC_START as u32);
        addr_lo.set_dest_id(entry.dest_id());
        addr_lo.set_virt_dest_id_hi(entry.virt_dest_id_hi());

        let data = MsiData::new(
            entry.vector(),
            entry.delivery_mode(),
            false,
            entry.trigger_mode(),
        );

        self.msi_sender.send(addr_lo.0 as u64, data.0)
    }

    fn read_reg(&self, regs: &IoApicRegs) -> u32 {
        match regs.select {
            IOAPICID | IOAPICARB => regs.id.0,
            IOAPICVER => RegVer::new(IOAPIC_VER, NUM_PINS - 1).0,
            select @ IOREDTBL_BASE..=IOREDTBL_MAX => {
                let pin = ((select - IOREDTBL_BASE) >> 1) as usize;
                let Some(entry) = regs.redirtbl.get(pin) else {
                    log::warn!("IOAPIC: read from unknown pin {pin:#x}");
                    return 0;
                };
                if select % 2 == 0 {
                    entry.0 as u32
                } else {
                    (entry.0 >> 32) as u32
                }
            }
            unknown => {
                log::warn!("IOAPCI: read from unknown register {unknown:#x}");
                0
            }
        }
    }

    fn write_reg(&self, regs: &mut IoApicRegs, val: u32) {
        match regs.select {
            IOAPICID => regs.id.set_id(RegId(val).id()),
            IOAPICVER | IOAPICARB => log::warn!("IOAPIC: IOAPICVER and IOAPICARB are read-only"),
            select @ IOREDTBL_BASE..=IOREDTBL_MAX => {
                let pin = ((select - IOREDTBL_BASE) >> 1) as usize;
                let Some(entry) = regs.redirtbl.get_mut(pin) else {
                    log::warn!("IOAPIC: write to unknown pin {pin:#x}");
                    return;
                };
                entry.0 = if select % 2 == 0 {
                    (entry.0 & 0xffffffff00000000) | (val as u64)
                } else {
                    (entry.0 & 0x00000000ffffffff) | ((val as u64) << 32)
                };
            }
            unknown => {
                log::warn!("IOAPIC: write to unknown register {unknown:#x} with value {val:#x}");
            }
        }
    }
}

impl<M: MsiSender> Mmio for IoApic<M> {
    fn size(&self) -> u64 {
        IOAPIC_END - IOAPIC_START
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        if size != 4 {
            log::warn!("IOAPIC: unaligned read: offset={offset:#x} size={size}");
            return Ok(0);
        }
        let regs = self.regs.lock();
        let val = match offset {
            IOREGSEL => regs.select as u32,
            IOWIN => self.read_reg(&regs),
            _ => {
                log::warn!("IOAPIC: read from unknown offset {offset:#x}");
                0
            }
        };
        Ok(val as u64)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        if size != 4 {
            log::warn!("IOAPIC: unaligned write: offset={offset:#x} size={size}");
            return Ok(Action::None);
        }
        let mut regs = self.regs.lock();
        match offset {
            IOREGSEL => regs.select = val as u8,
            IOWIN => self.write_reg(&mut regs, val as u32),
            _ => {
                log::warn!("IOAPIC: write to unknown offset {offset:#x} with value {val:#x}");
            }
        }
        Ok(Action::None)
    }
}

impl<M: MsiSender> Pause for IoApic<M> {
    fn pause(&self) -> device::Result<()> {
        Ok(())
    }

    fn resume(&self) -> device::Result<()> {
        Ok(())
    }
}

impl<M: MsiSender> MmioDev for IoApic<M> {}

#[cfg(test)]
#[path = "ioapic_test.rs"]
mod tests;
