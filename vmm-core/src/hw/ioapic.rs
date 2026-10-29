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

//! Intel 82093AA I/O APIC (`0xfec0_0000`) emulation for Split-IRQChip / Ring-0 hosts.
//!
//! Translates legacy ISA/GSI pin assertions (`0..24`) into architectural x86 MSI
//! `(addr, data)` writes delivered via [`VmmHostCore::inject_msi`].

use alloc::sync::Arc;
use core::fmt::{self, Debug, Formatter};

use crate::host::VmmHostCore;
use crate::hw::layout::APIC_START;
use crate::mem;
use crate::mem::mmio::Mmio;
use crate::sync::Mutex;

pub const IOAPIC_NUM_PINS: usize = 24;
pub const IOAPIC_SIZE: usize = 0x1000;

const REG_IOREGSEL: usize = 0x00;
const REG_IOWIN: usize = 0x10;
const REG_EOIR: usize = 0x40;

const IDX_ID: u8 = 0x00;
const IDX_VER: u8 = 0x01;
const IDX_ARB: u8 = 0x02;
const IDX_REDTBL_BASE: u8 = 0x10;
const IDX_REDTBL_END: u8 = IDX_REDTBL_BASE + (IOAPIC_NUM_PINS as u8) * 2 - 1;

const IOAPIC_VERSION: u32 = 0x20;

const RTE_MASKED: u64 = 1 << 16;
const RTE_TRIGGER_LEVEL: u64 = 1 << 15;
const RTE_REMOTE_IRR: u64 = 1 << 14;
/// Writable bits in low 32 bits of an RTE: vector (7:0), delivery_mode (10:8),
/// dest_mode (11), polarity (13), trigger_mode (15), mask (16).
/// Excludes read-only delivery_status (12) and remote_irr (14).
const RTE_WRITABLE_LO_MASK: u64 = 0x0001_afff;

#[derive(Debug)]
struct IoApicState {
    ioregsel: u8,
    id: u8,
    rtes: [u64; IOAPIC_NUM_PINS],
    /// Bitmask of currently asserted GSI input lines (`0..24`).
    irr: u32,
}

impl Default for IoApicState {
    fn default() -> Self {
        Self {
            ioregsel: 0,
            id: 0,
            rtes: [RTE_MASKED; IOAPIC_NUM_PINS],
            irr: 0,
        }
    }
}

pub struct IoApic {
    hv: Arc<dyn VmmHostCore>,
    state: Mutex<IoApicState>,
}

impl Debug for IoApic {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoApic")
            .field("state", &self.state)
            .finish()
    }
}

impl IoApic {
    pub fn new(hv: Arc<dyn VmmHostCore>) -> Self {
        Self {
            hv,
            state: Mutex::new(IoApicState::default()),
        }
    }

    pub fn reset(&self) {
        *self.state.lock() = IoApicState::default();
    }

    /// Format an unmasked Redirection Table Entry into architectural x86 MSI `(addr, data)`.
    #[inline]
    pub fn format_rte_msi(rte: u64) -> Option<(u64, u32)> {
        if (rte & RTE_MASKED) != 0 {
            return None;
        }
        let vector = (rte & 0xff) as u32;
        let delivery_mode = ((rte >> 8) & 0x7) as u32;
        if (delivery_mode == 0b000 || delivery_mode == 0b001) && vector < 16 {
            return None;
        }
        let dest_mode = (rte >> 11) & 0x1;
        let trigger_level = ((rte >> 15) & 0x1) as u32;
        let dest_id = (rte >> 56) & 0xff;
        let rh = u64::from(delivery_mode == 0b001);

        let addr = (APIC_START as u64) | (dest_id << 12) | (rh << 3) | (dest_mode << 2);
        let data = vector | (delivery_mode << 8) | (1 << 14) | (trigger_level << 15);
        Some((addr, data))
    }

    #[inline]
    fn deliver_msi(&self, addr: u64, data: u32) {
        if let Err(e) = self.hv.inject_msi(addr, data) {
            log::error!("IoApic: inject_msi({addr:#x}, {data:#x}) failed: {e}");
        }
    }

    /// Drive GSI input pin `gsi` (`0..24`) high (`true`) or low (`false`).
    pub fn set_irq(&self, gsi: u32, active: bool) {
        let pin = gsi as usize;
        if pin >= IOAPIC_NUM_PINS {
            return;
        }
        let pending_msi = {
            let mut st = self.state.lock();
            let bit = 1u32 << pin;
            let was_active = (st.irr & bit) != 0;
            if active {
                st.irr |= bit;
            } else {
                st.irr &= !bit;
                return;
            }

            let rte = st.rtes[pin];
            if (rte & RTE_MASKED) != 0 {
                None
            } else if (rte & RTE_TRIGGER_LEVEL) != 0 {
                if (rte & RTE_REMOTE_IRR) == 0 {
                    let msi = Self::format_rte_msi(rte);
                    if msi.is_some() {
                        st.rtes[pin] |= RTE_REMOTE_IRR;
                    }
                    msi
                } else {
                    None
                }
            } else if !was_active {
                Self::format_rte_msi(rte)
            } else {
                None
            }
        };

        if let Some((addr, data)) = pending_msi {
            self.deliver_msi(addr, data);
        }
    }

    /// Assert and immediately deassert an edge/pulse GSI input (used by ISA UART).
    pub fn pulse_irq(&self, gsi: u32) {
        self.set_irq(gsi, true);
        self.set_irq(gsi, false);
    }

    /// Broadcast an APIC End-Of-Interrupt for `vector`, clearing `Remote IRR` on matching
    /// level-triggered pins and re-firing if the input line remains asserted.
    pub fn eoi(&self, vector: u8) {
        let mut refire = [(0u64, 0u32); IOAPIC_NUM_PINS];
        let mut refire_count = 0usize;
        {
            let mut st = self.state.lock();
            for pin in 0..IOAPIC_NUM_PINS {
                let rte = st.rtes[pin];
                if (rte & RTE_TRIGGER_LEVEL) != 0
                    && (rte & RTE_REMOTE_IRR) != 0
                    && (rte & 0xff) as u8 == vector
                {
                    st.rtes[pin] &= !RTE_REMOTE_IRR;
                    if (st.irr & (1u32 << pin)) != 0
                        && let Some(msi) = Self::format_rte_msi(st.rtes[pin])
                    {
                        st.rtes[pin] |= RTE_REMOTE_IRR;
                        refire[refire_count] = msi;
                        refire_count += 1;
                    }
                }
            }
        }
        for &(addr, data) in &refire[..refire_count] {
            self.deliver_msi(addr, data);
        }
    }
}

impl Mmio for IoApic {
    fn size(&self) -> usize {
        IOAPIC_SIZE
    }

    fn read(&self, offset: usize, _size: u8) -> mem::Result<u64> {
        let st = self.state.lock();
        let val = match offset {
            REG_IOREGSEL => st.ioregsel as u32,
            REG_IOWIN => match st.ioregsel {
                IDX_ID | IDX_ARB => (st.id as u32) << 24,
                IDX_VER => (((IOAPIC_NUM_PINS as u32) - 1) << 16) | IOAPIC_VERSION,
                idx @ IDX_REDTBL_BASE..=IDX_REDTBL_END => {
                    let pin = ((idx - IDX_REDTBL_BASE) / 2) as usize;
                    let rte = st.rtes[pin];
                    if (idx - IDX_REDTBL_BASE).is_multiple_of(2) {
                        rte as u32
                    } else {
                        (rte >> 32) as u32
                    }
                }
                _ => 0,
            },
            _ => 0,
        };
        Ok(val as u64)
    }

    fn write(&self, offset: usize, _size: u8, val: u64) -> mem::Result<()> {
        match offset {
            REG_IOREGSEL => {
                self.state.lock().ioregsel = (val & 0xff) as u8;
            }
            REG_IOWIN => {
                let pending_msi = {
                    let mut st = self.state.lock();
                    match st.ioregsel {
                        IDX_ID => {
                            st.id = ((val >> 24) & 0x0f) as u8;
                            None
                        }
                        idx @ IDX_REDTBL_BASE..=IDX_REDTBL_END => {
                            let pin = ((idx - IDX_REDTBL_BASE) / 2) as usize;
                            let old = st.rtes[pin];
                            if (idx - IDX_REDTBL_BASE).is_multiple_of(2) {
                                let preserved_remote_irr = if (val & RTE_TRIGGER_LEVEL) != 0 {
                                    old & RTE_REMOTE_IRR
                                } else {
                                    0
                                };
                                let lo = (val & RTE_WRITABLE_LO_MASK) | preserved_remote_irr;
                                let new_rte = (old & 0xffff_ffff_0000_0000) | lo;
                                st.rtes[pin] = new_rte;
                                if (new_rte & RTE_TRIGGER_LEVEL) != 0
                                    && (new_rte & RTE_REMOTE_IRR) == 0
                                    && (st.irr & (1u32 << pin)) != 0
                                {
                                    let msi = Self::format_rte_msi(new_rte);
                                    if msi.is_some() {
                                        st.rtes[pin] |= RTE_REMOTE_IRR;
                                    }
                                    msi
                                } else {
                                    None
                                }
                            } else {
                                st.rtes[pin] =
                                    (old & 0x0000_0000_ffff_ffff) | ((val & 0xffff_ffff) << 32);
                                None
                            }
                        }
                        _ => None,
                    }
                };
                if let Some((addr, data)) = pending_msi {
                    self.deliver_msi(addr, data);
                }
            }
            REG_EOIR => {
                self.eoi((val & 0xff) as u8);
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;

    use super::*;
    use crate::host::test::FakeHost;

    #[test]
    fn test_ioapic_edge_and_level_msi_delivery() {
        let host = Arc::new(FakeHost::default());
        let ioapic = IoApic::new(host.clone());

        // Check version register: 24 pins (max_redir = 0x17), version 0x20.
        ioapic.write(REG_IOREGSEL, 4, IDX_VER as u64).unwrap();
        assert_eq!(ioapic.read(REG_IOWIN, 4).unwrap(), 0x0017_0020);

        // Pin 4 starts masked (0x0001_0000); pulsing should not inject an MSI.
        ioapic.pulse_irq(4);
        assert!(host.take_msis().is_empty());

        // Configure pin 4 (COM1): edge-triggered, physical dest APIC ID 1, vector 0x24.
        let pin4_lo = IDX_REDTBL_BASE + 4 * 2;
        let pin4_hi = pin4_lo + 1;
        ioapic.write(REG_IOREGSEL, 4, pin4_hi as u64).unwrap();
        ioapic.write(REG_IOWIN, 4, 1u64 << 24).unwrap();
        ioapic.write(REG_IOREGSEL, 4, pin4_lo as u64).unwrap();
        ioapic.write(REG_IOWIN, 4, 0x24).unwrap();

        ioapic.pulse_irq(4);
        let msis = host.take_msis();
        assert_eq!(msis, vec![(0xfee0_1000, 0x4024)]);

        // Configure pin 5: level-triggered, logical dest 0x02, vector 0x35.
        let pin5_lo = IDX_REDTBL_BASE + 5 * 2;
        let pin5_hi = pin5_lo + 1;
        ioapic.write(REG_IOREGSEL, 4, pin5_hi as u64).unwrap();
        ioapic.write(REG_IOWIN, 4, 2u64 << 24).unwrap();
        ioapic.write(REG_IOREGSEL, 4, pin5_lo as u64).unwrap();
        ioapic
            .write(REG_IOWIN, 4, 0x35 | (1 << 11) | RTE_TRIGGER_LEVEL)
            .unwrap();

        // Assert level line: fires once and sets Remote IRR (suppressing duplicates).
        ioapic.set_irq(5, true);
        ioapic.set_irq(5, true);
        let msis = host.take_msis();
        assert_eq!(msis, vec![(0xfee0_2004, 0xc035)]);

        // EOIR write while line is still asserted clears Remote IRR and re-fires!
        ioapic.write(REG_EOIR, 4, 0x35).unwrap();
        let msis = host.take_msis();
        assert_eq!(msis, vec![(0xfee0_2004, 0xc035)]);

        // Deassert line, then EOI: clears Remote IRR without re-firing.
        ioapic.set_irq(5, false);
        ioapic.write(REG_EOIR, 4, 0x35).unwrap();
        assert!(host.take_msis().is_empty());
    }
}
