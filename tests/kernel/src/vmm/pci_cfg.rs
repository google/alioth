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

//! Ring-0 PCI Type-1 (`0xcf8`–`0xcff`) configuration-space accessors,
//! `pci_passthrough=` cmdline parsing, and `#GP` port-I/O filtering so
//! Ring-0-owned BDFs (`virtio-iommu` and passthrough endpoints) are hidden
//! from unmodified Ring-3 `sys-io`.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::irq::IrqStack;
use crate::util::SpinLock;

pub const PCI_CONFIG_ADDR: u16 = 0xcf8;
pub const PCI_CONFIG_DATA: u16 = 0xcfc;
pub const PCI_CONFIG_DATA_END: u16 = 0xcff;

/// Global spinlock serializing all hardware `0xcf8`/`0xcfc` cycles across Ring 0
/// and `#GP`-emulated Ring-3 `CAP_IO_MANAGER` accesses.
static PCI_CFG_LOCK: SpinLock<()> = SpinLock::new(());

/// Lock-free 256-bit Bus-0 (`00:dd.f`) bitmaps (`4 * 64 = 256` slots).
static HIDDEN_BUS0_BITMAP: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static PASSTHROUGH_BUS0_BITMAP: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

static TRAP_IO_MANAGER_PIO: AtomicBool = AtomicBool::new(false);
static USPACE_PCI_CFG_ADDR: AtomicU32 = AtomicU32::new(0);

#[inline]
pub fn should_trap_io_manager_pio() -> bool {
    TRAP_IO_MANAGER_PIO.load(Ordering::Acquire)
}

pub fn hide_bdf_from_userspace(bdf: u16) {
    if (bdf >> 8) == 0 {
        let idx = ((bdf as usize) >> 6) & 3;
        let bit = 1u64 << (bdf & 63);
        HIDDEN_BUS0_BITMAP[idx].fetch_or(bit, Ordering::Release);
        TRAP_IO_MANAGER_PIO.store(true, Ordering::Release);
    }
}

pub fn mark_bdf_passthrough(bdf: u16) {
    if (bdf >> 8) == 0 {
        let idx = ((bdf as usize) >> 6) & 3;
        let bit = 1u64 << (bdf & 63);
        PASSTHROUGH_BUS0_BITMAP[idx].fetch_or(bit, Ordering::Release);
        hide_bdf_from_userspace(bdf);
    }
}

#[inline]
pub fn is_bdf_hidden_from_userspace(bdf: u16) -> bool {
    if (bdf >> 8) != 0 {
        return false;
    }
    let idx = ((bdf as usize) >> 6) & 3;
    let bit = 1u64 << (bdf & 63);
    (HIDDEN_BUS0_BITMAP[idx].load(Ordering::Acquire) & bit) != 0
}

#[inline]
pub fn is_bdf_passthrough(bdf: u16) -> bool {
    if (bdf >> 8) != 0 {
        return false;
    }
    let idx = ((bdf as usize) >> 6) & 3;
    let bit = 1u64 << (bdf & 63);
    (PASSTHROUGH_BUS0_BITMAP[idx].load(Ordering::Acquire) & bit) != 0
}

/// Parse `[domain:]bus:dev.func` (e.g. `"00:03.0"` or `"0000:00:03.0"`).
pub fn parse_bdf_token(token: &str) -> Option<u16> {
    let s = token.trim();
    let (prefix, dev_fn) = s.rsplit_once(':')?;
    let bus_str = match prefix.rsplit_once(':') {
        Some((dom_str, b_str)) => {
            let dom = u16::from_str_radix(dom_str, 16).ok()?;
            if dom != 0 {
                return None;
            }
            b_str
        }
        None => prefix,
    };
    let bus = u8::from_str_radix(bus_str, 16).ok()?;
    let (dev_str, fn_str) = dev_fn.split_once('.')?;
    let dev = u8::from_str_radix(dev_str, 16).ok()?;
    let func = u8::from_str_radix(fn_str, 16).ok()?;
    if dev >= 32 || func >= 8 {
        return None;
    }
    Some(((bus as u16) << 8) | ((dev as u16) << 3) | (func as u16))
}

/// Parse `pci_passthrough=00:03.0[,00:02.0]` tokens from the kernel command line.
pub fn init_from_cmdline(cmdline: &[u8]) {
    let Ok(s) = core::str::from_utf8(cmdline) else {
        return;
    };
    for arg in s.split_whitespace() {
        if let Some(list) = arg.strip_prefix("pci_passthrough=") {
            for item in list.split(',') {
                if item.is_empty() {
                    continue;
                }
                if let Some(bdf) = parse_bdf_token(item) {
                    mark_bdf_passthrough(bdf);
                    log::info!(
                        "vmm::pci_cfg: reserved passthrough PCI BDF {:02x}:{:02x}.{}",
                        bdf >> 8,
                        (bdf >> 3) & 0x1f,
                        bdf & 0x7
                    );
                } else {
                    log::warn!("vmm::pci_cfg: ignoring malformed pci_passthrough BDF '{item}'");
                }
            }
        }
    }
}

#[inline]
fn make_cfg_addr(bdf: u16, offset: u8) -> u32 {
    0x8000_0000 | ((bdf as u32) << 8) | ((offset as u32) & 0xfc)
}

#[inline]
unsafe fn raw_out32(port: u16, val: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
unsafe fn raw_out16(port: u16, val: u16) {
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
unsafe fn raw_out8(port: u16, val: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
unsafe fn raw_in32(port: u16) -> u32 {
    let val: u32;
    unsafe {
        asm!(
            "in eax, dx",
            out("eax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

#[inline]
unsafe fn raw_in16(port: u16) -> u16 {
    let val: u16;
    unsafe {
        asm!(
            "in ax, dx",
            out("ax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

#[inline]
unsafe fn raw_in8(port: u16) -> u8 {
    let val: u8;
    unsafe {
        asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

pub fn pci_cfg_read32(bdf: u16, offset: u8) -> u32 {
    let _g = PCI_CFG_LOCK.lock(line!());
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, offset));
        raw_in32(PCI_CONFIG_DATA)
    }
}

pub fn pci_cfg_read16(bdf: u16, offset: u8) -> u16 {
    let _g = PCI_CFG_LOCK.lock(line!());
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, offset));
        raw_in16(PCI_CONFIG_DATA + ((offset & 2) as u16))
    }
}

pub fn pci_cfg_read8(bdf: u16, offset: u8) -> u8 {
    let _g = PCI_CFG_LOCK.lock(line!());
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, offset));
        raw_in8(PCI_CONFIG_DATA + ((offset & 3) as u16))
    }
}

pub fn pci_cfg_write32(bdf: u16, offset: u8, val: u32) {
    let _g = PCI_CFG_LOCK.lock(line!());
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, offset));
        raw_out32(PCI_CONFIG_DATA, val);
    }
}

pub fn pci_cfg_write16(bdf: u16, offset: u8, val: u16) {
    let _g = PCI_CFG_LOCK.lock(line!());
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, offset));
        raw_out16(PCI_CONFIG_DATA + ((offset & 2) as u16), val);
    }
}

pub fn pci_cfg_write8(bdf: u16, offset: u8, val: u8) {
    let _g = PCI_CFG_LOCK.lock(line!());
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, offset));
        raw_out8(PCI_CONFIG_DATA + ((offset & 3) as u16), val);
    }
}

/// Read & size a physical PCI MMIO BAR while temporarily masking `MEM | IO`
/// in `PCI_COMMAND` so the host VMM never relocates an active BAR mapping.
/// Returns `Some((phys_addr, size, is_64, is_prefetchable))` for non-empty MMIO BARs.
pub fn probe_mmio_bar(bdf: u16, bar_idx: u8) -> Option<(u64, u64, bool, bool)> {
    if bar_idx >= 6 {
        return None;
    }
    let _g = PCI_CFG_LOCK.lock(line!());
    let bar_off = 0x10 + (bar_idx << 2);
    unsafe {
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, 0x04));
        let orig_cmd = raw_in16(PCI_CONFIG_DATA);

        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, bar_off));
        let orig_lo = raw_in32(PCI_CONFIG_DATA);
        if orig_lo == 0 || (orig_lo & 1) != 0 {
            return None;
        }
        let is_64 = (orig_lo & 0x6) == 0x4;
        let is_prefetch = (orig_lo & 0x8) != 0;
        if is_64 && bar_idx >= 5 {
            return None;
        }
        let orig_hi = if is_64 {
            raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, bar_off + 4));
            raw_in32(PCI_CONFIG_DATA)
        } else {
            0
        };

        // Disable MEM + IO decoding while writing all-ones to size the BAR.
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, 0x04));
        raw_out16(PCI_CONFIG_DATA, orig_cmd & !0x3);

        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, bar_off));
        raw_out32(PCI_CONFIG_DATA, 0xffff_ffff);
        let mask_lo = raw_in32(PCI_CONFIG_DATA) & 0xffff_fff0;
        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, bar_off));
        raw_out32(PCI_CONFIG_DATA, orig_lo);

        let mask_hi = if is_64 {
            raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, bar_off + 4));
            raw_out32(PCI_CONFIG_DATA, 0xffff_ffff);
            let m = raw_in32(PCI_CONFIG_DATA);
            raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, bar_off + 4));
            raw_out32(PCI_CONFIG_DATA, orig_hi);
            m
        } else {
            0xffff_ffff
        };

        raw_out32(PCI_CONFIG_ADDR, make_cfg_addr(bdf, 0x04));
        raw_out16(PCI_CONFIG_DATA, orig_cmd);

        let full_mask = ((mask_hi as u64) << 32) | (mask_lo as u64);
        if full_mask == 0 {
            return None;
        }
        let size = (!full_mask).wrapping_add(1);
        let phys = ((orig_hi as u64) << 32) | ((orig_lo & 0xffff_fff0) as u64);
        if phys == 0 || size == 0 {
            return None;
        }
        Some((phys, size, is_64, is_prefetch))
    }
}

/// Lock-free user virtual byte read over `upt_phys` while `IF = 0` inside `#GP`.
///
/// Safe against concurrent page reclamation because `upt_phys` is the active
/// `CR3` of the interrupted CPU and `tlb::invalidate` / `evict_user_page_table`
/// cannot complete a synchronous shootdown against this CPU until `iretq`
/// restores `IF = 1`. Avoids acquiring any `UserAddressSpace` `SpinLock` in
/// interrupt context (which would AB-BA deadlock against `tlb::invalidate`).
#[inline]
fn read_user_u8_lockfree(upt_phys: u64, vaddr: u64) -> Option<u8> {
    const PTE_PRESENT_USER: u64 = 0x5;
    const PTE_HUGE: u64 = 1 << 7;
    const PHYS_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
    const HUGE_2M_MASK: u64 = 0x000f_ffff_ffe0_0000;

    if upt_phys == 0 || vaddr >= (1u64 << 47) {
        return None;
    }
    let dm = crate::mm::PAGING_DIRECT_MAP_OFFSET;
    unsafe {
        let l4e = core::ptr::read_volatile(
            ((dm + (upt_phys & PHYS_ADDR_MASK)) as *const u64)
                .add(((vaddr >> 39) & 0x1ff) as usize),
        );
        if (l4e & PTE_PRESENT_USER) != PTE_PRESENT_USER {
            return None;
        }
        let l3e = core::ptr::read_volatile(
            ((dm + (l4e & PHYS_ADDR_MASK)) as *const u64).add(((vaddr >> 30) & 0x1ff) as usize),
        );
        if (l3e & PTE_PRESENT_USER) != PTE_PRESENT_USER || (l3e & PTE_HUGE) != 0 {
            return None;
        }
        let l2e = core::ptr::read_volatile(
            ((dm + (l3e & PHYS_ADDR_MASK)) as *const u64).add(((vaddr >> 21) & 0x1ff) as usize),
        );
        if (l2e & PTE_PRESENT_USER) != PTE_PRESENT_USER {
            return None;
        }
        let paddr = if (l2e & PTE_HUGE) != 0 {
            (l2e & HUGE_2M_MASK) | (vaddr & 0x1f_ffff)
        } else {
            let l1e = core::ptr::read_volatile(
                ((dm + (l2e & PHYS_ADDR_MASK)) as *const u64)
                    .add(((vaddr >> 12) & 0x1ff) as usize),
            );
            if (l1e & PTE_PRESENT_USER) != PTE_PRESENT_USER {
                return None;
            }
            (l1e & PHYS_ADDR_MASK) | (vaddr & 0xfff)
        };
        Some(core::ptr::read_volatile((dm + paddr) as *const u8))
    }
}

/// Emulate `in`/`out` for Ring-3 `CAP_IO_MANAGER` threads running with `IOPL = 0`,
/// mediating `0xcf8..=0xcff` so Ring-0-hidden BDFs return `0xffff_ffff` while
/// forwarding authorized non-PCI port I/O (such as `COM1` `0x3f8..=0x3ff`).
pub fn try_emulate_uspace_pio(upt_phys: u64, irq_stack: &mut IrqStack) -> bool {
    let rip = irq_stack.rip;
    let Some(mut op) = read_user_u8_lockfree(upt_phys, rip) else {
        return false;
    };

    let mut pos = 0u64;
    let mut pfx_66 = false;

    // Consume optional operand-size override (`0x66`) or REX (`0x40..=0x4f`) prefixes.
    for _ in 0..3 {
        if op == 0x66 {
            pfx_66 = true;
            pos += 1;
            let Some(next_b) = read_user_u8_lockfree(upt_phys, rip + pos) else {
                return false;
            };
            op = next_b;
        } else if (0x40..=0x4f).contains(&op) {
            pos += 1;
            let Some(next_b) = read_user_u8_lockfree(upt_phys, rip + pos) else {
                return false;
            };
            op = next_b;
        } else {
            break;
        }
    }

    let (is_write, size, port, insn_len): (bool, u8, u16, u64) = match op {
        0xe4..=0xe7 => {
            let Some(imm) = read_user_u8_lockfree(upt_phys, rip + pos + 1) else {
                return false;
            };
            let sz = if (op & 1) == 0 {
                1
            } else if pfx_66 {
                2
            } else {
                4
            };
            ((op & 2) != 0, sz, imm as u16, pos + 2)
        }
        0xec..=0xef => {
            let sz = if (op & 1) == 0 {
                1
            } else if pfx_66 {
                2
            } else {
                4
            };
            ((op & 2) != 0, sz, irq_stack.rdx as u16, pos + 1)
        }
        _ => return false,
    };

    if (0xcf8..=0xcfb).contains(&port) {
        if port == PCI_CONFIG_ADDR && size == 4 {
            if is_write {
                USPACE_PCI_CFG_ADDR.store(irq_stack.rax as u32, Ordering::Release);
            } else {
                irq_stack.rax = USPACE_PCI_CFG_ADDR.load(Ordering::Acquire) as u64;
            }
            irq_stack.rip = rip + insn_len;
            return true;
        }
        return false;
    }

    if (PCI_CONFIG_DATA..=PCI_CONFIG_DATA_END).contains(&port) {
        let latched = USPACE_PCI_CFG_ADDR.load(Ordering::Acquire);
        let valid = (latched & 0x8000_0000) != 0;
        let bdf = ((latched >> 8) & 0xffff) as u16;
        let hidden = !valid || is_bdf_hidden_from_userspace(bdf);

        if is_write {
            if !hidden {
                let _g = PCI_CFG_LOCK.lock(line!());
                unsafe {
                    raw_out32(PCI_CONFIG_ADDR, latched);
                    match size {
                        1 => raw_out8(port, irq_stack.rax as u8),
                        2 => raw_out16(port, irq_stack.rax as u16),
                        4 => raw_out32(port, irq_stack.rax as u32),
                        _ => return false,
                    }
                }
            }
        } else {
            let val: u32 = if hidden {
                0xffff_ffff
            } else {
                let _g = PCI_CFG_LOCK.lock(line!());
                unsafe {
                    raw_out32(PCI_CONFIG_ADDR, latched);
                    match size {
                        1 => raw_in8(port) as u32,
                        2 => raw_in16(port) as u32,
                        4 => raw_in32(port),
                        _ => return false,
                    }
                }
            };
            match size {
                1 => irq_stack.rax = (irq_stack.rax & !0xff) | ((val as u64) & 0xff),
                2 => irq_stack.rax = (irq_stack.rax & !0xffff) | ((val as u64) & 0xffff),
                4 => irq_stack.rax = val as u64,
                _ => return false,
            }
        }
        irq_stack.rip = rip + insn_len;
        return true;
    }

    // All other I/O ports (e.g. COM1 0x3f8..=0x3ff in `sys-tty` and debug port 0x80)
    // are authorized for `CAP_IO_MANAGER` threads and forwarded directly.
    if is_write {
        unsafe {
            match size {
                1 => raw_out8(port, irq_stack.rax as u8),
                2 => raw_out16(port, irq_stack.rax as u16),
                4 => raw_out32(port, irq_stack.rax as u32),
                _ => return false,
            }
        }
    } else {
        let val: u32 = unsafe {
            match size {
                1 => raw_in8(port) as u32,
                2 => raw_in16(port) as u32,
                4 => raw_in32(port),
                _ => return false,
            }
        };
        match size {
            1 => irq_stack.rax = (irq_stack.rax & !0xff) | ((val as u64) & 0xff),
            2 => irq_stack.rax = (irq_stack.rax & !0xffff) | ((val as u64) & 0xffff),
            4 => irq_stack.rax = val as u64,
            _ => return false,
        }
    }
    irq_stack.rip = rip + insn_len;
    true
}
