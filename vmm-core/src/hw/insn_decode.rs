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

//! Compact, float-free x86/x86_64 MMIO instruction decoder and guest page-table walker.
//!
//! Used when minimal Ring-0 hypervisors (Motor OS, MSHV, macOS HVF, or KVM emulation fallback)
//! surface raw [`crate::host::VmExit::MmioFault`] traps via [`VcpuCommPage`].

use crate::host::abi::{
    GPR_RAX, GPR_RBP, GPR_RBX, GPR_RCX, GPR_RDI, GPR_RSI, GPR_RSP, SYNC_REG_GPRS,
    SYNC_REG_RIP_RFLAGS, VcpuCommPage,
};
use crate::host::{HvError, HvResult, SegReg, VmEntry};
use crate::hw::msr::Efer;
use crate::hw::paging::Entry as PteFlags;
use crate::hw::reg::{Cr0, Cr4, Rflags, SegAccess};
use crate::mem::mapped::RamBus;
use crate::mem::{self, Memory};

const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const MAX_REP_BATCH: u64 = 64;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CpuMode {
    Mode16,
    Mode32,
    Mode64,
}

fn detect_cpu_mode(comm: &VcpuCommPage) -> CpuMode {
    let lma = (comm.efer & (Efer::LMA.bits() as u64)) != 0;
    let cs_access = SegAccess(comm.cs.access);
    if lma && cs_access.l_64bit() {
        CpuMode::Mode64
    } else if cs_access.db_size_32() {
        CpuMode::Mode32
    } else {
        CpuMode::Mode16
    }
}

fn eff_seg_base(comm: &VcpuCommPage, mode: CpuMode, seg: SegReg) -> u64 {
    match mode {
        CpuMode::Mode64 => match seg {
            SegReg::Fs => comm.fs_base,
            SegReg::Gs => comm.gs_base,
            _ => 0,
        },
        CpuMode::Mode16 | CpuMode::Mode32 => match seg {
            SegReg::Cs => comm.cs.base,
            SegReg::Ds => comm.ds_base,
            SegReg::Es => comm.es_base,
            SegReg::Fs => comm.fs_base,
            SegReg::Gs => comm.gs_base,
            SegReg::Ss => comm.ss_base,
            SegReg::Tr | SegReg::Ldtr => 0,
        },
    }
}

/// Translate a guest linear/virtual address (`gva`) to a guest physical address (`gpa`)
/// by walking the active x86/x86_64 guest page tables in [`RamBus`].
pub fn gva_to_gpa(ram: &RamBus, comm: &VcpuCommPage, gva: u64) -> HvResult<u64> {
    if (comm.cr0 & (Cr0::PG.bits() as u64)) == 0 {
        return Ok(gva & 0xffff_ffff);
    }

    let present = PteFlags::P.bits() as u64;
    let page_size = PteFlags::PS.bits() as u64;

    if (comm.efer & (Efer::LMA.bits() as u64)) != 0 {
        let mut table_gpa = comm.cr3 & PTE_ADDR_MASK;
        if (comm.cr4 & (Cr4::LA57.bits() as u64)) != 0 {
            let pml5_idx = (gva >> 48) & 0x1ff;
            let pml5e: u64 = ram
                .read(table_gpa + pml5_idx * 8)
                .map_err(|_| HvError::HardwareFault)?;
            if (pml5e & present) == 0 {
                return Err(HvError::HardwareFault);
            }
            table_gpa = pml5e & PTE_ADDR_MASK;
        }

        let pml4_idx = (gva >> 39) & 0x1ff;
        let pml4e: u64 = ram
            .read(table_gpa + pml4_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pml4e & present) == 0 {
            return Err(HvError::HardwareFault);
        }

        let pdpt_idx = (gva >> 30) & 0x1ff;
        let pdpte: u64 = ram
            .read((pml4e & PTE_ADDR_MASK) + pdpt_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pdpte & present) == 0 {
            return Err(HvError::HardwareFault);
        }
        if (pdpte & page_size) != 0 {
            return Ok((pdpte & 0x000f_ffff_c000_0000) | (gva & 0x3fff_ffff));
        }

        let pd_idx = (gva >> 21) & 0x1ff;
        let pde: u64 = ram
            .read((pdpte & PTE_ADDR_MASK) + pd_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pde & present) == 0 {
            return Err(HvError::HardwareFault);
        }
        if (pde & page_size) != 0 {
            return Ok((pde & 0x000f_ffff_ffe0_0000) | (gva & 0x001f_ffff));
        }

        let pt_idx = (gva >> 12) & 0x1ff;
        let pte: u64 = ram
            .read((pde & PTE_ADDR_MASK) + pt_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pte & present) == 0 {
            return Err(HvError::HardwareFault);
        }
        return Ok((pte & PTE_ADDR_MASK) | (gva & 0xfff));
    }

    if (comm.cr4 & (Cr4::PAE.bits() as u64)) != 0 {
        let gva32 = gva & 0xffff_ffff;
        let pdpt_idx = (gva32 >> 30) & 0x3;
        let pdpte: u64 = ram
            .read((comm.cr3 & 0xffff_ffe0) + pdpt_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pdpte & present) == 0 {
            return Err(HvError::HardwareFault);
        }

        let pd_idx = (gva32 >> 21) & 0x1ff;
        let pde: u64 = ram
            .read((pdpte & PTE_ADDR_MASK) + pd_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pde & present) == 0 {
            return Err(HvError::HardwareFault);
        }
        if (pde & page_size) != 0 {
            return Ok((pde & 0x000f_ffff_ffe0_0000) | (gva32 & 0x001f_ffff));
        }

        let pt_idx = (gva32 >> 12) & 0x1ff;
        let pte: u64 = ram
            .read((pde & PTE_ADDR_MASK) + pt_idx * 8)
            .map_err(|_| HvError::HardwareFault)?;
        if (pte & present) == 0 {
            return Err(HvError::HardwareFault);
        }
        return Ok((pte & PTE_ADDR_MASK) | (gva32 & 0xfff));
    }

    let gva32 = gva & 0xffff_ffff;
    let pd_idx = (gva32 >> 22) & 0x3ff;
    let pde32: u32 = ram
        .read((comm.cr3 & 0xffff_f000) + pd_idx * 4)
        .map_err(|_| HvError::HardwareFault)?;
    let pde = pde32 as u64;
    if (pde & present) == 0 {
        return Err(HvError::HardwareFault);
    }
    if (comm.cr4 & (Cr4::PSE.bits() as u64)) != 0 && (pde & page_size) != 0 {
        return Ok((pde & 0xffc0_0000) | (gva32 & 0x003f_ffff));
    }

    let pt_idx = (gva32 >> 12) & 0x3ff;
    let pte32: u32 = ram
        .read((pde & 0xffff_f000) + pt_idx * 4)
        .map_err(|_| HvError::HardwareFault)?;
    let pte = pte32 as u64;
    if (pte & present) == 0 {
        return Err(HvError::HardwareFault);
    }
    Ok((pte & 0xffff_f000) | (gva32 & 0xfff))
}

fn read_guest_linear(ram: &RamBus, comm: &VcpuCommPage, mut gva: u64, mut dst: &mut [u8]) -> HvResult<()> {
    while !dst.is_empty() {
        let page_rem = (0x1000 - ((gva & 0xfff) as usize)).min(dst.len());
        let gpa = gva_to_gpa(ram, comm, gva)?;
        ram.lock_layout()
            .read_exact_bytes(gpa, &mut dst[..page_rem])
            .map_err(|_| HvError::HardwareFault)?;
        gva = gva.wrapping_add(page_rem as u64);
        dst = &mut dst[page_rem..];
    }
    Ok(())
}

fn write_guest_linear(ram: &RamBus, comm: &VcpuCommPage, mut gva: u64, mut src: &[u8]) -> HvResult<()> {
    while !src.is_empty() {
        let page_rem = (0x1000 - ((gva & 0xfff) as usize)).min(src.len());
        let gpa = gva_to_gpa(ram, comm, gva)?;
        ram.lock_layout()
            .write_exact_bytes(gpa, &src[..page_rem])
            .map_err(|_| HvError::HardwareFault)?;
        gva = gva.wrapping_add(page_rem as u64);
        src = &src[page_rem..];
    }
    Ok(())
}

fn fetch_insn_window(
    ram: &RamBus,
    comm: &VcpuCommPage,
    mode: CpuMode,
    insn_len: u8,
    insn_bytes: &[u8; 15],
    buf: &mut [u8; 15],
) -> HvResult<usize> {
    if insn_len > 0 {
        let n = (insn_len as usize).min(15);
        buf[..n].copy_from_slice(&insn_bytes[..n]);
        return Ok(n);
    }

    let rip_gva = eff_seg_base(comm, mode, SegReg::Cs).wrapping_add(comm.rip);
    let first_len = (0x1000 - ((rip_gva & 0xfff) as usize)).min(15);
    let gpa0 = gva_to_gpa(ram, comm, rip_gva)?;
    ram.lock_layout()
        .read_exact_bytes(gpa0, &mut buf[..first_len])
        .map_err(|_| HvError::HardwareFault)?;

    if first_len < 15
        && let Ok(gpa1) = gva_to_gpa(ram, comm, rip_gva.wrapping_add(first_len as u64))
        && ram
            .lock_layout()
            .read_exact_bytes(gpa1, &mut buf[first_len..15])
            .is_ok()
    {
        return Ok(15);
    }
    Ok(first_len)
}

#[inline]
fn read_gpr_sized(comm: &VcpuCommPage, reg: u8, size: u8, rex_present: bool) -> u64 {
    match size {
        1 => {
            if !rex_present && (4..8).contains(&reg) {
                (comm.gprs[(reg - 4) as usize] >> 8) & 0xff
            } else {
                comm.gprs[reg as usize] & 0xff
            }
        }
        2 => comm.gprs[reg as usize] & 0xffff,
        4 => comm.gprs[reg as usize] & 0xffff_ffff,
        8 => comm.gprs[reg as usize],
        _ => 0,
    }
}

#[inline]
fn write_gpr_sized(comm: &mut VcpuCommPage, reg: u8, size: u8, rex_present: bool, val: u64) {
    match size {
        1 => {
            if !rex_present && (4..8).contains(&reg) {
                let dst = &mut comm.gprs[(reg - 4) as usize];
                *dst = (*dst & !0xff00) | ((val & 0xff) << 8);
            } else {
                let dst = &mut comm.gprs[reg as usize];
                *dst = (*dst & !0xff) | (val & 0xff);
            }
        }
        2 => {
            let dst = &mut comm.gprs[reg as usize];
            *dst = (*dst & !0xffff) | (val & 0xffff);
        }
        4 => {
            // In 64-bit x86, 32-bit GPR writes zero-extend to 64 bits.
            comm.gprs[reg as usize] = val & 0xffff_ffff;
        }
        8 => {
            comm.gprs[reg as usize] = val;
        }
        _ => {}
    }
    comm.dirty_regs |= SYNC_REG_GPRS;
}

#[inline]
fn mask_size(val: u64, size: u8) -> u64 {
    match size {
        1 => val & 0xff,
        2 => val & 0xffff,
        4 => val & 0xffff_ffff,
        _ => val,
    }
}

fn update_logic_flags(comm: &mut VcpuCommPage, res: u64, size: u8) {
    let r = mask_size(res, size);
    let sign_bit = 1u64 << (size * 8 - 1);
    let status_mask = (Rflags::CF
        | Rflags::PF
        | Rflags::AF
        | Rflags::ZF
        | Rflags::SF
        | Rflags::OF)
        .bits() as u64;

    let mut flags = (comm.rflags & !status_mask) | (Rflags::RESERVED_1.bits() as u64);
    if r == 0 {
        flags |= Rflags::ZF.bits() as u64;
    }
    if (r & sign_bit) != 0 {
        flags |= Rflags::SF.bits() as u64;
    }
    if ((r as u8).count_ones() & 1) == 0 {
        flags |= Rflags::PF.bits() as u64;
    }
    comm.rflags = flags;
    comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
}

fn update_sub_flags(comm: &mut VcpuCommPage, lhs: u64, rhs: u64, size: u8) -> u64 {
    let a = mask_size(lhs, size);
    let b = mask_size(rhs, size);
    let r = mask_size(a.wrapping_sub(b), size);
    let sign_bit = 1u64 << (size * 8 - 1);
    let status_mask = (Rflags::CF
        | Rflags::PF
        | Rflags::AF
        | Rflags::ZF
        | Rflags::SF
        | Rflags::OF)
        .bits() as u64;

    let mut flags = (comm.rflags & !status_mask) | (Rflags::RESERVED_1.bits() as u64);
    if a < b {
        flags |= Rflags::CF.bits() as u64;
    }
    if r == 0 {
        flags |= Rflags::ZF.bits() as u64;
    }
    if (r & sign_bit) != 0 {
        flags |= Rflags::SF.bits() as u64;
    }
    if ((r as u8).count_ones() & 1) == 0 {
        flags |= Rflags::PF.bits() as u64;
    }
    if (((a ^ b) & (a ^ r)) & sign_bit) != 0 {
        flags |= Rflags::OF.bits() as u64;
    }
    if ((a ^ b ^ r) & 0x10) != 0 {
        flags |= Rflags::AF.bits() as u64;
    }
    comm.rflags = flags;
    comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
    r
}

fn update_add_flags(comm: &mut VcpuCommPage, lhs: u64, rhs: u64, size: u8) -> u64 {
    let a = mask_size(lhs, size);
    let b = mask_size(rhs, size);
    let r = mask_size(a.wrapping_add(b), size);
    let sign_bit = 1u64 << (size * 8 - 1);
    let status_mask = (Rflags::CF
        | Rflags::PF
        | Rflags::AF
        | Rflags::ZF
        | Rflags::SF
        | Rflags::OF)
        .bits() as u64;

    let mut flags = (comm.rflags & !status_mask) | (Rflags::RESERVED_1.bits() as u64);
    if r < a {
        flags |= Rflags::CF.bits() as u64;
    }
    if r == 0 {
        flags |= Rflags::ZF.bits() as u64;
    }
    if (r & sign_bit) != 0 {
        flags |= Rflags::SF.bits() as u64;
    }
    if ((r as u8).count_ones() & 1) == 0 {
        flags |= Rflags::PF.bits() as u64;
    }
    if ((!(a ^ b) & (a ^ r)) & sign_bit) != 0 {
        flags |= Rflags::OF.bits() as u64;
    }
    if ((a ^ b ^ r) & 0x10) != 0 {
        flags |= Rflags::AF.bits() as u64;
    }
    comm.rflags = flags;
    comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
    r
}

struct InsnCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> InsnCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn u8(&mut self) -> HvResult<u8> {
        let b = *self.bytes.get(self.pos).ok_or(HvError::InvalidParam)?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> HvResult<u16> {
        if self.pos + 2 > self.bytes.len() {
            return Err(HvError::InvalidParam);
        }
        let v = u16::from_le_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> HvResult<u32> {
        if self.pos + 4 > self.bytes.len() {
            return Err(HvError::InvalidParam);
        }
        let v = u32::from_le_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn u64(&mut self) -> HvResult<u64> {
        if self.pos + 8 > self.bytes.len() {
            return Err(HvError::InvalidParam);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(arr))
    }
}

struct DecodedMemOp {
    reg: u8,
    reg_low3: u8,
    offset_without_rip: u64,
    rip_relative: bool,
    default_seg: SegReg,
}

fn decode_modrm_mem(
    cur: &mut InsnCursor<'_>,
    comm: &VcpuCommPage,
    mode: CpuMode,
    addr_bits: u8,
    rex: u8,
) -> HvResult<DecodedMemOp> {
    let modrm = cur.u8()?;
    let mod_bits = modrm >> 6;
    if mod_bits == 3 {
        return Err(HvError::InvalidParam);
    }

    let rex_r = (rex & 0x04) != 0;
    let rex_x = (rex & 0x02) != 0;
    let rex_b = (rex & 0x01) != 0;

    let reg_low3 = (modrm >> 3) & 7;
    let reg = reg_low3 | (u8::from(rex_r) << 3);
    let rm_low = modrm & 7;
    let rm = rm_low | (u8::from(rex_b) << 3);

    if addr_bits == 16 {
        let mut default_seg = SegReg::Ds;
        let base_idx: u16 = match rm_low {
            0 => (comm.gprs[GPR_RBX] as u16).wrapping_add(comm.gprs[GPR_RSI] as u16),
            1 => (comm.gprs[GPR_RBX] as u16).wrapping_add(comm.gprs[GPR_RDI] as u16),
            2 => {
                default_seg = SegReg::Ss;
                (comm.gprs[GPR_RBP] as u16).wrapping_add(comm.gprs[GPR_RSI] as u16)
            }
            3 => {
                default_seg = SegReg::Ss;
                (comm.gprs[GPR_RBP] as u16).wrapping_add(comm.gprs[GPR_RDI] as u16)
            }
            4 => comm.gprs[GPR_RSI] as u16,
            5 => comm.gprs[GPR_RDI] as u16,
            6 => {
                if mod_bits == 0 {
                    let disp16 = cur.u16()?;
                    return Ok(DecodedMemOp {
                        reg,
                        reg_low3,
                        offset_without_rip: disp16 as u64,
                        rip_relative: false,
                        default_seg,
                    });
                }
                default_seg = SegReg::Ss;
                comm.gprs[GPR_RBP] as u16
            }
            7 => comm.gprs[GPR_RBX] as u16,
            _ => unreachable!(),
        };
        let disp: i16 = match mod_bits {
            0 => 0,
            1 => (cur.u8()? as i8) as i16,
            2 => cur.u16()? as i16,
            _ => unreachable!(),
        };
        return Ok(DecodedMemOp {
            reg,
            reg_low3,
            offset_without_rip: base_idx.wrapping_add(disp as u16) as u64,
            rip_relative: false,
            default_seg,
        });
    }

    let mut default_seg = SegReg::Ds;
    let mut rip_relative = false;
    let base_plus_index = if rm_low == 4 {
        let sib = cur.u8()?;
        let scale = 1u64 << (sib >> 6);
        let index_reg = ((sib >> 3) & 7) | (u8::from(rex_x) << 3);
        let index_val = if index_reg as usize == GPR_RSP {
            0
        } else {
            comm.gprs[index_reg as usize].wrapping_mul(scale)
        };

        let base_low = sib & 7;
        let base_reg = base_low | (u8::from(rex_b) << 3);
        let (base_val, disp) = if mod_bits == 0 && base_low == 5 {
            (0u64, (cur.u32()? as i32) as i64)
        } else {
            if base_reg as usize == GPR_RSP || base_reg as usize == GPR_RBP {
                default_seg = SegReg::Ss;
            }
            let disp = match mod_bits {
                0 => 0i64,
                1 => (cur.u8()? as i8) as i64,
                2 => (cur.u32()? as i32) as i64,
                _ => unreachable!(),
            };
            (comm.gprs[base_reg as usize], disp)
        };
        base_val.wrapping_add(index_val).wrapping_add(disp as u64)
    } else if mod_bits == 0 && rm_low == 5 {
        let disp = (cur.u32()? as i32) as i64;
        if mode == CpuMode::Mode64 {
            rip_relative = true;
        }
        disp as u64
    } else {
        if rm as usize == GPR_RSP || rm as usize == GPR_RBP {
            default_seg = SegReg::Ss;
        }
        let disp = match mod_bits {
            0 => 0i64,
            1 => (cur.u8()? as i8) as i64,
            2 => (cur.u32()? as i32) as i64,
            _ => unreachable!(),
        };
        comm.gprs[rm as usize].wrapping_add(disp as u64)
    };

    Ok(DecodedMemOp {
        reg,
        reg_low3,
        offset_without_rip: base_plus_index,
        rip_relative,
        default_seg,
    })
}

fn finalize_mem_gva(
    mem_op: &DecodedMemOp,
    comm: &VcpuCommPage,
    mode: CpuMode,
    addr_bits: u8,
    seg_override: Option<SegReg>,
    final_insn_len: usize,
) -> u64 {
    let mut eff = mem_op.offset_without_rip;
    if mem_op.rip_relative {
        eff = comm
            .rip
            .wrapping_add(final_insn_len as u64)
            .wrapping_add(eff);
    }
    let masked = match addr_bits {
        16 => eff & 0xffff,
        32 => eff & 0xffff_ffff,
        _ => eff,
    };
    let seg = seg_override.unwrap_or(mem_op.default_seg);
    eff_seg_base(comm, mode, seg).wrapping_add(masked)
}

#[inline]
fn resolve_mmio_gpa(
    ram: &RamBus,
    comm: &VcpuCommPage,
    fault_gpa: u64,
    fault_gva: Option<u64>,
    decoded_gva: u64,
) -> Result<u64, mem::Error> {
    if fault_gpa != 0 {
        return Ok(fault_gpa);
    }
    let gva = fault_gva.unwrap_or(decoded_gva);
    gva_to_gpa(ram, comm, gva).map_err(mem::Error::Hv)
}

#[inline]
fn mmio_read_val(memory: &Memory, gpa: u64, size: u8) -> Result<u64, mem::Error> {
    match memory.handle_mmio(gpa, None, size)? {
        VmEntry::Mmio { data } => Ok(mask_size(data, size)),
        _ => Ok(0),
    }
}

#[inline]
fn read_imm_op(cur: &mut InsnCursor<'_>, op_size: u8) -> Result<u64, mem::Error> {
    match op_size {
        1 => Ok(cur.u8().map_err(mem::Error::Hv)? as u64),
        2 => Ok(cur.u16().map_err(mem::Error::Hv)? as u64),
        4 => Ok(cur.u32().map_err(mem::Error::Hv)? as u64),
        8 => Ok(((cur.u32().map_err(mem::Error::Hv)? as i32) as i64) as u64),
        _ => Err(mem::Error::Hv(HvError::InvalidParam)),
    }
}

#[inline]
fn read_addr_reg(comm: &VcpuCommPage, reg: usize, addr_bits: u8) -> u64 {
    match addr_bits {
        16 => comm.gprs[reg] & 0xffff,
        32 => comm.gprs[reg] & 0xffff_ffff,
        _ => comm.gprs[reg],
    }
}

#[inline]
fn write_addr_reg(comm: &mut VcpuCommPage, reg: usize, addr_bits: u8, val: u64) {
    match addr_bits {
        16 => {
            comm.gprs[reg] = (comm.gprs[reg] & !0xffff) | (val & 0xffff);
        }
        32 => {
            comm.gprs[reg] = val & 0xffff_ffff;
        }
        _ => {
            comm.gprs[reg] = val;
        }
    }
    comm.dirty_regs |= SYNC_REG_GPRS;
}

/// Decode and emulate one faulting x86/x86_64 MMIO instruction against `memory`,
/// updating `comm.gprs`, `comm.rflags`, `comm.rip`, and `comm.dirty_regs` in place.
#[allow(clippy::too_many_arguments)]
pub fn emulate_mmio_fault(
    memory: &Memory,
    comm: &mut VcpuCommPage,
    fault_gpa: u64,
    fault_gva: Option<u64>,
    is_write: bool,
    insn_len: u8,
    insn_bytes: &[u8; 15],
) -> Result<VmEntry, mem::Error> {
    let mode = detect_cpu_mode(comm);
    let ram = memory.ram_bus();
    let mut fetched = [0u8; 15];
    let valid_len =
        fetch_insn_window(&ram, comm, mode, insn_len, insn_bytes, &mut fetched).map_err(mem::Error::Hv)?;
    let mut cur = InsnCursor::new(&fetched[..valid_len]);

    let mut op_size_override = false;
    let mut addr_size_override = false;
    let mut has_rep = false;
    let mut seg_override: Option<SegReg> = None;
    let mut rex: Option<u8> = None;

    let opcode = loop {
        let b = cur.u8().map_err(mem::Error::Hv)?;
        match b {
            0x66 => {
                op_size_override = true;
                rex = None;
            }
            0x67 => {
                addr_size_override = true;
                rex = None;
            }
            0xf0 => {
                rex = None;
            }
            0xf2 | 0xf3 => {
                has_rep = true;
                rex = None;
            }
            0x26 => {
                seg_override = Some(SegReg::Es);
                rex = None;
            }
            0x2e => {
                seg_override = Some(SegReg::Cs);
                rex = None;
            }
            0x36 => {
                seg_override = Some(SegReg::Ss);
                rex = None;
            }
            0x3e => {
                seg_override = Some(SegReg::Ds);
                rex = None;
            }
            0x64 => {
                seg_override = Some(SegReg::Fs);
                rex = None;
            }
            0x65 => {
                seg_override = Some(SegReg::Gs);
                rex = None;
            }
            0x40..=0x4f if mode == CpuMode::Mode64 => {
                rex = Some(b);
            }
            _ => break b,
        }
    };

    let rex_present = rex.is_some();
    let rex_byte = rex.unwrap_or(0);
    let rex_w = (rex_byte & 0x08) != 0;

    let op_size: u8 = match mode {
        CpuMode::Mode64 => {
            if rex_w {
                8
            } else if op_size_override {
                2
            } else {
                4
            }
        }
        CpuMode::Mode32 => {
            if op_size_override {
                2
            } else {
                4
            }
        }
        CpuMode::Mode16 => {
            if op_size_override {
                4
            } else {
                2
            }
        }
    };

    let addr_bits: u8 = match mode {
        CpuMode::Mode64 => {
            if addr_size_override {
                32
            } else {
                64
            }
        }
        CpuMode::Mode32 => {
            if addr_size_override {
                16
            } else {
                32
            }
        }
        CpuMode::Mode16 => {
            if addr_size_override {
                32
            } else {
                16
            }
        }
    };

    match opcode {
        // MOV r/m, r (0x88 8-bit, 0x89 16/32/64-bit)
        0x88 | 0x89 => {
            let sz = if opcode == 0x88 { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let val = read_gpr_sized(comm, mem_op.reg, sz, rex_present);
            let entry = memory.handle_mmio(gpa, Some(val), sz)?;
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(entry)
        }

        // MOV r, r/m (0x8a 8-bit, 0x8b 16/32/64-bit)
        0x8a | 0x8b => {
            let sz = if opcode == 0x8a { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let val = mmio_read_val(memory, gpa, sz)?;
            write_gpr_sized(comm, mem_op.reg, sz, rex_present, val);
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(VmEntry::None)
        }

        // MOV r/m, imm (0xc6 /0 imm8, 0xc7 /0 imm16/32)
        0xc6 | 0xc7 => {
            let sz = if opcode == 0xc6 { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            if mem_op.reg_low3 != 0 {
                return Err(mem::Error::Hv(HvError::Unsupported));
            }
            let imm = read_imm_op(&mut cur, sz)?;
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let entry = memory.handle_mmio(gpa, Some(mask_size(imm, sz)), sz)?;
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(entry)
        }

        // MOV AL/AX/EAX/RAX, moffs (0xa0, 0xa1) & MOV moffs, AL/AX/EAX/RAX (0xa2, 0xa3)
        0xa0..=0xa3 => {
            let sz = if (opcode & 1) == 0 { 1 } else { op_size };
            let moffs = match addr_bits {
                16 => cur.u16().map_err(mem::Error::Hv)? as u64,
                32 => cur.u32().map_err(mem::Error::Hv)? as u64,
                _ => cur.u64().map_err(mem::Error::Hv)?,
            };
            let total_len = cur.pos;
            let seg = seg_override.unwrap_or(SegReg::Ds);
            let gva = eff_seg_base(comm, mode, seg).wrapping_add(moffs);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;

            let entry = if opcode <= 0xa1 {
                let val = mmio_read_val(memory, gpa, sz)?;
                write_gpr_sized(comm, GPR_RAX as u8, sz, rex_present, val);
                VmEntry::None
            } else {
                let val = read_gpr_sized(comm, GPR_RAX as u8, sz, rex_present);
                memory.handle_mmio(gpa, Some(val), sz)?
            };
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(entry)
        }

        // MOVSXD r32/64, r/m32 (0x63 in 64-bit mode)
        0x63 if mode == CpuMode::Mode64 => {
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let raw32 = mmio_read_val(memory, gpa, 4)? as u32;
            let sext = ((raw32 as i32) as i64) as u64;
            write_gpr_sized(comm, mem_op.reg, op_size, rex_present, sext);
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(VmEntry::None)
        }

        // Two-byte escape (0x0f): MOVZX (0xb6, 0xb7) & MOVSX (0xbe, 0xbf)
        0x0f => {
            let op2 = cur.u8().map_err(mem::Error::Hv)?;
            match op2 {
                0xb6 | 0xb7 | 0xbe | 0xbf => {
                    let src_sz: u8 = if (op2 & 1) == 0 { 1 } else { 2 };
                    let sign_ext = op2 >= 0xbe;
                    let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                        .map_err(mem::Error::Hv)?;
                    let total_len = cur.pos;
                    let gva =
                        finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
                    let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
                    let raw = mmio_read_val(memory, gpa, src_sz)?;
                    let ext = if sign_ext {
                        if src_sz == 1 {
                            (((raw as u8) as i8) as i64) as u64
                        } else {
                            (((raw as u16) as i16) as i64) as u64
                        }
                    } else {
                        raw
                    };
                    write_gpr_sized(comm, mem_op.reg, op_size, rex_present, ext);
                    comm.rip = comm.rip.wrapping_add(total_len as u64);
                    comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
                    Ok(VmEntry::None)
                }
                _ => Err(mem::Error::Hv(HvError::Unsupported)),
            }
        }

        // XCHG r/m, r (0x86 8-bit, 0x87 16/32/64-bit)
        0x86 | 0x87 => {
            let sz = if opcode == 0x86 { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let old_mem = mmio_read_val(memory, gpa, sz)?;
            let old_reg = read_gpr_sized(comm, mem_op.reg, sz, rex_present);
            let entry = memory.handle_mmio(gpa, Some(old_reg), sz)?;
            write_gpr_sized(comm, mem_op.reg, sz, rex_present, old_mem);
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(entry)
        }

        // ALU r/m, r and r, r/m:
        // ADD (0x00..0x03), OR (0x08..0x0b), AND (0x20..0x23), SUB (0x28..0x2b),
        // XOR (0x30..0x33), CMP (0x38..0x3b), TEST (0x84, 0x85)
        0x00..=0x03
        | 0x08..=0x0b
        | 0x20..=0x23
        | 0x28..=0x2b
        | 0x30..=0x33
        | 0x38..=0x3b
        | 0x84
        | 0x85 => {
            let sz = if (opcode & 1) == 0 { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let mem_val = mmio_read_val(memory, gpa, sz)?;
            let reg_val = read_gpr_sized(comm, mem_op.reg, sz, rex_present);

            let entry = if opcode == 0x84 || opcode == 0x85 {
                update_logic_flags(comm, mem_val & reg_val, sz);
                VmEntry::None
            } else {
                let dir_reg_dst = (opcode & 2) != 0;
                let (lhs, rhs) = if dir_reg_dst {
                    (reg_val, mem_val)
                } else {
                    (mem_val, reg_val)
                };
                let group = opcode & 0xf8;
                let (res, writeback) = match group {
                    0x00 => (update_add_flags(comm, lhs, rhs, sz), true),
                    0x08 => {
                        let r = mask_size(lhs | rhs, sz);
                        update_logic_flags(comm, r, sz);
                        (r, true)
                    }
                    0x20 => {
                        let r = mask_size(lhs & rhs, sz);
                        update_logic_flags(comm, r, sz);
                        (r, true)
                    }
                    0x28 => (update_sub_flags(comm, lhs, rhs, sz), true),
                    0x30 => {
                        let r = mask_size(lhs ^ rhs, sz);
                        update_logic_flags(comm, r, sz);
                        (r, true)
                    }
                    0x38 => (update_sub_flags(comm, lhs, rhs, sz), false),
                    _ => unreachable!(),
                };
                if !writeback {
                    VmEntry::None
                } else if dir_reg_dst {
                    write_gpr_sized(comm, mem_op.reg, sz, rex_present, res);
                    VmEntry::None
                } else {
                    memory.handle_mmio(gpa, Some(res), sz)?
                }
            };

            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(entry)
        }

        // Immediate ALU Group 1: 0x80 (r/m8, imm8), 0x81 (r/m, imm16/32), 0x83 (r/m, simm8)
        0x80 | 0x81 | 0x83 => {
            let sz = if opcode == 0x80 { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            let imm = if opcode == 0x83 {
                let b = cur.u8().map_err(mem::Error::Hv)? as i8;
                mask_size((b as i64) as u64, sz)
            } else {
                mask_size(read_imm_op(&mut cur, sz)?, sz)
            };
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let lhs = mmio_read_val(memory, gpa, sz)?;

            let entry = match mem_op.reg_low3 {
                0 => {
                    let res = update_add_flags(comm, lhs, imm, sz);
                    memory.handle_mmio(gpa, Some(res), sz)?
                }
                1 => {
                    let res = mask_size(lhs | imm, sz);
                    update_logic_flags(comm, res, sz);
                    memory.handle_mmio(gpa, Some(res), sz)?
                }
                4 => {
                    let res = mask_size(lhs & imm, sz);
                    update_logic_flags(comm, res, sz);
                    memory.handle_mmio(gpa, Some(res), sz)?
                }
                5 => {
                    let res = update_sub_flags(comm, lhs, imm, sz);
                    memory.handle_mmio(gpa, Some(res), sz)?
                }
                6 => {
                    let res = mask_size(lhs ^ imm, sz);
                    update_logic_flags(comm, res, sz);
                    memory.handle_mmio(gpa, Some(res), sz)?
                }
                7 => {
                    let _ = update_sub_flags(comm, lhs, imm, sz);
                    VmEntry::None
                }
                _ => return Err(mem::Error::Hv(HvError::Unsupported)),
            };

            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(entry)
        }

        // Unary Group 3: TEST r/m, imm (0xf6 /0|/1, 0xf7 /0|/1)
        0xf6 | 0xf7 => {
            let sz = if opcode == 0xf6 { 1 } else { op_size };
            let mem_op = decode_modrm_mem(&mut cur, comm, mode, addr_bits, rex_byte)
                .map_err(mem::Error::Hv)?;
            if mem_op.reg_low3 > 1 {
                return Err(mem::Error::Hv(HvError::Unsupported));
            }
            let imm = mask_size(read_imm_op(&mut cur, sz)?, sz);
            let total_len = cur.pos;
            let gva = finalize_mem_gva(&mem_op, comm, mode, addr_bits, seg_override, total_len);
            let gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, gva)?;
            let lhs = mmio_read_val(memory, gpa, sz)?;
            update_logic_flags(comm, lhs & imm, sz);
            comm.rip = comm.rip.wrapping_add(total_len as u64);
            comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            Ok(VmEntry::None)
        }

        // STOSB / STOSW / STOSD / STOSQ (0xaa, 0xab)
        0xaa | 0xab => {
            let sz = if opcode == 0xaa { 1 } else { op_size };
            let total_len = cur.pos;
            let val = read_gpr_sized(comm, GPR_RAX as u8, sz, rex_present);
            let df = (comm.rflags & (Rflags::DF.bits() as u64)) != 0;
            let step: i64 = if df { -(sz as i64) } else { sz as i64 };

            let mut count = if has_rep {
                read_addr_reg(comm, GPR_RCX, addr_bits)
            } else {
                1
            };
            if has_rep && count == 0 {
                comm.rip = comm.rip.wrapping_add(total_len as u64);
                comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
                return Ok(VmEntry::None);
            }

            let mut di = read_addr_reg(comm, GPR_RDI, addr_bits);
            let first_gva = eff_seg_base(comm, mode, SegReg::Es).wrapping_add(di);
            let mut cur_gpa = resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, first_gva)?;
            let start_page = cur_gpa & !0xfff;
            let mut iters = 0u64;
            let mut last_entry = VmEntry::None;

            while count > 0 && iters < MAX_REP_BATCH {
                if iters > 0 && ((cur_gpa & !0xfff) != start_page || ((cur_gpa + (sz as u64) - 1) & !0xfff) != start_page) {
                    break;
                }
                last_entry = memory.handle_mmio(cur_gpa, Some(val), sz)?;
                di = di.wrapping_add(step as u64);
                count -= 1;
                iters += 1;
                if matches!(last_entry, VmEntry::Shutdown | VmEntry::Reboot) || !has_rep {
                    break;
                }
                cur_gpa = cur_gpa.wrapping_add(step as u64);
            }

            write_addr_reg(comm, GPR_RDI, addr_bits, di);
            if has_rep {
                write_addr_reg(comm, GPR_RCX, addr_bits, count);
            }
            if !has_rep || count == 0 {
                comm.rip = comm.rip.wrapping_add(total_len as u64);
                comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            }
            Ok(last_entry)
        }

        // MOVSB / MOVSW / MOVSD / MOVSQ (0xa4, 0xa5)
        0xa4 | 0xa5 => {
            let sz = if opcode == 0xa4 { 1 } else { op_size };
            let total_len = cur.pos;
            let df = (comm.rflags & (Rflags::DF.bits() as u64)) != 0;
            let step: i64 = if df { -(sz as i64) } else { sz as i64 };

            let mut count = if has_rep {
                read_addr_reg(comm, GPR_RCX, addr_bits)
            } else {
                1
            };
            if has_rep && count == 0 {
                comm.rip = comm.rip.wrapping_add(total_len as u64);
                comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
                return Ok(VmEntry::None);
            }

            let src_seg = seg_override.unwrap_or(SegReg::Ds);
            let mut si = read_addr_reg(comm, GPR_RSI, addr_bits);
            let mut di = read_addr_reg(comm, GPR_RDI, addr_bits);

            let fault_side_gva = if is_write {
                eff_seg_base(comm, mode, SegReg::Es).wrapping_add(di)
            } else {
                eff_seg_base(comm, mode, src_seg).wrapping_add(si)
            };
            let mut cur_mmio_gpa =
                resolve_mmio_gpa(&ram, comm, fault_gpa, fault_gva, fault_side_gva)?;
            let start_page = cur_mmio_gpa & !0xfff;
            let mut iters = 0u64;
            let mut last_entry = VmEntry::None;

            while count > 0 && iters < MAX_REP_BATCH {
                if iters > 0
                    && ((cur_mmio_gpa & !0xfff) != start_page
                        || ((cur_mmio_gpa + (sz as u64) - 1) & !0xfff) != start_page)
                {
                    break;
                }
                if is_write {
                    let src_gva = eff_seg_base(comm, mode, src_seg)
                        .wrapping_add(mask_addr(si, addr_bits));
                    let mut buf = [0u8; 8];
                    read_guest_linear(&ram, comm, src_gva, &mut buf[..sz as usize])
                        .map_err(mem::Error::Hv)?;
                    let val = mask_size(u64::from_le_bytes(buf), sz);
                    last_entry = memory.handle_mmio(cur_mmio_gpa, Some(val), sz)?;
                } else {
                    let val = mmio_read_val(memory, cur_mmio_gpa, sz)?;
                    let dst_gva = eff_seg_base(comm, mode, SegReg::Es)
                        .wrapping_add(mask_addr(di, addr_bits));
                    let bytes = val.to_le_bytes();
                    write_guest_linear(&ram, comm, dst_gva, &bytes[..sz as usize])
                        .map_err(mem::Error::Hv)?;
                }

                si = si.wrapping_add(step as u64);
                di = di.wrapping_add(step as u64);
                count -= 1;
                iters += 1;
                if matches!(last_entry, VmEntry::Shutdown | VmEntry::Reboot) || !has_rep {
                    break;
                }
                cur_mmio_gpa = cur_mmio_gpa.wrapping_add(step as u64);
            }

            write_addr_reg(comm, GPR_RSI, addr_bits, si);
            write_addr_reg(comm, GPR_RDI, addr_bits, di);
            if has_rep {
                write_addr_reg(comm, GPR_RCX, addr_bits, count);
            }
            if !has_rep || count == 0 {
                comm.rip = comm.rip.wrapping_add(total_len as u64);
                comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
            }
            Ok(last_entry)
        }

        _ => Err(mem::Error::Hv(HvError::Unsupported)),
    }
}

#[inline]
fn mask_addr(val: u64, addr_bits: u8) -> u64 {
    match addr_bits {
        16 => val & 0xffff,
        32 => val & 0xffff_ffff,
        _ => val,
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use crate::host::abi::{
        GPR_R8, GPR_R9, GPR_RAX, GPR_RBX, GPR_RCX, GPR_RDI, GPR_RDX, GPR_RSI, GPR_RSP,
        RawSegReg, SYNC_REG_GPRS, SYNC_REG_RIP_RFLAGS, VcpuCommPage,
    };
    use crate::host::test::FakeHost;
    use crate::host::VmEntry;
    use crate::hw::msr::Efer;
    use crate::hw::paging::Entry as PteFlags;
    use crate::hw::reg::{Cr0, Cr4, Rflags};
    use crate::mem::mmio::Mmio;
    use crate::mem::{AddrOpt, MemRegion, MemRegionType, Memory, Result as MemResult};
    use crate::sync::Mutex;

    use super::{emulate_mmio_fault, gva_to_gpa};

    const MMIO_BASE: u64 = 0x8000_0000;

    #[derive(Debug)]
    struct ScratchMmio {
        buf: Mutex<[u8; 256]>,
    }

    impl ScratchMmio {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                buf: Mutex::new([0u8; 256]),
            })
        }
    }

    impl Mmio for ScratchMmio {
        fn size(&self) -> usize {
            0x1000
        }

        fn read(&self, offset: usize, size: u8) -> MemResult<u64> {
            let buf = self.buf.lock();
            let mut raw = [0u8; 8];
            let n = size as usize;
            raw[..n].copy_from_slice(&buf[offset..offset + n]);
            Ok(u64::from_le_bytes(raw))
        }

        fn write(&self, offset: usize, size: u8, val: u64) -> MemResult<()> {
            let mut buf = self.buf.lock();
            let raw = val.to_le_bytes();
            let n = size as usize;
            buf[offset..offset + n].copy_from_slice(&raw[..n]);
            Ok(())
        }
    }

    fn comm_64bit() -> VcpuCommPage {
        VcpuCommPage {
            rip: 0xffff_ffff_8100_1000,
            rflags: Rflags::RESERVED_1.bits() as u64,
            cr0: (Cr0::PE | Cr0::PG).bits() as u64,
            cr4: Cr4::PAE.bits() as u64,
            efer: (Efer::LME | Efer::LMA).bits() as u64,
            cs: RawSegReg {
                base: 0,
                limit: 0xffff_ffff,
                access: 0xa09b, // L=1 (bit 13), P=1, S=1, code
                selector: 0x10,
                _pad: [0; 6],
            },
            ..Default::default()
        }
    }

    fn pad_insn(slice: &[u8]) -> (u8, [u8; 15]) {
        let mut out = [0u8; 15];
        out[..slice.len()].copy_from_slice(slice);
        (slice.len() as u8, out)
    }

    fn setup_mem_with_mmio() -> (Memory, Arc<ScratchMmio>) {
        let hv = FakeHost::new_arc();
        let mem = Memory::new(hv);
        let mmio = ScratchMmio::new();
        mem.add_region(
            AddrOpt::Fixed(MMIO_BASE),
            Arc::new(MemRegion::with_emulated(
                mmio.clone(),
                MemRegionType::Reserved,
            )),
        )
        .unwrap();
        (mem, mmio)
    }

    #[test]
    fn test_mov_loads_stores_and_register_subfields() {
        let (mem, mmio) = setup_mem_with_mmio();
        let mut comm = comm_64bit();

        // 1. `mov dword [rdi], eax` (0x89 0x07) -> write 0xdead_beef
        comm.gprs[GPR_RDI] = MMIO_BASE + 0x10;
        comm.gprs[GPR_RAX] = 0x1111_2222_dead_beef;
        let (len, bytes) = pad_insn(&[0x89, 0x07]);
        assert_eq!(
            emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x10, None, true, len, &bytes).unwrap(),
            VmEntry::None
        );
        assert_eq!(mmio.read(0x10, 4).unwrap(), 0xdead_beef);
        assert_eq!(comm.rip, 0xffff_ffff_8100_1002);

        // 2. `mov r8d, dword [rdi]` (0x44 0x8b 0x07) -> 32-bit load zero-extends upper 32 bits!
        comm.gprs[GPR_R8] = 0xffff_ffff_0000_0000;
        comm.dirty_regs = 0;
        let (len, bytes) = pad_insn(&[0x44, 0x8b, 0x07]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x10, None, false, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_R8], 0x0000_0000_dead_beef);
        assert_eq!(
            comm.dirty_regs & (SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS),
            SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS
        );

        // 3. High-byte AH (`mov [rdi], ah` -> 0x88 0x27 without REX) vs SPL (`0x40 0x88 0x27` with REX)
        comm.gprs[GPR_RAX] = 0x0000_0000_0000_5a11;
        comm.gprs[GPR_RSP] = 0x0000_0000_0000_00c3;
        let (len, bytes) = pad_insn(&[0x88, 0x27]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x20, None, true, len, &bytes).unwrap();
        assert_eq!(mmio.read(0x20, 1).unwrap(), 0x5a);

        let (len, bytes) = pad_insn(&[0x40, 0x88, 0x27]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x21, None, true, len, &bytes).unwrap();
        assert_eq!(mmio.read(0x21, 1).unwrap(), 0xc3);

        // 4. `mov qword [rdi + 0x28], -0x10` (`0x48 0xc7 0x47 0x28 0xf0 0xff 0xff 0xff`)
        comm.gprs[GPR_RDI] = MMIO_BASE;
        let (len, bytes) = pad_insn(&[0x48, 0xc7, 0x47, 0x28, 0xf0, 0xff, 0xff, 0xff]);
        emulate_mmio_fault(&mem, &mut comm, 0, None, true, len, &bytes).unwrap_err(); // PG=1 w/o PT when gpa=0
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x28, None, true, len, &bytes).unwrap();
        assert_eq!(mmio.read(0x28, 8).unwrap(), 0xffff_ffff_ffff_fff0);

        // 5. `mov eax, [0x80000010]` moffs64 (`0xa1` + 8-byte addr)
        let mut moffs_insn = [0u8; 9];
        moffs_insn[0] = 0xa1;
        moffs_insn[1..9].copy_from_slice(&(MMIO_BASE + 0x10).to_le_bytes());
        comm.gprs[GPR_RAX] = 0x9999_0000_0000_0000;
        let (len, bytes) = pad_insn(&moffs_insn);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x10, None, false, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_RAX], 0xdead_beef);
    }

    #[test]
    fn test_movzx_movsx_and_movsxd() {
        let (mem, mmio) = setup_mem_with_mmio();
        let mut comm = comm_64bit();

        mmio.write(0x0, 1, 0x85).unwrap();
        mmio.write(0x4, 2, 0x8001).unwrap();
        mmio.write(0x8, 4, 0x8000_0002).unwrap();

        // `movzx rax, byte [rbx]` -> `0x48 0x0f 0xb6 0x03`
        comm.gprs[GPR_RBX] = MMIO_BASE;
        let (len, bytes) = pad_insn(&[0x48, 0x0f, 0xb6, 0x03]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE, None, false, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_RAX], 0x85);

        // `movsx rax, byte [rbx]` -> `0x48 0x0f 0xbe 0x03`
        let (len, bytes) = pad_insn(&[0x48, 0x0f, 0xbe, 0x03]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE, None, false, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_RAX], 0xffff_ffff_ffff_ff85);

        // `movsx r9, word [rbx + 4]` -> `0x4c 0x0f 0xbf 0x4b 0x04`
        let (len, bytes) = pad_insn(&[0x4c, 0x0f, 0xbf, 0x4b, 0x04]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 4, None, false, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_R9], 0xffff_ffff_ffff_8001);

        // `movsxd rdx, dword [rbx + 8]` -> `0x48 0x63 0x53 0x08`
        let (len, bytes) = pad_insn(&[0x48, 0x63, 0x53, 0x08]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 8, None, false, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_RDX], 0xffff_ffff_8000_0002);
    }

    #[test]
    fn test_alu_and_or_cmp_test_flags() {
        let (mem, mmio) = setup_mem_with_mmio();
        let mut comm = comm_64bit();

        mmio.write(0x30, 4, 0x00ff_00f0).unwrap();
        comm.gprs[GPR_RDI] = MMIO_BASE + 0x30;

        // `or dword [rdi], 0x0f` -> `0x83 0x0f 0x0f`
        let (len, bytes) = pad_insn(&[0x83, 0x0f, 0x0f]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x30, None, true, len, &bytes).unwrap();
        assert_eq!(mmio.read(0x30, 4).unwrap(), 0x00ff_00ff);
        assert_eq!(comm.rflags & (Rflags::ZF | Rflags::CF | Rflags::OF).bits() as u64, 0);

        // `and dword [rdi], 0x0000_00ff` -> `0x81 0x27 0xff 0x00 0x00 0x00`
        let (len, bytes) = pad_insn(&[0x81, 0x27, 0xff, 0x00, 0x00, 0x00]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x30, None, true, len, &bytes).unwrap();
        assert_eq!(mmio.read(0x30, 4).unwrap(), 0xff);

        // `cmp dword [rdi], 0xff` -> `0x81 0x3f 0xff 0x00 0x00 0x00` -> sets ZF=1, CF=0
        let (len, bytes) = pad_insn(&[0x81, 0x3f, 0xff, 0x00, 0x00, 0x00]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x30, None, false, len, &bytes).unwrap();
        assert_ne!(comm.rflags & (Rflags::ZF.bits() as u64), 0);
        assert_eq!(comm.rflags & (Rflags::CF.bits() as u64), 0);

        // `test byte [rdi], 0x80` -> `0xf6 0x07 0x80` -> 0xff & 0x80 = 0x80 (SF=1, ZF=0)
        let (len, bytes) = pad_insn(&[0xf6, 0x07, 0x80]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x30, None, false, len, &bytes).unwrap();
        assert_ne!(comm.rflags & (Rflags::SF.bits() as u64), 0);
        assert_eq!(comm.rflags & (Rflags::ZF.bits() as u64), 0);
    }

    #[test]
    fn test_paged_gva_to_gpa_rep_stosd_rep_movsb_and_insn_fetch() {
        let (mem, mmio) = setup_mem_with_mmio();
        let ram_pages = mem.alloc_anon_mem(0x20_000).unwrap();
        mem.add_region(
            AddrOpt::Fixed(0),
            Arc::new(MemRegion::with_mapped(ram_pages, MemRegionType::Ram)),
        )
        .unwrap();
        let ram = mem.ram_bus();

        // Build 4-level x86_64 page tables at CR3 = 0x1000:
        //   PML4[0] -> PDPT 0x2000
        //   PDPT[0] -> PD   0x3000
        //   PD[0]   -> PT   0x4000
        //   PT[5]   -> 4 KiB RAM page at GPA 0x5000 (GVA 0x5000)
        //   PT[6]   -> 4 KiB code page at GPA 0x6000 (GVA 0x6000)
        //   PD[1]   -> 2 MiB PS huge page at GPA 0x0020_0000 (GVA 0x0020_0000)
        //   PDPT[1] -> 1 GiB PS huge page at GPA 0x8000_0000 (GVA 0x4000_0000 -> MMIO_BASE!)
        let p_rw = (PteFlags::P | PteFlags::RW).bits() as u64;
        let ps = PteFlags::PS.bits() as u64;
        ram.write::<u64>(0x1000, &(0x2000 | p_rw)).unwrap();
        ram.write::<u64>(0x2000, &(0x3000 | p_rw)).unwrap();
        ram.write::<u64>(0x2008, &(MMIO_BASE | p_rw | ps)).unwrap();
        ram.write::<u64>(0x3000, &(0x4000 | p_rw)).unwrap();
        ram.write::<u64>(0x3008, &(0x0020_0000 | p_rw | ps)).unwrap();
        ram.write::<u64>(0x4000 + 5 * 8, &(0x5000 | p_rw)).unwrap();
        ram.write::<u64>(0x4000 + 6 * 8, &(0x6000 | p_rw)).unwrap();

        let mut comm = comm_64bit();
        comm.cr3 = 0x1000;

        assert_eq!(gva_to_gpa(&ram, &comm, 0x5abc).unwrap(), 0x5abc);
        assert_eq!(
            gva_to_gpa(&ram, &comm, 0x0020_1234).unwrap(),
            0x0020_1234
        );
        assert_eq!(
            gva_to_gpa(&ram, &comm, 0x4000_0080).unwrap(),
            MMIO_BASE + 0x80
        );

        // 1. `rep stosd` (`0xf3 0xab`): fill 4 dwords at MMIO_BASE + 0x40 with 0xa5a5_5a5a
        comm.rip = 0x6000;
        comm.gprs[GPR_RAX] = 0xa5a5_5a5a;
        comm.gprs[GPR_RDI] = 0x4000_0040;
        comm.gprs[GPR_RCX] = 4;
        let (len, bytes) = pad_insn(&[0xf3, 0xab]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x40, None, true, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_RCX], 0);
        assert_eq!(comm.gprs[GPR_RDI], 0x4000_0050);
        assert_eq!(comm.rip, 0x6002);
        for i in 0..4 {
            assert_eq!(mmio.read(0x40 + i * 4, 4).unwrap(), 0xa5a5_5a5a);
        }

        // 2. `rep movsb` (`0xf3 0xa4`): copy 6 bytes from paged Guest RAM GVA 0x5100 -> MMIO + 0x60
        ram.lock_layout()
            .write_exact_bytes(0x5100, b"MotOS!")
            .unwrap();
        comm.rip = 0x6010;
        comm.gprs[GPR_RSI] = 0x5100;
        comm.gprs[GPR_RDI] = 0x4000_0060;
        comm.gprs[GPR_RCX] = 6;
        let (len, bytes) = pad_insn(&[0xf3, 0xa4]);
        emulate_mmio_fault(&mem, &mut comm, MMIO_BASE + 0x60, None, true, len, &bytes).unwrap();
        assert_eq!(comm.gprs[GPR_RCX], 0);
        assert_eq!(comm.rip, 0x6012);
        assert_eq!(&mmio.buf.lock()[0x60..0x66], b"MotOS!");

        // 3. `insn_len == 0` + RIP-relative `[rip + disp32]` + `fault_gpa == 0`:
        // Place `mov ecx, dword [rip + 0x3fff_9ff2]` (`0x8b 0x0d 0xf2 0x9f 0xff 0x3f`) at GVA 0x6088:
        // Next RIP = 0x608e -> 0x608e + 0x3fff_9ff2 = 0x4000_0080 -> translates via 1 GiB PDPT[1] to MMIO_BASE + 0x80!
        mmio.write(0x80, 4, 0xfeed_face).unwrap();
        ram.lock_layout()
            .write_exact_bytes(0x6088, &[0x8b, 0x0d, 0xf2, 0x9f, 0xff, 0x3f])
            .unwrap();
        comm.rip = 0x6088;
        comm.gprs[GPR_RCX] = 0;
        emulate_mmio_fault(&mem, &mut comm, 0, None, false, 0, &[0u8; 15]).unwrap();
        assert_eq!(comm.gprs[GPR_RCX], 0xfeed_face);
        assert_eq!(comm.rip, 0x608e);
    }
}
