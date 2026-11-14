// `#![no_std]` Ring-0 `.cwasm` ELF machine-code validator rejecting any FP/SIMD opcodes.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, String> {
    let bytes: [u8; 2] = buf
        .get(off..off + 2)
        .ok_or_else(|| "unexpected EOF reading u16".to_string())?
        .try_into()
        .unwrap();
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = buf
        .get(off..off + 4)
        .ok_or_else(|| "unexpected EOF reading u32".to_string())?
        .try_into()
        .unwrap();
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64, String> {
    let bytes: [u8; 8] = buf
        .get(off..off + 8)
        .ok_or_else(|| "unexpected EOF reading u64".to_string())?
        .try_into()
        .unwrap();
    Ok(u64::from_le_bytes(bytes))
}

fn decode_modrm(buf: &[u8], mut pos: usize) -> Result<usize, String> {
    if pos >= buf.len() {
        return Err("unexpected EOF in ModRM".to_string());
    }
    let modrm = buf[pos];
    pos += 1;
    let mod_bits = (modrm >> 6) & 3;
    let rm = modrm & 7;
    if mod_bits == 3 {
        return Ok(pos);
    }
    if rm == 4 {
        if pos >= buf.len() {
            return Err("unexpected EOF in SIB".to_string());
        }
        let sib = buf[pos];
        pos += 1;
        let base = sib & 7;
        if mod_bits == 0 && base == 5 {
            return Ok(pos + 4);
        }
    }
    match mod_bits {
        0 if rm == 5 => Ok(pos + 4),
        1 => Ok(pos + 1),
        2 => Ok(pos + 4),
        _ => Ok(pos),
    }
}

fn find_br_table_ranges(fn_bytes: &[u8]) -> BTreeMap<usize, usize> {
    let mut skip_ranges = BTreeMap::new();
    let len = fn_bytes.len();
    let mut i = 0;

    while i + 10 <= len {
        let cmp_pos = if (0x40..=0x4f).contains(&fn_bytes[i]) {
            i + 1
        } else {
            i
        };
        if cmp_pos + 2 > len || fn_bytes[cmp_pos] != 0x3b {
            i += 1;
            continue;
        }
        let after_cmp = cmp_pos + 2;

        if after_cmp >= len {
            break;
        }
        let (cmov_rex, cmov_pos) = if (0x40..=0x4f).contains(&fn_bytes[after_cmp]) {
            (fn_bytes[after_cmp], after_cmp + 1)
        } else {
            (0u8, after_cmp)
        };
        if cmov_pos + 3 > len || fn_bytes[cmov_pos] != 0x0f || fn_bytes[cmov_pos + 1] != 0x42 {
            i += 1;
            continue;
        }
        let cmov_modrm = fn_bytes[cmov_pos + 2];
        let after_cmov = cmov_pos + 3;

        if after_cmov + 7 > len
            || !matches!(fn_bytes[after_cmov], 0x48 | 0x4c)
            || fn_bytes[after_cmov + 1] != 0x8d
            || (fn_bytes[after_cmov + 2] & 0xc7) != 0x05
        {
            i += 1;
            continue;
        }
        let Ok(disp) = read_u32_le(fn_bytes, after_cmov + 3) else {
            i += 1;
            continue;
        };
        let after_lea = after_cmov + 7;
        if !matches!(disp, 8..=11) {
            i += 1;
            continue;
        }

        let reg_low = (cmov_modrm >> 3) & 7;
        let need_rex_b = (cmov_rex & 0x04) != 0;
        let mov_op = 0xb8 + reg_low;

        let mut max_idx: Option<u32> = None;
        for back in 5..=24 {
            if i < back {
                break;
            }
            let p = i - back;
            if need_rex_b {
                if p >= 1 && fn_bytes[p - 1] == 0x41 && fn_bytes[p] == mov_op {
                    max_idx = read_u32_le(fn_bytes, p + 1).ok();
                    break;
                }
            } else if fn_bytes[p] == mov_op && (p == 0 || fn_bytes[p - 1] != 0x41) {
                max_idx = read_u32_le(fn_bytes, p + 1).ok();
                break;
            }
        }

        if let Some(max_val) = max_idx {
            let ts = after_lea + disp as usize;
            let tbl_bytes = (max_val as usize).saturating_add(1).saturating_mul(4);
            let te = ts.saturating_add(tbl_bytes);
            if te <= len {
                skip_ranges.insert(ts, te);
            }
        }

        i = after_lea;
    }

    skip_ranges
}

fn verify_function_code(fn_bytes: &[u8], fn_name: &str) -> Result<usize, String> {
    let skip_ranges = find_br_table_ranges(fn_bytes);

    let mut masked = fn_bytes.to_vec();
    for (&ts, &te) in &skip_ranges {
        masked[ts..te].fill(0x90);
    }

    let last_ud2 = masked
        .windows(2)
        .rposition(|w| w == [0x0f, 0x0b])
        .map(|p| p + 2)
        .unwrap_or(0);
    let last_ret = masked
        .iter()
        .rposition(|&b| b == 0xc3)
        .map(|p| p + 1)
        .unwrap_or(0);
    let last_term = last_ud2.max(last_ret);
    let code_end = if last_term > 0 && last_term < fn_bytes.len() {
        last_term
    } else {
        fn_bytes.len()
    };

    let mut pos = 0;
    let mut insns = 0;
    while pos < code_end {
        if let Some(&next_pos) = skip_ranges.get(&pos) {
            pos = next_pos;
            continue;
        }
        let start_pos = pos;
        let mut op_size_16 = false;
        let mut rep_prefix = 0u8;

        while pos < code_end
            && matches!(
                fn_bytes[pos],
                0x66 | 0xf0 | 0xf2 | 0xf3 | 0x2e | 0x3e | 0x26 | 0x36 | 0x64 | 0x65
            )
        {
            if fn_bytes[pos] == 0x66 {
                op_size_16 = true;
            } else if matches!(fn_bytes[pos], 0xf2 | 0xf3) {
                rep_prefix = fn_bytes[pos];
            }
            pos += 1;
        }

        let mut rex = 0u8;
        if pos < code_end && (0x40..=0x4f).contains(&fn_bytes[pos]) {
            rex = fn_bytes[pos];
            pos += 1;
        }

        if pos >= code_end {
            return Err(format!("trailing prefix at end of {fn_name}"));
        }
        let op = fn_bytes[pos];
        pos += 1;

        if (0xd8..=0xdf).contains(&op) || op == 0x9b || matches!(op, 0xc4 | 0xc5 | 0x62) {
            return Err(format!(
                "disallowed FP/SIMD opcode 0x{op:02x} in {fn_name} at +0x{start_pos:x}"
            ));
        }

        let imm_size = if !op_size_16 || (rex & 0x08) != 0 {
            4
        } else {
            2
        };

        match op {
            0x50..=0x5f | 0x90 | 0x98 | 0x99 | 0xc3 | 0xcc | 0xf4 => {}
            0xc2 => {
                pos += 2;
            }
            0x00..=0x03
            | 0x08..=0x0b
            | 0x10..=0x13
            | 0x18..=0x1b
            | 0x20..=0x23
            | 0x28..=0x2b
            | 0x30..=0x33
            | 0x38..=0x3b
            | 0x63
            | 0x84..=0x8b
            | 0x8d
            | 0xd0..=0xd3
            | 0xfe
            | 0xff => {
                pos = decode_modrm(fn_bytes, pos)?;
            }
            0x04
            | 0x0c
            | 0x14
            | 0x1c
            | 0x24
            | 0x2c
            | 0x34
            | 0x3c
            | 0x6a
            | 0xa8
            | 0xeb
            | 0x70..=0x7f
            | 0xb0..=0xb7 => {
                pos += 1;
            }
            0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0xa9 => {
                pos += imm_size;
            }
            0x68 | 0xe8 | 0xe9 => {
                pos += 4;
            }
            0xb8..=0xbf => {
                pos += if (rex & 0x08) != 0 { 8 } else { imm_size };
            }
            0x80 | 0x82 | 0x83 | 0xc0 | 0xc1 | 0xc6 => {
                pos = decode_modrm(fn_bytes, pos)? + 1;
            }
            0x81 | 0xc7 | 0x69 => {
                pos = decode_modrm(fn_bytes, pos)? + imm_size;
            }
            0x6b => {
                pos = decode_modrm(fn_bytes, pos)? + 1;
            }
            0xf6 => {
                let reg = (fn_bytes[pos] >> 3) & 7;
                pos = decode_modrm(fn_bytes, pos)? + if reg <= 1 { 1 } else { 0 };
            }
            0xf7 => {
                let reg = (fn_bytes[pos] >> 3) & 7;
                pos = decode_modrm(fn_bytes, pos)? + if reg <= 1 { imm_size } else { 0 };
            }
            0x0f => {
                if pos >= code_end {
                    return Err(format!("truncated 0x0f opcode in {fn_name}"));
                }
                let op2 = fn_bytes[pos];
                pos += 1;
                match op2 {
                    0x0b => {}
                    0x1f | 0x40..=0x4f | 0x90..=0x9f | 0xa5 | 0xad => {
                        pos = decode_modrm(fn_bytes, pos)?;
                    }
                    0x80..=0x8f => {
                        pos += 4;
                    }
                    0xa3 | 0xab | 0xaf | 0xb0 | 0xb1 | 0xb3 | 0xb6 | 0xb7 | 0xbb | 0xbc | 0xbd
                    | 0xbe | 0xbf | 0xc0 | 0xc1 => {
                        if matches!(rep_prefix, 0xf2 | 0xf3) && !matches!(op2, 0xb8 | 0xbc | 0xbd) {
                            return Err(format!(
                                "disallowed rep 0x0f 0x{op2:02x} in {fn_name} at +0x{start_pos:x}"
                            ));
                        }
                        pos = decode_modrm(fn_bytes, pos)?;
                    }
                    0xa4 | 0xac | 0xba => {
                        pos = decode_modrm(fn_bytes, pos)? + 1;
                    }
                    0xae => {
                        if pos >= code_end {
                            return Err(format!("truncated 0x0f 0xae in {fn_name}"));
                        }
                        let modrm = fn_bytes[pos];
                        if (modrm >> 6) != 3 {
                            return Err(format!(
                                "disallowed fxsave/fxrstor/mxcsr (0x0f 0xae 0x{modrm:02x}) in {fn_name} at +0x{start_pos:x}"
                            ));
                        }
                        pos += 1;
                    }
                    0xc8..=0xcf => {}
                    _ => {
                        return Err(format!(
                            "disallowed FP/SIMD 2-byte opcode 0x0f 0x{op2:02x} in {fn_name} at +0x{start_pos:x}"
                        ));
                    }
                }
            }
            _ => {
                return Err(format!(
                    "unrecognized or disallowed opcode 0x{op:02x} in {fn_name} at +0x{start_pos:x}"
                ));
            }
        }

        if pos > code_end {
            return Err(format!(
                "instruction decoding overrun in {fn_name} at +0x{start_pos:x}"
            ));
        }
        insns += 1;
    }

    Ok(insns)
}

/// Validates that a precompiled Wasmtime `.cwasm` ELF image contains zero
/// floating-point (x87, SSE/SSE2) or SIMD (MMX, SSE, AVX, AVX-512) machine
/// instructions across all functions in its `.text` section.
pub fn validate_cwasm_no_fp(cwasm_bytes: &[u8]) -> Result<(), String> {
    if cwasm_bytes.len() < 64 || &cwasm_bytes[0..4] != b"\x7fELF" || cwasm_bytes[4] != 2 {
        return Err("invalid 64-bit ELF header in .cwasm".to_string());
    }

    let e_shoff = read_u64_le(cwasm_bytes, 40)? as usize;
    let e_shentsize = read_u16_le(cwasm_bytes, 58)? as usize;
    let e_shnum = read_u16_le(cwasm_bytes, 60)? as usize;
    let e_shstrndx = read_u16_le(cwasm_bytes, 62)? as usize;

    if e_shstrndx >= e_shnum {
        return Err("invalid e_shstrndx in .cwasm ELF".to_string());
    }

    let shstr_hdr = e_shoff
        .checked_add(e_shstrndx.saturating_mul(e_shentsize))
        .ok_or_else(|| "shstr_hdr overflow".to_string())?;
    let shstr_off = read_u64_le(cwasm_bytes, shstr_hdr + 24)? as usize;
    let shstr_size = read_u64_le(cwasm_bytes, shstr_hdr + 32)? as usize;
    let shstr = cwasm_bytes
        .get(shstr_off..shstr_off.saturating_add(shstr_size))
        .ok_or_else(|| "shstrtab out of bounds".to_string())?;

    let mut text_sec: Option<(usize, usize, usize)> = None;
    let mut symtab_sec: Option<(usize, usize)> = None;
    let mut strtab_sec: Option<(usize, usize)> = None;

    for idx in 0..e_shnum {
        let off = e_shoff + idx * e_shentsize;
        let sh_name = read_u32_le(cwasm_bytes, off)? as usize;
        let sh_offset = read_u64_le(cwasm_bytes, off + 24)? as usize;
        let sh_size = read_u64_le(cwasm_bytes, off + 32)? as usize;

        let Some(tail) = shstr.get(sh_name..) else {
            return Err("section name out of bounds".to_string());
        };
        let name_end = tail
            .iter()
            .position(|&b| b == 0)
            .map(|p| sh_name + p)
            .unwrap_or(shstr.len());
        let name = core::str::from_utf8(&shstr[sh_name..name_end]).unwrap_or("");

        match name {
            ".text" => text_sec = Some((idx, sh_offset, sh_size)),
            ".symtab" => symtab_sec = Some((sh_offset, sh_size)),
            ".strtab" => strtab_sec = Some((sh_offset, sh_size)),
            _ => {}
        }
    }

    let (text_ndx, text_off, text_size) =
        text_sec.ok_or_else(|| "missing .text section in .cwasm".to_string())?;
    let (symtab_off, symtab_size) =
        symtab_sec.ok_or_else(|| "missing .symtab section in .cwasm".to_string())?;
    let (strtab_off, strtab_size) =
        strtab_sec.ok_or_else(|| "missing .strtab section in .cwasm".to_string())?;

    let text = cwasm_bytes
        .get(text_off..text_off.saturating_add(text_size))
        .ok_or_else(|| ".text section out of bounds".to_string())?;
    let symtab = cwasm_bytes
        .get(symtab_off..symtab_off.saturating_add(symtab_size))
        .ok_or_else(|| ".symtab section out of bounds".to_string())?;
    let strtab = cwasm_bytes
        .get(strtab_off..strtab_off.saturating_add(strtab_size))
        .ok_or_else(|| ".strtab section out of bounds".to_string())?;

    let mut verified_fns = 0usize;
    let mut off = 0;
    while off + 24 <= symtab.len() {
        let st_name = read_u32_le(symtab, off)? as usize;
        let st_info = symtab[off + 4];
        let st_shndx = read_u16_le(symtab, off + 6)? as usize;
        let st_value = read_u64_le(symtab, off + 8)? as usize;
        let st_size = read_u64_le(symtab, off + 16)? as usize;
        off += 24;

        if (st_info & 0x0f) == 2 && st_shndx == text_ndx && st_size > 0 {
            let name_end = strtab
                .get(st_name..)
                .and_then(|s| s.iter().position(|&b| b == 0).map(|p| st_name + p))
                .unwrap_or(strtab.len());
            let fn_name = strtab
                .get(st_name..name_end)
                .and_then(|s| core::str::from_utf8(s).ok())
                .unwrap_or("<unknown>");

            let fn_bytes = text
                .get(st_value..st_value.saturating_add(st_size))
                .ok_or_else(|| format!("function {fn_name} out of .text bounds"))?;
            verify_function_code(fn_bytes, fn_name)?;
            verified_fns += 1;
        }
    }

    if verified_fns == 0 {
        return Err("no STT_FUNC symbols found in .cwasm .text section".to_string());
    }

    Ok(())
}
