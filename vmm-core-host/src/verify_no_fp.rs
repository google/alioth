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

use std::collections::HashMap;

fn read_uleb(buf: &[u8], mut pos: usize) -> Result<(u32, usize), String> {
    let mut res = 0u32;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() {
            return Err("unexpected EOF while reading LEB128".to_string());
        }
        let b = buf[pos];
        pos += 1;
        res |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((res, pos));
        }
        shift += 7;
        if shift >= 35 {
            return Err("LEB128 overflow".to_string());
        }
    }
}

fn check_wasm_valtype(ty: u8, context: &str) -> Result<(), String> {
    match ty {
        0x7f | 0x7e => Ok(()), // i32, i64
        0x7d => Err(format!("disallowed f32 value type in Wasm {context}")),
        0x7c => Err(format!("disallowed f64 value type in Wasm {context}")),
        0x7b => Err(format!("disallowed v128 SIMD value type in Wasm {context}")),
        0x70 | 0x6f => Ok(()), // funcref, externref
        other => Err(format!(
            "unexpected Wasm value type 0x{other:02x} in {context}"
        )),
    }
}

fn skip_leb(buf: &[u8], mut pos: usize, max_bytes: usize) -> Result<usize, String> {
    for _ in 0..max_bytes {
        let b = *buf
            .get(pos)
            .ok_or_else(|| "unexpected EOF while skipping LEB128".to_string())?;
        pos += 1;
        if (b & 0x80) == 0 {
            return Ok(pos);
        }
    }
    Err("LEB128 exceeds maximum byte length".to_string())
}

/// Walks a single Wasm function's instruction slice (`[start..end)`), optionally rewriting
/// `memory.copy` (`0xfc 0x0a 0x00 0x00`, 4B) -> `call __vmm_memcpy` (4B) and
/// `memory.fill` (`0xfc 0x0b 0x00`, 3B) -> `call __vmm_memset` (3B), while rejecting any
/// floating-point or SIMD instructions and returning the count of hardware `0xfe` atomic RMW ops.
fn scan_or_rewrite_wasm_insns(
    wasm_bytes: &mut [u8],
    mut pc: usize,
    body_end: usize,
    fn_idx: u32,
    rewrite_targets: Option<([u8; 4], [u8; 3])>,
) -> Result<usize, String> {
    let mut atomic_rmw_count = 0usize;
    while pc < body_end {
        let op_pos = pc;
        let op = wasm_bytes[pc];
        pc += 1;

        match op {
            // Control & parametric no-immediate opcodes
            0x00 | 0x01 | 0x05 | 0x0b | 0x0f | 0x1a | 0x1b => {}
            // `block`, `loop`, `if` -> blocktype (1-byte empty/valtype or sleb128 typeidx)
            0x02..=0x04 => {
                let bt = *wasm_bytes
                    .get(pc)
                    .ok_or_else(|| format!("EOF in blocktype in fn[{fn_idx}]"))?;
                if matches!(bt, 0x40 | 0x7f | 0x7e | 0x70 | 0x6f) {
                    pc += 1;
                } else if matches!(bt, 0x7d | 0x7c | 0x7b) {
                    return Err(format!(
                        "disallowed FP/SIMD blocktype 0x{bt:02x} in fn[{fn_idx}]"
                    ));
                } else {
                    pc = skip_leb(wasm_bytes, pc, 5)?;
                }
            }
            // Single uleb128 immediate
            0x0c | 0x0d | 0x10 | 0x20..=0x26 | 0x3f | 0x40 => {
                pc = skip_leb(wasm_bytes, pc, 5)?;
            }
            // `br_table`: vec(labelidx) + default labelidx
            0x0e => {
                let (cnt, mut next_pc) = read_uleb(wasm_bytes, pc)?;
                for _ in 0..=cnt {
                    next_pc = skip_leb(wasm_bytes, next_pc, 5)?;
                }
                pc = next_pc;
            }
            // `call_indirect`: typeidx + tableidx
            0x11 => {
                pc = skip_leb(wasm_bytes, pc, 5)?;
                pc = skip_leb(wasm_bytes, pc, 5)?;
            }
            // `select t*`: vec(valtype)
            0x1c => {
                let (cnt, mut next_pc) = read_uleb(wasm_bytes, pc)?;
                for _ in 0..cnt {
                    check_wasm_valtype(wasm_bytes[next_pc], &format!("fn[{fn_idx}] select"))?;
                    next_pc += 1;
                }
                pc = next_pc;
            }
            // Integer memory loads & stores (`memarg`: align uleb + offset uleb)
            0x28 | 0x29 | 0x2c..=0x37 | 0x3a..=0x3e => {
                pc = skip_leb(wasm_bytes, pc, 5)?;
                pc = skip_leb(wasm_bytes, pc, 10)?;
            }
            // `i32.const`
            0x41 => {
                pc = skip_leb(wasm_bytes, pc, 5)?;
            }
            // `i64.const`
            0x42 => {
                pc = skip_leb(wasm_bytes, pc, 10)?;
            }
            // Integer comparisons, arithmetic, conversions, sign-extension
            0x45..=0x5a | 0x67..=0x8a | 0xa7..=0xb1 | 0xc0..=0xc4 => {}
            // Disallowed float loads/stores, constants, comparisons, arithmetic, conversions
            0x2a | 0x2b | 0x38 | 0x39 | 0x43 | 0x44 | 0x5b..=0x66 | 0x8b..=0xa6
            | 0xb2..=0xbf => {
                return Err(format!(
                    "disallowed FP opcode 0x{op:02x} in Code function[{fn_idx}] at +0x{op_pos:x}"
                ));
            }
            // Disallowed 0xfd SIMD prefix
            0xfd => {
                return Err(format!(
                    "disallowed SIMD 0xfd opcode in Code function[{fn_idx}] at +0x{op_pos:x}"
                ));
            }
            // 0xfc misc / bulk-memory prefix
            0xfc => {
                let (subop, next_pc) = read_uleb(wasm_bytes, pc)?;
                pc = next_pc;
                match subop {
                    0..=7 => {
                        return Err(format!(
                            "disallowed FP saturating trunc 0xfc {subop} in fn[{fn_idx}]"
                        ));
                    }
                    8 => {
                        // `memory.init dataidx 0x00`
                        pc = skip_leb(wasm_bytes, pc, 5)?;
                        pc += 1;
                    }
                    9 | 13 | 15..=17 => {
                        pc = skip_leb(wasm_bytes, pc, 5)?;
                    }
                    10 => {
                        // `memory.copy 0x00 0x00` (4 bytes total from `op_pos`)
                        if pc + 2 > body_end || wasm_bytes[pc..pc + 2] != [0x00, 0x00] {
                            return Err(format!("malformed memory.copy in fn[{fn_idx}]"));
                        }
                        pc += 2;
                        if let Some((memcpy_call, _)) = rewrite_targets {
                            if pc - op_pos != 4 {
                                return Err("unexpected memory.copy encoding length".to_string());
                            }
                            wasm_bytes[op_pos..pc].copy_from_slice(&memcpy_call);
                        } else {
                            return Err(format!(
                                "unrewritten memory.copy (0xfc 0x0a) in Code function[{fn_idx}]"
                            ));
                        }
                    }
                    11 => {
                        // `memory.fill 0x00` (3 bytes total from `op_pos`)
                        if pc + 1 > body_end || wasm_bytes[pc] != 0x00 {
                            return Err(format!("malformed memory.fill in fn[{fn_idx}]"));
                        }
                        pc += 1;
                        if let Some((_, memset_call)) = rewrite_targets {
                            if pc - op_pos != 3 {
                                return Err("unexpected memory.fill encoding length".to_string());
                            }
                            wasm_bytes[op_pos..pc].copy_from_slice(&memset_call);
                        } else {
                            return Err(format!(
                                "unrewritten memory.fill (0xfc 0x0b) in Code function[{fn_idx}]"
                            ));
                        }
                    }
                    12 | 14 => {
                        pc = skip_leb(wasm_bytes, pc, 5)?;
                        pc = skip_leb(wasm_bytes, pc, 5)?;
                    }
                    other => {
                        return Err(format!(
                            "unexpected 0xfc subopcode {other} in fn[{fn_idx}]"
                        ));
                    }
                }
            }
            // 0xfe threads / atomics prefix
            0xfe => {
                let (subop, next_pc) = read_uleb(wasm_bytes, pc)?;
                pc = next_pc;
                if subop >= 0x10 {
                    atomic_rmw_count += 1;
                }
                if subop == 0x03 {
                    // `atomic.fence 0x00`
                    pc += 1;
                } else {
                    // `memarg`: align uleb + offset uleb
                    pc = skip_leb(wasm_bytes, pc, 5)?;
                    pc = skip_leb(wasm_bytes, pc, 10)?;
                }
            }
            other => {
                return Err(format!(
                    "unexpected Wasm opcode 0x{other:02x} in Code function[{fn_idx}] at +0x{op_pos:x}"
                ));
            }
        }
    }
    if pc != body_end {
        return Err(format!("Wasm instruction scan overran Code function[{fn_idx}]"));
    }
    Ok(atomic_rmw_count)
}

/// Rewrites all `memory.copy` (`0xfc 0x0a 0x00 0x00`) and `memory.fill` (`0xfc 0x0b 0x00`)
/// instructions in `wasm_bytes` into direct `call __vmm_memcpy` and `call __vmm_memset`
/// instructions so Cranelift never lowers bulk-memory ops into inline `%xmm` SIMD stores.
#[allow(dead_code)]
pub fn rewrite_wasm_bulk_memory(wasm_bytes: &mut [u8]) -> Result<(), String> {
    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != b"\0asm" || &wasm_bytes[4..8] != b"\x01\0\0\0" {
        return Err("invalid WebAssembly module header".to_string());
    }

    let mut pos = 8;
    let mut memcpy_idx: Option<u32> = None;
    let mut memset_idx: Option<u32> = None;
    let mut code_range: Option<(usize, usize)> = None;

    while pos < wasm_bytes.len() {
        let sec_id = wasm_bytes[pos];
        pos += 1;
        let (sec_len, next_pos) = read_uleb(wasm_bytes, pos)?;
        pos = next_pos;
        let sec_end = pos + sec_len as usize;

        if sec_id == 7 {
            let (count, mut p) = read_uleb(wasm_bytes, pos)?;
            for _ in 0..count {
                let (name_len, next_p) = read_uleb(wasm_bytes, p)?;
                p = next_p;
                let name = std::str::from_utf8(&wasm_bytes[p..p + name_len as usize]).unwrap_or("");
                p += name_len as usize;
                let kind = wasm_bytes[p];
                p += 1;
                let (idx, next_p) = read_uleb(wasm_bytes, p)?;
                p = next_p;
                if kind == 0 {
                    if name == "__vmm_memcpy" {
                        memcpy_idx = Some(idx);
                    } else if name == "__vmm_memset" {
                        memset_idx = Some(idx);
                    }
                }
            }
        } else if sec_id == 10 {
            code_range = Some((pos, sec_end));
        }

        pos = sec_end;
    }

    let cpy_idx = memcpy_idx.ok_or("__vmm_memcpy export not found in vmm-core.wasm")?;
    let set_idx = memset_idx.ok_or("__vmm_memset export not found in vmm-core.wasm")?;
    if set_idx >= (1 << 14) {
        return Err(format!(
            "__vmm_memset function index {set_idx} exceeds 2-byte ULEB128 capacity"
        ));
    }

    let memcpy_call = [
        0x10u8,
        0x80 | ((cpy_idx & 0x7f) as u8),
        0x80 | (((cpy_idx >> 7) & 0x7f) as u8),
        ((cpy_idx >> 14) & 0x7f) as u8,
    ];
    let memset_call = [
        0x10u8,
        0x80 | ((set_idx & 0x7f) as u8),
        ((set_idx >> 7) & 0x7f) as u8,
    ];

    let (code_start, _code_end) = code_range.ok_or("Code section not found in vmm-core.wasm")?;
    let (fn_count, mut p) = read_uleb(wasm_bytes, code_start)?;
    for fn_idx in 0..fn_count {
        let (body_size, next_p) = read_uleb(wasm_bytes, p)?;
        p = next_p;
        let body_end = p + body_size as usize;
        let (local_decls, mut lp) = read_uleb(wasm_bytes, p)?;
        for _ in 0..local_decls {
            let (_cnt, next_lp) = read_uleb(wasm_bytes, lp)?;
            lp = next_lp + 1;
        }
        scan_or_rewrite_wasm_insns(
            wasm_bytes,
            lp,
            body_end,
            fn_idx,
            Some((memcpy_call, memset_call)),
        )?;
        p = body_end;
    }
    Ok(())
}

/// Validates that a `.wasm` module binary contains zero WASI imports, zero floating-point
/// (`f32`/`f64`) or SIMD (`v128`) types/instructions, and zero raw `memory.copy` or
/// `memory.fill` bulk-memory opcodes.
pub fn validate_wasm_no_fp(wasm_bytes: &[u8]) -> Result<(), String> {
    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != b"\0asm" || &wasm_bytes[4..8] != b"\x01\0\0\0" {
        return Err("invalid WebAssembly module header".to_string());
    }

    let mut pos = 8;
    let mut has_shared_memory_import = false;
    let mut total_atomic_rmws = 0usize;
    while pos < wasm_bytes.len() {
        let sec_id = wasm_bytes[pos];
        pos += 1;
        let (sec_len, next_pos) = read_uleb(wasm_bytes, pos)?;
        pos = next_pos;
        let sec_end = pos
            .checked_add(sec_len as usize)
            .filter(|&e| e <= wasm_bytes.len())
            .ok_or_else(|| "Wasm section extends past EOF".to_string())?;

        match sec_id {
            1 => {
                // Type section
                let (count, mut p) = read_uleb(wasm_bytes, pos)?;
                for i in 0..count {
                    if p >= sec_end || wasm_bytes[p] != 0x60 {
                        return Err(format!("expected functype 0x60 in Type[{i}]"));
                    }
                    p += 1;
                    let (param_count, next_p) = read_uleb(wasm_bytes, p)?;
                    p = next_p;
                    for _ in 0..param_count {
                        check_wasm_valtype(wasm_bytes[p], &format!("Type[{i}] param"))?;
                        p += 1;
                    }
                    let (result_count, next_p) = read_uleb(wasm_bytes, p)?;
                    p = next_p;
                    for _ in 0..result_count {
                        check_wasm_valtype(wasm_bytes[p], &format!("Type[{i}] result"))?;
                        p += 1;
                    }
                }
            }
            2 => {
                // Import section: ensure Ring-0 purity (only "env", "vmm", "vmm_bridge" allowed;
                // zero WASI imports) and no FP/SIMD imported globals.
                let (count, mut p) = read_uleb(wasm_bytes, pos)?;
                for i in 0..count {
                    let (mod_len, next_p) = read_uleb(wasm_bytes, p)?;
                    p = next_p;
                    let mod_end = p + mod_len as usize;
                    let mod_name = std::str::from_utf8(
                        wasm_bytes
                            .get(p..mod_end)
                            .ok_or_else(|| "Import module name out of bounds".to_string())?,
                    )
                    .map_err(|_| "invalid UTF-8 in Import module name".to_string())?;
                    p = mod_end;

                    let (field_len, next_p) = read_uleb(wasm_bytes, p)?;
                    p = next_p;
                    let field_end = p + field_len as usize;
                    let field_name = std::str::from_utf8(
                        wasm_bytes
                            .get(p..field_end)
                            .ok_or_else(|| "Import field name out of bounds".to_string())?,
                    )
                    .map_err(|_| "invalid UTF-8 in Import field name".to_string())?;
                    p = field_end;

                    if !matches!(mod_name, "env" | "vmm" | "vmm_bridge") {
                        return Err(format!(
                            "disallowed non-Ring-0 Wasm import {mod_name:?}::{field_name:?} at Import[{i}]"
                        ));
                    }

                    let kind = *wasm_bytes
                        .get(p)
                        .ok_or_else(|| "unexpected EOF in Import kind".to_string())?;
                    p += 1;
                    match kind {
                        0x00 => {
                            let (_type_idx, next_p) = read_uleb(wasm_bytes, p)?;
                            p = next_p;
                        }
                        0x01 => {
                            p += 1; // elemtype
                            let (flags, next_p) = read_uleb(wasm_bytes, p)?;
                            let (_min, mut next_p) = read_uleb(wasm_bytes, next_p)?;
                            if (flags & 0x01) != 0 {
                                let (_max, np) = read_uleb(wasm_bytes, next_p)?;
                                next_p = np;
                            }
                            p = next_p;
                        }
                        0x02 => {
                            let (flags, next_p) = read_uleb(wasm_bytes, p)?;
                            if mod_name == "env" && field_name == "memory" && (flags & 0x03) == 0x03
                            {
                                has_shared_memory_import = true;
                            }
                            let (_min, mut next_p) = read_uleb(wasm_bytes, next_p)?;
                            if (flags & 0x01) != 0 {
                                let (_max, np) = read_uleb(wasm_bytes, next_p)?;
                                next_p = np;
                            }
                            p = next_p;
                        }
                        0x03 => {
                            check_wasm_valtype(wasm_bytes[p], &format!("Import[{i}] global"))?;
                            p += 2; // valtype + mutability
                        }
                        other => {
                            return Err(format!(
                                "unexpected import kind 0x{other:02x} at Import[{i}]"
                            ));
                        }
                    }
                }
            }
            6 => {
                // Global section
                let (count, mut p) = read_uleb(wasm_bytes, pos)?;
                for i in 0..count {
                    check_wasm_valtype(wasm_bytes[p], &format!("Global[{i}]"))?;
                    p += 2; // valtype + mutability
                    while p < sec_end && wasm_bytes[p] != 0x0b {
                        p += 1;
                    }
                    p += 1; // skip 0x0b end
                }
            }
            10 => {
                // Code section
                let (fn_count, mut p) = read_uleb(wasm_bytes, pos)?;
                for fn_idx in 0..fn_count {
                    let (body_size, next_p) = read_uleb(wasm_bytes, p)?;
                    p = next_p;
                    let body_end = p + body_size as usize;
                    let (local_decls, mut lp) = read_uleb(wasm_bytes, p)?;
                    for _ in 0..local_decls {
                        let (_cnt, next_lp) = read_uleb(wasm_bytes, lp)?;
                        lp = next_lp;
                        check_wasm_valtype(
                            wasm_bytes[lp],
                            &format!("Code function[{fn_idx}] local"),
                        )?;
                        lp += 1;
                    }
                    let mut body_copy = wasm_bytes[lp..body_end].to_vec();
                    let body_len = body_copy.len();
                    total_atomic_rmws +=
                        scan_or_rewrite_wasm_insns(&mut body_copy, 0, body_len, fn_idx, None)?;
                    p = body_end;
                }
            }
            _ => {}
        }

        pos = sec_end;
    }

    if !has_shared_memory_import {
        return Err("vmm-core.wasm must import bounded shared env::memory".to_string());
    }
    if total_atomic_rmws == 0 {
        return Err(
            "vmm-core.wasm contains zero 0xfe hardware atomic RMW ops (+atomics / build-std missing)"
                .to_string(),
        );
    }

    Ok(())
}

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

fn find_br_table_ranges(fn_bytes: &[u8]) -> HashMap<usize, usize> {
    let mut skip_ranges = HashMap::new();
    let len = fn_bytes.len();
    let mut i = 0;

    while i + 10 <= len {
        // Match optional REX + 0x3b <modrm> (cmp)
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

        // Match optional REX + 0x0f 0x42 <modrm> (cmovb)
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

        // Match [0x48 | 0x4c] 0x8d <rip_modrm> <disp32> (lea disp32(%rip), %r_tbl)
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
            0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0x6a | 0xa8 | 0xeb
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
                    0xa3 | 0xab | 0xaf | 0xb0 | 0xb1 | 0xb3 | 0xb6 | 0xb7 | 0xbb | 0xbc
                    | 0xbd | 0xbe | 0xbf | 0xc0 | 0xc1 => {
                        if matches!(rep_prefix, 0xf2 | 0xf3)
                            && !matches!(op2, 0xb8 | 0xbc | 0xbd)
                        {
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

    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstr_off = read_u64_le(cwasm_bytes, shstr_hdr + 24)? as usize;
    let shstr_size = read_u64_le(cwasm_bytes, shstr_hdr + 32)? as usize;
    let shstr = cwasm_bytes
        .get(shstr_off..shstr_off + shstr_size)
        .ok_or_else(|| "shstrtab out of bounds".to_string())?;

    let mut text_sec: Option<(usize, usize, usize)> = None;
    let mut symtab_sec: Option<(usize, usize)> = None;
    let mut strtab_sec: Option<(usize, usize)> = None;

    for idx in 0..e_shnum {
        let off = e_shoff + idx * e_shentsize;
        let sh_name = read_u32_le(cwasm_bytes, off)? as usize;
        let sh_offset = read_u64_le(cwasm_bytes, off + 24)? as usize;
        let sh_size = read_u64_le(cwasm_bytes, off + 32)? as usize;

        let name_end = shstr[sh_name..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| sh_name + p)
            .unwrap_or(shstr.len());
        let name = std::str::from_utf8(&shstr[sh_name..name_end]).unwrap_or("");

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
        .get(text_off..text_off + text_size)
        .ok_or_else(|| ".text section out of bounds".to_string())?;
    let symtab = cwasm_bytes
        .get(symtab_off..symtab_off + symtab_size)
        .ok_or_else(|| ".symtab section out of bounds".to_string())?;
    let strtab = cwasm_bytes
        .get(strtab_off..strtab_off + strtab_size)
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
                .and_then(|s| std::str::from_utf8(s).ok())
                .unwrap_or("<unknown>");

            let fn_bytes = text
                .get(st_value..st_value + st_size)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_sse_and_x87_instructions() {
        // Valid GPR function: push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let valid = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        assert!(verify_function_code(&valid, "valid_fn").is_ok());

        // Inject movdqu (%rsi), %xmm3 (f3 0f 6f 1e) before ret
        let with_movdqu = [0x55, 0x48, 0x89, 0xe5, 0xf3, 0x0f, 0x6f, 0x1e, 0x5d, 0xc3];
        assert!(verify_function_code(&with_movdqu, "movdqu_fn").is_err());

        // Inject movsd (%rsi), %xmm0 (f2 0f 10 06) before ret
        let with_movsd = [0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x10, 0x06, 0x5d, 0xc3];
        assert!(verify_function_code(&with_movsd, "movsd_fn").is_err());

        // Inject x87 fldl (%rax) (dd 00) before ret
        let with_x87 = [0x55, 0x48, 0x89, 0xe5, 0xdd, 0x00, 0x5d, 0xc3];
        assert!(verify_function_code(&with_x87, "x87_fn").is_err());
    }
}
