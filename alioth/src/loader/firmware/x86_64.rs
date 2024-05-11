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

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crate::arch::layout::MEM_64_START;
use crate::arch::reg::{Cr0, Rflags, SegAccess};
use crate::hv::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::loader::{InitState, Result};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{AddrOpt, MemRegion, MemRegionType, Memory};

pub fn load<P: AsRef<Path>>(memory: &Memory, path: P) -> Result<InitState> {
    let file = File::open(path)?;
    let size = file.metadata()?.len() as usize;
    assert_eq!(size & 0xfff, 0);

    let rom = ArcMemPages::new_file(file)?;
    let gpa = MEM_64_START - size;
    memory.add_region(
        AddrOpt::Fixed(gpa),
        Arc::new(MemRegion::with_mapped(rom, MemRegionType::Reserved)),
    )?;
    let boot_cs = SegRegVal {
        selector: 0xf000,
        base: 0xffff0000,
        limit: 0xffff,
        access: SegAccess(0x9a),
    };
    let boot_ds = SegRegVal {
        selector: 0x0,
        base: 0x0,
        limit: 0xffff,
        access: SegAccess(0x93),
    };
    let boot_ss = SegRegVal {
        selector: 0x0,
        base: 0x0,
        limit: 0xffff,
        access: SegAccess(0x92),
    };
    let boot_tr = SegRegVal {
        selector: 0x0,
        base: 0x0,
        limit: 0xffff,
        access: SegAccess(0x83),
    };
    let boot_ldtr = SegRegVal {
        selector: 0x0,
        base: 0x0,
        limit: 0xffff,
        access: SegAccess(0x82),
    };
    let init = InitState {
        regs: vec![
            (Reg::Rax, 0),
            (Reg::Rbx, 0),
            (Reg::Rcx, 0),
            (Reg::Rdx, 0x600),
            (Reg::Rsi, 0),
            (Reg::Rdi, 0),
            (Reg::Rsp, 0),
            (Reg::Rbp, 0),
            (Reg::R8, 0),
            (Reg::R9, 0),
            (Reg::R10, 0),
            (Reg::R11, 0),
            (Reg::R12, 0),
            (Reg::R13, 0),
            (Reg::R14, 0),
            (Reg::R15, 0),
            (Reg::Rip, 0xfff0),
            (Reg::Rflags, Rflags::RESERVED_1.bits() as u64),
        ],
        sregs: vec![
            (SReg::Cr0, (Cr0::ET | Cr0::NW | Cr0::CD).bits() as u64),
            (SReg::Cr2, 0),
            (SReg::Cr3, 0),
            (SReg::Cr4, 0),
            (SReg::Cr8, 0),
            (SReg::Efer, 0),
        ],
        seg_regs: vec![
            (SegReg::Cs, boot_cs),
            (SegReg::Ds, boot_ds),
            (SegReg::Es, boot_ds),
            (SegReg::Fs, boot_ds),
            (SegReg::Gs, boot_ds),
            (SegReg::Ss, boot_ss),
            (SegReg::Tr, boot_tr),
            (SegReg::Ldtr, boot_ldtr),
        ],
        dt_regs: vec![
            (
                DtReg::Idtr,
                DtRegVal {
                    base: 0,
                    limit: 0xffff,
                },
            ),
            (
                DtReg::Gdtr,
                DtRegVal {
                    base: 0,
                    limit: 0xffff,
                },
            ),
        ],
        initramfs: None,
    };
    Ok(init)
}
