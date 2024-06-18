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

use crate::c_enum;
use bitflags::bitflags;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Reg {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    X30,
    Sp,
    Pc,
    Pstate,
}

pub const fn encode(op0: u16, op1: u16, crn: u16, crm: u16, op2: u16) -> u16 {
    op0 << 14 | op1 << 11 | crn << 7 | crm << 3 | op2
}

c_enum! {
    pub struct SReg(u16);
    {
        MPIDR_EL1 = encode(3, 0, 0, 0, 5);
    }
}

// https://developer.arm.com/documentation/den0024/a/ARMv8-Registers/Processor-state
bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Pstate: u32 {
        /// Negative condition flag.
        const N = 1 << 31;
        /// Zero condition flag.
        const Z = 1 << 30;
        /// Carry condition flag.
        const C = 1 << 29;
        /// oVerflow condition flag.
        const V = 1 << 28;
        /// Debug mask bit.
        /// Software Step bit.
        const SS = 1 << 21;
        /// Illegal execution state bit.
        const IL = 1 << 20;
        const D = 1 << 9;
        /// SError mask bit.
        const A = 1 << 8;
        /// IRQ mask bit.
        const I = 1 << 7;
        /// FIQ mask bit.
        const F = 1 << 6;
        const M = 1 << 4;

        const EL_BIT3 = 1 << 3;
        const EL_BIT2 = 1 << 2;
        const EL_H = 1 << 0;
    }
}
