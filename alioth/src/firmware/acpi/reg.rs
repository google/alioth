// Copyright 2024 Google LLC
// Copyright © 2019 Intel Corporation
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

use std::time::Instant;

use crate::firmware::acpi::bindings::FadtSleepControlReg;
use crate::mem::Result;
use crate::mem::emulated::{Action, Mmio};

pub const FADT_RESET_VAL: u8 = b'r';

#[derive(Debug)]
pub struct FadtReset;

impl Mmio for FadtReset {
    fn size(&self) -> u64 {
        1
    }

    fn read(&self, _offset: u64, _size: u8) -> Result<u64> {
        Ok(0)
    }

    fn write(&self, _offset: u64, _size: u8, val: u64) -> Result<Action> {
        if val as u8 == FADT_RESET_VAL {
            Ok(Action::Reset)
        } else {
            Ok(Action::None)
        }
    }
}

#[derive(Debug)]
pub struct FadtSleepControl;

impl Mmio for FadtSleepControl {
    fn size(&self) -> u64 {
        1
    }

    fn read(&self, _offset: u64, _size: u8) -> Result<u64> {
        Ok(0)
    }

    fn write(&self, _offset: u64, _size: u8, val: u64) -> Result<Action> {
        let val = FadtSleepControlReg(val as u8);
        if val.slp_en() && val.sle_typx() == 5 {
            Ok(Action::Shutdown)
        } else {
            Ok(Action::None)
        }
    }
}

// The following AcpiPmTimer implementation is derived from Cloud Hypervisor.
// Copyright © 2019 Intel Corporation

/// Power Management Timer
///
/// ACPI v6.5, Sec. 4.8.2.1
#[derive(Debug)]
pub struct AcpiPmTimer {
    start: Instant,
}

const PM_TIMER_FREQUENCY_HZ: u128 = 3_579_545;

impl AcpiPmTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for AcpiPmTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmio for AcpiPmTimer {
    fn read(&self, _offset: u64, _size: u8) -> Result<u64> {
        let nanos = Instant::now().duration_since(self.start).as_nanos();
        let counter = nanos * PM_TIMER_FREQUENCY_HZ / 1_000_000_000;
        Ok(counter as u32 as u64)
    }

    fn write(&self, _offset: u64, _size: u8, _val: u64) -> Result<Action> {
        Ok(Action::None)
    }

    fn size(&self) -> u64 {
        4
    }
}

#[cfg(test)]
#[path = "reg_test.rs"]
mod tests;
