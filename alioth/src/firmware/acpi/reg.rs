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
