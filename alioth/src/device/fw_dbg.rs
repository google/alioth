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

use parking_lot::Mutex;

use crate::device::{MmioDev, Pause, Result};
use crate::mem;
use crate::mem::emulated::{Action, Mmio};

#[derive(Debug, Default)]
pub struct FwDbg {
    buffer: Mutex<Vec<u8>>,
}

impl FwDbg {
    pub fn new() -> Self {
        FwDbg::default()
    }
}

impl Mmio for FwDbg {
    fn size(&self) -> u64 {
        1
    }

    fn read(&self, _offset: u64, _size: u8) -> mem::Result<u64> {
        Ok(0xe9)
    }

    fn write(&self, _offset: u64, _size: u8, val: u64) -> mem::Result<Action> {
        let mut buffer = self.buffer.lock();
        if val as u8 == b'\n' {
            log::debug!("{}", String::from_utf8_lossy(&buffer));
            buffer.clear();
        } else {
            buffer.push(val as u8);
        }
        Ok(Action::None)
    }
}

impl Pause for FwDbg {
    fn pause(&self) -> Result<()> {
        Ok(())
    }

    fn resume(&self) -> Result<()> {
        Ok(())
    }
}

impl MmioDev for FwDbg {}
