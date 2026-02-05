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

use alioth_macros::trace_error;
use snafu::Snafu;

use crate::errors::DebugTrace;
use crate::mem::emulated::Mmio;

pub mod console;
#[cfg(target_arch = "x86_64")]
#[path = "fw_cfg/fw_cfg.rs"]
pub mod fw_cfg;
pub mod net;
#[cfg(target_arch = "aarch64")]
pub mod pl011;
#[cfg(target_arch = "aarch64")]
pub mod pl031;
#[cfg(target_arch = "x86_64")]
pub mod serial;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Device is not pausable"))]
    NotPausable,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait Pause {
    fn pause(&self) -> Result<()> {
        error::NotPausable.fail()
    }
    fn resume(&self) -> Result<()> {
        error::NotPausable.fail()
    }
}

pub trait MmioDev: Mmio + Pause {}
