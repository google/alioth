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

#[path = "acpi/acpi.rs"]
#[cfg(target_arch = "x86_64")]
pub mod acpi;
#[path = "dt/dt.rs"]
pub mod dt;
#[path = "ovmf/ovmf.rs"]
pub mod ovmf;

use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};

use self::ovmf::x86_64::tdx::{TDVF_SIGNATURE, TDVF_VERSION};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Firmware missing {name}"))]
    MissingMetadata { name: &'static str },
    #[snafu(display("Firmware missing TDVF signature {TDVF_SIGNATURE:08x}, got {got:08x}"))]
    MissingTdvfSignature { got: u32 },
    #[snafu(display("Firmware missing TDVF version {TDVF_VERSION}, got {got}"))]
    MissingTdvfVersion { got: u32 },
    #[snafu(display("Invalid firmware data layout"))]
    InvalidLayout,
}

type Result<T, E = Error> = std::result::Result<T, E>;
