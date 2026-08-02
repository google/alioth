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

pub mod bindings;
pub mod conn;
pub mod device;

use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};
use crate::vfio::user::bindings::{VfioUserCmd, VfioUserHeaderFlag};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Unexpected vfio-user response, want {want:?}, got {got:?}"))]
    Response { want: VfioUserCmd, got: VfioUserCmd },
    #[snafu(display("Unexpected vfio-user message id, want {want}, got {got}"))]
    MsgId { want: u16, got: u16 },
    #[snafu(display("Unexpected vfio-user message flags {flags:?}"))]
    HeaderFlag { flags: VfioUserHeaderFlag },
    #[snafu(display("Failed to send {want} bytes, only {done} bytes were sent"))]
    PartialWrite { want: usize, done: usize },
    #[snafu(display("Failed to read {want} bytes, only {done} bytes were read"))]
    PartialRead { want: usize, done: usize },
    #[snafu(display("Unsupported vfio-user version {major}.{minor}"))]
    Version { major: u16, minor: u16 },
    #[snafu(display("Server error: cmd {cmd:?}, error code {code}"))]
    ServerErr { cmd: VfioUserCmd, code: u32 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
