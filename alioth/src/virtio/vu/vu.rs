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

pub mod backend;
pub mod bindings;
pub mod conn;
pub mod frontend;

use std::path::PathBuf;

use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};
use crate::virtio::vu::bindings::VuFeature;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Cannot access socket {path:?}"))]
    AccessSocket {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("vhost-user message ({req:#x}) missing fd"))]
    MissingFd { req: u32 },
    #[snafu(display("Unexpected vhost-user response, want {want}, got {got}"))]
    Response { want: u32, got: u32 },
    #[snafu(display("Unexpected vhost-user message size, want {want}, get {got}"))]
    MsgSize { want: usize, got: usize },
    #[snafu(display("Failed to send {want} bytes, only {done} bytes were sent"))]
    PartialWrite { want: usize, done: usize },
    #[snafu(display("Invalid vhost-user message payload size, want {want}, got {got}"))]
    PayloadSize { want: usize, got: u32 },
    #[snafu(display("vhost-user backend replied error code {ret:#x} to request {req:#x}"))]
    RequestErr { ret: u64, req: u32 },
    #[snafu(display("vhost-user backend signaled an error of queue {index:#x}"))]
    QueueErr { index: u16 },
    #[snafu(display("vhost-user backend is missing device feature {feature:#x}"))]
    DeviceFeature { feature: u128 },
    #[snafu(display("vhost-user backend is missing protocol feature {feature:x?}"))]
    ProtocolFeature { feature: VuFeature },
}

type Result<T, E = Error> = std::result::Result<T, E>;
