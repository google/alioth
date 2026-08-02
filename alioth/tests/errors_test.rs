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

use alioth::errors::{BoxTrace, DebugTrace};
use alioth_macros::trace_error;
use assert_matches::assert_matches;
use snafu::Snafu;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub), context(suffix(false)))]
pub enum Error {
    #[snafu(display("source error"))]
    Source,
    #[snafu(display("any error"))]
    Any {
        source: Box<dyn DebugTrace + Send + Sync + 'static>,
    },
}

#[test]
fn test_boxed_error_location() {
    let e1 = error::Source.build();
    let r: Result<(), _> = Err(e1).box_trace(error::Any);
    let e2 = r.unwrap_err();
    let location = assert_matches! {e2, Error::Any {  _location, .. } => _location};
    assert_eq!(location.file(), file!());
}
