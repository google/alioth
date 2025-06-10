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

use std::error::Error;
use std::fmt;

use snafu::{ErrorCompat, IntoError, ResultExt};

pub use alioth_macros::{DebugTrace, trace_error};

pub trait DebugTrace: Error {
    fn debug_trace(&self, f: &mut fmt::Formatter) -> Result<u32, fmt::Error>;
}

impl Error for Box<dyn DebugTrace + Send + Sync + 'static> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Error::source(Box::as_ref(self))
    }
}

pub trait BoxTrace<'a, T> {
    fn box_trace<C, E>(self, context: C) -> Result<T, E>
    where
        C: IntoError<E, Source = Box<dyn DebugTrace + Send + Sync + 'a>>,
        E: Error + ErrorCompat;
}

impl<'a, T, E1> BoxTrace<'a, T> for Result<T, E1>
where
    E1: DebugTrace + Send + Sync + 'a,
{
    fn box_trace<C, E>(self, context: C) -> Result<T, E>
    where
        C: IntoError<E, Source = Box<dyn DebugTrace + Send + Sync + 'a>>,
        E: Error + ErrorCompat,
    {
        self.map_err(|e| Box::new(e) as _).context(context)
    }
}
