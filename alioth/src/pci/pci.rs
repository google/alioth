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

pub mod bus;
pub mod cap;
pub mod config;
pub mod host_bridge;
pub mod pvpanic;
pub mod segment;

use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

use bitfield::bitfield;
use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};
use crate::mem::{IoRegion, MemRegion};

use self::config::PciConfig;

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Bdf(u16);
    impl Debug;
    impl new;
    pub u8, bus, set_bus: 15, 8;
    pub u8, dev, set_dev: 7, 3;
    pub u8, func, set_func: 2, 0;
}

impl Display for Bdf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}.{:x}", self.bus(), self.dev(), self.func())
    }
}

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to access guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("Failed to reset device"))]
    Reset {
        source: Box<dyn DebugTrace + Send + Sync + 'static>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait Pci: Debug + Send + Sync + 'static {
    fn name(&self) -> &str;
    fn config(&self) -> &dyn PciConfig;
    fn reset(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub enum PciBar {
    Empty,
    Mem(Arc<MemRegion>),
    Io(Arc<IoRegion>),
}
