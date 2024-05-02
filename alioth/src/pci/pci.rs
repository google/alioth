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

use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

use bitfield::bitfield;
use thiserror::Error;

use crate::mem;

pub mod bus;
pub mod cap;
pub mod config;
pub mod segment;

use config::PciConfig;

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct Bdf(u16);
    impl Debug;
    bus, _: 15, 8;
    dev, _: 7, 3;
    func, _: 2, 0;
}

impl Display for Bdf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}.{:x}", self.bus(), self.dev(), self.func())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("{0:?} already exists")]
    BdfExists(Bdf),

    #[error("cannot find appropriate bdf")]
    NoBdfSlots,

    #[error("invalid bar index {0}")]
    InvalidBar(usize),

    #[error("reset failed")]
    ResetFailed,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait Pci: Debug + Send + Sync + 'static {
    fn config(&self) -> Arc<dyn PciConfig>;
    fn reset(&self) -> Result<()>;
}
