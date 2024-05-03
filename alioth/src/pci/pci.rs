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
use parking_lot::RwLock;
use thiserror::Error;

use crate::mem;
use crate::mem::{IoRegion, MemRegion, MemRegionCallback};

pub mod bus;
pub mod cap;
pub mod config;
pub mod host_bridge;
pub mod segment;

use config::{HeaderData, PciConfig};

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

#[derive(Debug, Clone)]
pub enum PciBar {
    Empty,
    Mem32(Arc<MemRegion>),
    Mem64(Arc<MemRegion>),
    Io(Arc<IoRegion>),
}

impl PciBar {
    pub const fn empty_6() -> [PciBar; 6] {
        const EMPTY: PciBar = PciBar::Empty;
        [EMPTY; 6]
    }
}

#[derive(Debug)]
struct BarCallback {
    index: u8,
    is_64: bool,
    header: Arc<RwLock<HeaderData>>,
}

impl MemRegionCallback for BarCallback {
    fn mapped(&self, addr: usize) -> mem::Result<()> {
        self.header
            .write()
            .set_bar(self.index as usize, addr as u32);
        if self.is_64 {
            self.header
                .write()
                .set_bar(self.index as usize + 1, (addr >> 32) as u32);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PciDevice {
    pub name: Arc<String>,
    pub dev: Arc<dyn Pci>,
}

impl PciDevice {
    pub fn new(name: Arc<String>, dev: Arc<dyn Pci>) -> PciDevice {
        let config = dev.config();
        let dev_bars = &config.get_header().bars;
        for (index, dev_bar) in dev_bars.iter().enumerate() {
            let header = config.get_header().data.clone();
            match dev_bar {
                PciBar::Empty => {}
                PciBar::Mem32(region) => region.callbacks.lock().push(Box::new(BarCallback {
                    index: index as u8,
                    is_64: false,
                    header,
                })),
                PciBar::Mem64(region) => region.callbacks.lock().push(Box::new(BarCallback {
                    index: index as u8,
                    is_64: true,
                    header,
                })),
                PciBar::Io(region) => region.callbacks.lock().push(Box::new(BarCallback {
                    index: index as u8,
                    is_64: false,
                    header,
                })),
            }
        }
        PciDevice { name, dev }
    }
}
