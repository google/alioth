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
pub mod segment;

use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

use bitfield::bitfield;
use parking_lot::RwLock;
use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};
use crate::mem;
use crate::mem::{IoRegion, MemRegion, MemRegionCallback};

use self::config::{BAR_MEM64, HeaderData, PciConfig};

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Bdf(u16);
    impl Debug;
    pub u8, bus, _: 15, 8;
    pub dev, _: 7, 3;
    pub func, _: 2, 0;
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
    fn config(&self) -> &dyn PciConfig;
    fn reset(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub enum PciBar {
    Empty,
    Mem(Arc<MemRegion>),
    Io(Arc<IoRegion>),
}

#[derive(Debug)]
struct BarCallback {
    index: u8,
    header: Arc<RwLock<HeaderData>>,
}

impl MemRegionCallback for BarCallback {
    fn mapped(&self, addr: u64) -> mem::Result<()> {
        let mut header = self.header.write();
        let (old, _) = header.get_bar(self.index as usize);
        header.set_bar(self.index as usize, addr as u32);
        if old & BAR_MEM64 == BAR_MEM64 {
            header.set_bar(self.index as usize + 1, (addr >> 32) as u32);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PciDevice {
    pub name: Arc<str>,
    pub dev: Arc<dyn Pci>,
}

impl PciDevice {
    pub fn new(name: impl Into<Arc<str>>, dev: Arc<dyn Pci>) -> PciDevice {
        let config = dev.config();
        let dev_bars = &config.get_header().bars;
        for (index, dev_bar) in dev_bars.iter().enumerate() {
            let header = config.get_header().data.clone();
            match dev_bar {
                PciBar::Empty => {}
                PciBar::Mem(region) => region.callbacks.lock().push(Box::new(BarCallback {
                    index: index as u8,
                    header,
                })),
                PciBar::Io(region) => region.callbacks.lock().push(Box::new(BarCallback {
                    index: index as u8,
                    header,
                })),
            }
        }
        PciDevice {
            name: name.into(),
            dev,
        }
    }
}
