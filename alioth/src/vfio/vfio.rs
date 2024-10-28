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

pub mod bindings;
pub mod cdev;
pub mod container;
pub mod device;
pub mod group;
pub mod ioctls;
pub mod iommu;
pub mod pci;

use std::path::{Path, PathBuf};

use bindings::VfioIommu;
use serde::Deserialize;
use serde_aco::Help;
use snafu::Snafu;

use crate::errors::{trace_error, DebugTrace};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Failed to access guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Cannot access device {path:?}"))]
    AccessDevice {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("Not supported PCI header type {ty:#x}"))]
    NotSupportedHeader { ty: u8 },
    #[snafu(display("Setting container iommu to {new:?}, but it already has {current:?}"))]
    SetContainerIommu { current: VfioIommu, new: VfioIommu },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Deserialize, Help)]
pub struct VfioParam {
    /// Path to a VFIO cdev, e.g. /dev/vfio/devices/vfio0.
    pub cdev: Box<Path>,
    /// Path to the iommu device. [default: /dev/iommu]
    pub dev_iommu: Option<Box<Path>>,
}
