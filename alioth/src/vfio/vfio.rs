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

pub mod cdev;
pub mod container;
pub mod device;
pub mod group;
pub mod iommu;
pub mod pci;

use std::path::Path;

use serde::Deserialize;
use serde_aco::Help;
use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};
use crate::sys::vfio::VfioIommu;

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
        path: Box<Path>,
        error: std::io::Error,
    },
    #[snafu(display("Not supported PCI header type {ty:#x}"))]
    NotSupportedHeader { ty: u8 },
    #[snafu(display("Setting container iommu to {new:?}, but it already has {current:?}"))]
    SetContainerIommu { current: VfioIommu, new: VfioIommu },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub struct CdevParam {
    /// Path to a VFIO cdev, e.g. /dev/vfio/devices/vfio0.
    pub path: Box<Path>,
    /// Name of the IO Address space to which this device should be attached.
    pub ioas: Option<Box<str>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub struct IoasParam {
    /// Name of the IO Address space.
    pub name: Box<str>,
    /// Path to the iommu device. [default: /dev/iommu]
    pub dev_iommu: Option<Box<Path>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub struct GroupParam {
    /// Path to a VFIO group file, e.g. /dev/vfio/12.
    pub path: Box<Path>,
    /// Device ID, e.g. 0000:06:0d.0.
    #[serde(default)]
    pub devices: Vec<Box<str>>,
    /// Name of the container to which this device should be attached.
    pub container: Option<Box<str>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub struct ContainerParam {
    /// Name of the Container.
    pub name: Box<str>,
    /// Path to the vfio device. [default: /dev/vfio/vfio]
    pub dev_vfio: Option<Box<Path>>,
}
