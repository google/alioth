// Copyright 2025 Google LLC
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

#[cfg(target_os = "linux")]
use std::path::Path;

use alioth::board::BoardSpec;
use alioth::device::console::ConsoleSpec;
#[cfg(target_arch = "x86_64")]
use alioth::device::fw_cfg::FwCfgItemSpec;
use alioth::loader::PayloadSpec;
#[cfg(target_os = "linux")]
use alioth::vfio::{VfioCdevSpec, VfioContainerSpec, VfioGroupSpec, VfioIoasSpec};
use alioth::virtio::dev::balloon::BalloonSpec;
use alioth::virtio::dev::blk::BlkFileSpec;
use alioth::virtio::dev::entropy::EntropySpec;
use alioth::virtio::dev::fs::shared_dir::SharedDirSpec;
#[cfg(target_os = "macos")]
use alioth::virtio::dev::net::vmnet::VmnetSpec;
use alioth::virtio::dev::vsock::UdsVsockSpec;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::{fs::vu::VuFsSpec, net::tap::TapNetSpec, vsock::VhostVsockSpec};
use serde::Deserialize;
use serde_aco::Help;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct VuSocket {
    pub socket: Box<Path>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub enum NetSpec {
    /// VirtIO net device backed by TUN/TAP, MacVTap, or IPVTap.
    #[cfg(target_os = "linux")]
    #[serde(alias = "tap")]
    Tap(TapNetSpec),
    /// VirtIO net device backed by vmnet framework.
    #[cfg(target_os = "macos")]
    #[serde(alias = "vmnet")]
    Vmnet(VmnetSpec),
    /// vhost-user net device over a Unix domain socket.
    #[cfg(target_os = "linux")]
    #[serde(alias = "vu")]
    Vu(VuSocket),
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub enum BlkSpec {
    /// VirtIO block device backed a disk image file.
    #[serde(alias = "file")]
    File(BlkFileSpec),
    #[cfg(target_os = "linux")]
    #[serde(alias = "vu")]
    /// vhost-user block device over a Unix domain socket.
    Vu(VuSocket),
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone, Help)]
pub enum FsSpec {
    /// VirtIO FS device backed by a shared directory.
    #[serde(alias = "dir")]
    Dir(SharedDirSpec),
    #[cfg(target_os = "linux")]
    /// VirtIO FS device backed by a vhost-user process, e.g. virtiofsd.
    #[serde(alias = "vu")]
    Vu(VuFsSpec),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub enum VsockSpec {
    #[cfg(target_os = "linux")]
    /// Vsock device backed by host kernel vhost-vsock module.
    #[serde(alias = "vhost")]
    Vhost(VhostVsockSpec),
    /// Vsock device mapped to a Unix domain socket.
    #[serde(alias = "uds")]
    Uds(UdsVsockSpec),
    #[cfg(target_os = "linux")]
    /// Vsock device backed by a vhost-user process.
    #[serde(alias = "vu")]
    Vu(VuSocket),
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct VmSpec {
    pub board: BoardSpec,

    pub payload: PayloadSpec,

    pub console: ConsoleSpec,
    pub net: Vec<NetSpec>,
    pub blk: Vec<BlkSpec>,
    pub fs: Vec<FsSpec>,
    pub vsock: Option<VsockSpec>,
    pub entropy: Option<EntropySpec>,
    pub balloon: Option<BalloonSpec>,
    pub pvpanic: bool,

    #[cfg(target_arch = "x86_64")]
    pub fw_cfg: Vec<FwCfgItemSpec>,

    #[cfg(target_os = "linux")]
    pub vfio_cdev: Vec<VfioCdevSpec>,
    #[cfg(target_os = "linux")]
    pub vfio_ioas: Vec<VfioIoasSpec>,
    #[cfg(target_os = "linux")]
    pub vfio_group: Vec<VfioGroupSpec>,
    #[cfg(target_os = "linux")]
    pub vfio_container: Vec<VfioContainerSpec>,
}
