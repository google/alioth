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

use serde::Deserialize;
use serde_aco::Help;

use crate::board::BoardConfig;
#[cfg(target_arch = "x86_64")]
use crate::device::fw_cfg::FwCfgItemParam;
use crate::loader::Payload;
use crate::virtio::dev::balloon::BalloonParam;
use crate::virtio::dev::blk::BlkFileParam;
use crate::virtio::dev::entropy::EntropyParam;
use crate::virtio::dev::fs::shared_dir::SharedDirParam;
#[cfg(target_os = "macos")]
use crate::virtio::dev::net::vmnet::NetVmnetParam;
use crate::virtio::dev::vsock::UdsVsockParam;
#[cfg(target_os = "linux")]
use crate::{
    vfio::{CdevParam, ContainerParam, GroupParam, IoasParam},
    virtio::dev::{fs::vu::VuFsParam, net::tap::NetTapParam, vsock::VhostVsockParam},
};

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub struct VuSocket {
    pub socket: Box<Path>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub enum NetParam {
    /// VirtIO net device backed by TUN/TAP, MacVTap, or IPVTap.
    #[cfg(target_os = "linux")]
    #[serde(alias = "tap")]
    Tap(NetTapParam),
    /// VirtIO net device backed by vmnet framework.
    #[cfg(target_os = "macos")]
    #[serde(alias = "vmnet")]
    Vmnet(NetVmnetParam),
    /// vhost-user net device over a Unix domain socket.
    #[cfg(target_os = "linux")]
    #[serde(alias = "vu")]
    Vu(VuSocket),
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub enum BlkParam {
    /// VirtIO block device backed a disk image file.
    #[serde(alias = "file")]
    File(BlkFileParam),
    #[cfg(target_os = "linux")]
    #[serde(alias = "vu")]
    /// vhost-user block device over a Unix domain socket.
    Vu(VuSocket),
}

#[derive(Debug, PartialEq, Eq, Deserialize, Clone, Help)]
pub enum FsParam {
    /// VirtIO FS device backed by a shared directory.
    #[serde(alias = "dir")]
    Dir(SharedDirParam),
    #[cfg(target_os = "linux")]
    /// VirtIO FS device backed by a vhost-user process, e.g. virtiofsd.
    #[serde(alias = "vu")]
    Vu(VuFsParam),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub enum VsockParam {
    #[cfg(target_os = "linux")]
    /// Vsock device backed by host kernel vhost-vsock module.
    #[serde(alias = "vhost")]
    Vhost(VhostVsockParam),
    /// Vsock device mapped to a Unix domain socket.
    #[serde(alias = "uds")]
    Uds(UdsVsockParam),
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Config {
    pub board: BoardConfig,

    pub payload: Payload,

    pub net: Vec<NetParam>,
    pub blk: Vec<BlkParam>,
    pub fs: Vec<FsParam>,
    pub vsock: Option<VsockParam>,
    pub entropy: Option<EntropyParam>,
    pub balloon: Option<BalloonParam>,
    pub pvpanic: bool,

    #[cfg(target_arch = "x86_64")]
    pub fw_cfg: Vec<FwCfgItemParam>,

    #[cfg(target_os = "linux")]
    pub vfio_cdev: Vec<CdevParam>,
    #[cfg(target_os = "linux")]
    pub vfio_ioas: Vec<IoasParam>,
    #[cfg(target_os = "linux")]
    pub vfio_group: Vec<GroupParam>,
    #[cfg(target_os = "linux")]
    pub vfio_container: Vec<ContainerParam>,
}
