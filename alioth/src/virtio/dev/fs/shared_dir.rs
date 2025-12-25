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

use std::cmp::min;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use serde_aco::Help;

use crate::fuse::passthrough::Passthrough;
use crate::virtio::Result;
use crate::virtio::dev::DevParam;
use crate::virtio::dev::fs::{Fs, FsConfig};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct SharedDirParam {
    /// Mount tag seen by the guest.
    pub tag: String,
    /// Path to the shared dir.
    pub path: Box<Path>,
    /// Size of memory region for DAX in bytes.
    /// 0 means no DAX. [default: 0]
    #[serde(default)]
    pub dax_window: usize,
}

impl DevParam for SharedDirParam {
    type Device = Fs<Passthrough>;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Fs<Passthrough>> {
        let passthrough = Passthrough::new(self.path)?;
        let mut config = FsConfig {
            tag: [0; 36],
            num_request_queues: 1,
            notify_buf_size: 0,
        };
        let tag_size = min(config.tag.len(), self.tag.len());
        config.tag[0..tag_size].copy_from_slice(&self.tag.as_bytes()[0..tag_size]);
        Fs::new(name, passthrough, config, self.dax_window)
    }
}
