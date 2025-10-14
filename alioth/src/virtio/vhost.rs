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

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use snafu::{ResultExt, Snafu};

use crate::errors::{BoxTrace, DebugTrace, trace_error};
use crate::mem::mapped::Ram;
use crate::mem::{self, LayoutUpdated};
use crate::sys::vhost::{
    MemoryMultipleRegion, MemoryRegion, VhostFeature, VirtqAddr, VirtqFile, VirtqState,
    vhost_get_backend_features, vhost_get_features, vhost_set_backend_features, vhost_set_features,
    vhost_set_mem_table, vhost_set_owner, vhost_set_virtq_addr, vhost_set_virtq_base,
    vhost_set_virtq_call, vhost_set_virtq_err, vhost_set_virtq_kick, vhost_set_virtq_num,
    vhost_vsock_set_guest_cid, vhost_vsock_set_running,
};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Cannot access device {path:?}"))]
    AccessDevice {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("vhost backend is missing device feature {feature:#x}"))]
    VhostMissingDeviceFeature { feature: u128 },
    #[snafu(display("vhost-{dev} signals an error of queue {index:#x}"))]
    VhostQueueErr { dev: &'static str, index: u16 },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct VhostDev {
    fd: File,
}

impl VhostDev {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let fd = File::open(&path).context(error::AccessDevice {
            path: path.as_ref(),
        })?;
        Ok(VhostDev { fd })
    }

    pub fn get_features(&self) -> Result<u64> {
        let feat = unsafe { vhost_get_features(&self.fd) }?;
        Ok(feat)
    }

    pub fn set_features(&self, val: &u64) -> Result<()> {
        unsafe { vhost_set_features(&self.fd, val) }?;
        Ok(())
    }

    pub fn get_backend_features(&self) -> Result<VhostFeature> {
        let feat = unsafe { vhost_get_backend_features(&self.fd) }?;
        Ok(VhostFeature::from_bits_retain(feat))
    }

    pub fn set_backend_features(&self, val: &VhostFeature) -> Result<()> {
        unsafe { vhost_set_backend_features(&self.fd, &val.bits()) }?;
        Ok(())
    }

    pub fn set_owner(&self) -> Result<()> {
        unsafe { vhost_set_owner(&self.fd) }?;
        Ok(())
    }

    pub fn set_virtq_num(&self, state: &VirtqState) -> Result<()> {
        unsafe { vhost_set_virtq_num(&self.fd, state) }?;
        Ok(())
    }

    pub fn set_virtq_addr(&self, addr: &VirtqAddr) -> Result<()> {
        unsafe { vhost_set_virtq_addr(&self.fd, addr) }?;
        Ok(())
    }

    pub fn set_virtq_base(&self, state: &VirtqState) -> Result<()> {
        unsafe { vhost_set_virtq_base(&self.fd, state) }?;
        Ok(())
    }

    pub fn set_virtq_kick(&self, file: &VirtqFile) -> Result<()> {
        unsafe { vhost_set_virtq_kick(&self.fd, file) }?;
        Ok(())
    }

    pub fn set_virtq_call(&self, file: &VirtqFile) -> Result<()> {
        unsafe { vhost_set_virtq_call(&self.fd, file) }?;
        Ok(())
    }

    pub fn set_virtq_err(&self, file: &VirtqFile) -> Result<()> {
        unsafe { vhost_set_virtq_err(&self.fd, file) }?;
        Ok(())
    }

    pub fn set_mem_table<const N: usize>(&self, table: &MemoryMultipleRegion<N>) -> Result<()> {
        unsafe { vhost_set_mem_table(&self.fd, table) }?;
        Ok(())
    }

    pub fn vsock_set_guest_cid(&self, cid: u64) -> Result<()> {
        unsafe { vhost_vsock_set_guest_cid(&self.fd, &cid) }?;
        Ok(())
    }

    pub fn vsock_set_running(&self, val: bool) -> Result<()> {
        unsafe { vhost_vsock_set_running(&self.fd, &(val as _)) }?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct UpdateVsockMem {
    pub dev: Arc<VhostDev>,
}

impl LayoutUpdated for UpdateVsockMem {
    fn ram_updated(&self, ram: &Ram) -> mem::Result<()> {
        let mut table = MemoryMultipleRegion {
            num: 0,
            _padding: 0,
            regions: [MemoryRegion::default(); 64],
        };
        for (index, (gpa, user_mem)) in ram.iter().enumerate() {
            table.num += 1;
            table.regions[index].gpa = gpa;
            table.regions[index].hva = user_mem.addr() as u64;
            table.regions[index].size = user_mem.size();
        }
        let ret = self.dev.set_mem_table(&table);
        ret.box_trace(mem::error::ChangeLayout)?;
        log::trace!(
            "vhost-{}: updated mem table to {:x?}",
            self.dev.fd.as_raw_fd(),
            &table.regions[..table.num as usize]
        );
        Ok(())
    }
}
