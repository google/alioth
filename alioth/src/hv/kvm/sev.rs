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

use std::fmt::Debug;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use snafu::ResultExt;

use crate::arch::sev::SevStatus;
use crate::hv::Result;
use crate::hv::kvm::kvm_error;
use crate::sys::sev::{SevCmd, SevIssueCmd, sev_issue_cmd};

#[derive(Debug)]
pub struct SevFd {
    fd: OwnedFd,
}

impl AsFd for SevFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl SevFd {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let f = File::open(&path).context(kvm_error::OpenFile {
            path: path.as_ref(),
        })?;
        let sev_fd = Self { fd: f.into() };
        Ok(sev_fd)
    }

    #[allow(dead_code)]
    pub fn issue_cmd<T>(&self, cmd: SevCmd, data: &mut T) -> Result<()> {
        let mut req = SevIssueCmd {
            cmd,
            data: data as *mut T as _,
            error: SevStatus::SUCCESS,
        };
        unsafe { sev_issue_cmd(&self.fd, &mut req) }.context(kvm_error::SevCmd)?;
        if req.error != SevStatus::SUCCESS {
            return kvm_error::SevErr { code: req.error }.fail()?;
        }
        Ok(())
    }
}
