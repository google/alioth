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

use std::os::fd::OwnedFd;

use crate::hv::kvm::Kvm;
use crate::hv::kvm::vm::KvmVm;
use crate::hv::{Result, VmConfig};
use crate::sys::kvm::KvmVmType;

impl Kvm {
    pub(super) fn determine_vm_type(_config: &VmConfig) -> Result<KvmVmType> {
        Ok(KvmVmType(0))
    }

    pub(super) fn create_guest_memfd(
        &self,
        _config: &VmConfig,
        _vm_fd: &OwnedFd,
    ) -> Result<Option<OwnedFd>> {
        Ok(None)
    }

    pub(super) fn vm_init_arch(&self, _config: &VmConfig, _kvm_vm: &KvmVm) -> Result<()> {
        Ok(())
    }
}
