// Copyright 2026 Google LLC
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

use crate::hv::Result;
use crate::hv::kvm::tdx::tdx_op;
use crate::hv::kvm::vcpu::KvmVcpu;
use crate::sys::tdx::{KvmTdxCmdId, KvmTdxInitMemRegion, KvmTdxInitMemRegionFlag};

impl KvmVcpu {
    pub fn tdx_init_mem_region(&self, data: &[u8], gpa: u64, measure: bool) -> Result<()> {
        let mut region = KvmTdxInitMemRegion {
            source_addr: data.as_ptr() as u64,
            nr_pages: data.len() as u64 >> 12,
            gpa,
        };
        let flag = if measure {
            KvmTdxInitMemRegionFlag::MEASURE_MEMORY_REGION
        } else {
            KvmTdxInitMemRegionFlag::empty()
        };
        tdx_op(
            &self.fd,
            KvmTdxCmdId::INIT_MEM_REGION,
            flag.bits(),
            Some(&mut region),
        )
    }
}
