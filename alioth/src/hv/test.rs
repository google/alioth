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

use super::{error, MemMapOption, Result};

#[derive(Debug)]
pub struct FakeVmMemory;

impl crate::hv::VmMemory for FakeVmMemory {
    fn mem_map(
        &self,
        _slot: u32,
        _gpa: u64,
        _size: u64,
        _hva: usize,
        _option: MemMapOption,
    ) -> Result<()> {
        Ok(())
    }

    fn unmap(&self, _slot: u32, _gpa: u64, _size: u64) -> Result<()> {
        Ok(())
    }

    fn max_mem_slots(&self) -> Result<u32> {
        error::Capability { cap: "MaxMemSlots" }.fail()
    }

    fn mark_private_memory(&self, _gpa: u64, _size: u64, _private: bool) -> Result<()> {
        unimplemented!()
    }
}
