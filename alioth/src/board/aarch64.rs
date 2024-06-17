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

use crate::board::{Board, BoardConfig, Result, VcpuGuard};
use crate::hv::{Hypervisor, Vm};
use crate::loader::InitState;
use crate::mem::mapped::ArcMemPages;

pub struct ArchBoard {}

impl ArchBoard {
    pub fn new<H: Hypervisor>(_hv: &H, _config: &BoardConfig) -> Result<Self> {
        unimplemented!()
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn setup_firmware(&self, _fw: &mut ArcMemPages) -> Result<()> {
        unimplemented!()
    }

    pub fn init_ap(&self, _id: u32, _vcpu: &mut V::Vcpu, _vcpus: &VcpuGuard) -> Result<()> {
        unimplemented!()
    }

    pub fn init_boot_vcpu(&self, _vcpu: &mut V::Vcpu, _init_state: &InitState) -> Result<()> {
        unimplemented!()
    }

    pub fn init_vcpu(&self, _id: u32, _vcpu: &mut V::Vcpu) -> Result<()> {
        unimplemented!()
    }

    pub fn create_ram(&self) -> Result<()> {
        unimplemented!()
    }

    pub fn coco_init(&self, _id: u32) -> Result<()> {
        unimplemented!()
    }

    pub fn coco_finalize(&self, _id: u32, _vcpus: &VcpuGuard) -> Result<()> {
        unimplemented!()
    }

    pub fn create_firmware_data(&self, _init_state: &InitState) -> Result<()> {
        unimplemented!()
    }
}
