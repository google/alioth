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

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};
use std::ptr::null_mut;
use std::thread::JoinHandle;

use parking_lot::Mutex;
use snafu::ResultExt;

use crate::hv::hvf::bindings::{
    hv_vcpu_create, hv_vm_destroy, hv_vm_map, hv_vm_unmap, HvMemoryFlag,
};
use crate::hv::hvf::check_ret;
use crate::hv::hvf::vcpu::HvfVcpu;
use crate::hv::{
    error, GicV2, IoeventFd, IoeventFdRegistry, IrqFd, IrqSender, MemMapOption, MsiSender, Result,
    Vm, VmMemory,
};

#[derive(Debug)]
pub struct HvfMemory {}

impl VmMemory for HvfMemory {
    fn deregister_encrypted_range(&self, _range: &[u8]) -> Result<()> {
        unimplemented!()
    }
    fn max_mem_slots(&self) -> Result<u32> {
        error::Capability { cap: "MaxMemSlots" }.fail()
    }
    fn mem_map(
        &self,
        _slot: u32,
        gpa: u64,
        size: u64,
        hva: usize,
        option: MemMapOption,
    ) -> Result<()> {
        if option.log_dirty {
            return error::Capability { cap: "log dirty" }.fail();
        }
        let mut flags = HvMemoryFlag::empty();
        if option.read {
            flags |= HvMemoryFlag::READ;
        }
        if option.write {
            flags |= HvMemoryFlag::WRITE;
        }
        if option.exec {
            flags |= HvMemoryFlag::EXEC;
        }
        let ret = unsafe { hv_vm_map(hva as *const u8, gpa, size as usize, flags) };
        check_ret(ret).context(error::GuestMap { hva, gpa, size })?;
        Ok(())
    }

    fn register_encrypted_range(&self, _range: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn unmap(&self, _slot: u32, gpa: u64, size: u64) -> Result<()> {
        let ret = unsafe { hv_vm_unmap(gpa, size as usize) };
        check_ret(ret).context(error::GuestUnmap { gpa, size })?;
        Ok(())
    }

    fn mark_private_memory(&self, _gpa: u64, _size: u64, _private: bool) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfIrqSender {}
impl IrqSender for HvfIrqSender {
    fn send(&self) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfIrqFd {}
impl AsFd for HvfIrqFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unimplemented!()
    }
}
impl IrqFd for HvfIrqFd {
    fn get_addr_hi(&self) -> u32 {
        unimplemented!()
    }
    fn get_addr_lo(&self) -> u32 {
        unimplemented!()
    }
    fn get_data(&self) -> u32 {
        unimplemented!()
    }
    fn get_masked(&self) -> bool {
        unimplemented!()
    }
    fn set_addr_hi(&self, _val: u32) -> Result<()> {
        unimplemented!()
    }
    fn set_addr_lo(&self, _val: u32) -> Result<()> {
        unimplemented!()
    }
    fn set_data(&self, _val: u32) -> Result<()> {
        unimplemented!()
    }
    fn set_masked(&self, _val: bool) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfMsiSender {}

impl MsiSender for HvfMsiSender {
    type IrqFd = HvfIrqFd;
    fn create_irqfd(&self) -> Result<Self::IrqFd> {
        unimplemented!()
    }
    fn send(&self, _addr: u64, _data: u32) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfIoeventFd {}

impl IoeventFd for HvfIoeventFd {}

impl AsFd for HvfIoeventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfIoeventFdRegistry {}

impl IoeventFdRegistry for HvfIoeventFdRegistry {
    type IoeventFd = HvfIoeventFd;
    fn create(&self) -> Result<Self::IoeventFd> {
        unimplemented!()
    }
    fn deregister(&self, _fd: &Self::IoeventFd) -> Result<()> {
        unimplemented!()
    }
    fn register(
        &self,
        _fd: &Self::IoeventFd,
        _gpa: u64,
        _len: u8,
        _data: Option<u64>,
    ) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfGicV2 {}

impl GicV2 for HvfGicV2 {
    fn init(&self) -> Result<()> {
        unimplemented!()
    }
    fn get_dist_reg(&self, _cpu_index: u32, _offset: u16) -> Result<u32> {
        unimplemented!()
    }
    fn set_dist_reg(&self, _cpu_index: u32, _offset: u16, _val: u32) -> Result<()> {
        unimplemented!()
    }
    fn get_cpu_reg(&self, _cpu_index: u32, _offset: u16) -> Result<u32> {
        unimplemented!()
    }
    fn set_cpu_reg(&self, _cpu_index: u32, _offset: u16, _val: u32) -> Result<()> {
        unimplemented!()
    }
    fn get_num_irqs(&self) -> Result<u32> {
        unimplemented!()
    }
    fn set_num_irqs(&self, _val: u32) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfVm {
    pub(super) vcpus: Mutex<HashMap<u32, u64>>,
}

impl Drop for HvfVm {
    fn drop(&mut self) {
        let ret = unsafe { hv_vm_destroy() };
        if let Err(e) = check_ret(ret) {
            log::error!("hv_vm_destroy: {e:?}");
        }
    }
}

impl Vm for HvfVm {
    type Vcpu = HvfVcpu;
    type Memory = HvfMemory;
    type MsiSender = HvfMsiSender;
    type IoeventFdRegistry = HvfIoeventFdRegistry;
    fn create_ioeventfd_registry(&self) -> Result<Self::IoeventFdRegistry> {
        unimplemented!()
    }
    fn create_msi_sender(&self) -> Result<Self::MsiSender> {
        unimplemented!()
    }
    fn create_vcpu(&self, id: u32) -> Result<Self::Vcpu> {
        let mut exit = null_mut();
        let mut vcpu_id = 0;
        let ret = unsafe { hv_vcpu_create(&mut vcpu_id, &mut exit, null_mut()) };
        check_ret(ret).context(error::CreateVcpu)?;
        self.vcpus.lock().insert(id, vcpu_id);
        Ok(HvfVcpu { exit, vcpu_id })
    }
    fn create_vm_memory(&mut self) -> Result<Self::Memory> {
        unimplemented!()
    }
    fn stop_vcpu<T>(_id: u32, _handle: &JoinHandle<T>) -> Result<()> {
        unimplemented!()
    }

    type GicV2 = HvfGicV2;

    fn create_gic_v2(
        &self,
        _distributor_base: u64,
        _cpu_interface_base: u64,
    ) -> Result<Self::GicV2> {
        unimplemented!()
    }

    type IrqSender = HvfIrqSender;
    fn create_irq_sender(&self, _pin: u8) -> Result<Self::IrqSender> {
        unimplemented!()
    }
}
