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

use std::cmp;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::fd::{AsFd, BorrowedFd};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;

use parking_lot::Mutex;
use snafu::ResultExt;

use crate::arch::reg::MpidrEl1;
use crate::hv::hvf::vcpu::{HvfVcpu, encode_mpidr};
use crate::hv::hvf::{OsObject, check_ret};
use crate::hv::{
    GicV2, GicV2m, GicV3, IoeventFd, IoeventFdRegistry, IrqFd, IrqSender, Its, MemMapOption,
    MsiSender, Result, Vm, VmMemory, error,
};
use crate::sys::hvf::{
    HvMemoryFlag, hv_gic_config_create, hv_gic_config_set_distributor_base,
    hv_gic_config_set_msi_interrupt_range, hv_gic_config_set_msi_region_base,
    hv_gic_config_set_redistributor_base, hv_gic_create, hv_gic_get_spi_interrupt_range,
    hv_gic_send_msi, hv_gic_set_spi, hv_vcpus_exit, hv_vm_create, hv_vm_destroy, hv_vm_map,
    hv_vm_unmap,
};

#[derive(Debug)]
pub struct HvfMemory;

impl VmMemory for HvfMemory {
    fn deregister_encrypted_range(&self, _range: &[u8]) -> Result<()> {
        Err(ErrorKind::Unsupported.into()).context(error::EncryptedRegion)
    }

    fn mem_map(&self, gpa: u64, size: u64, hva: usize, option: MemMapOption) -> Result<()> {
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
        check_ret(ret).context(error::GuestMap { hva, gpa, size })
    }

    fn register_encrypted_range(&self, _range: &[u8]) -> Result<()> {
        Err(ErrorKind::Unsupported.into()).context(error::EncryptedRegion)
    }

    fn unmap(&self, gpa: u64, size: u64) -> Result<()> {
        let ret = unsafe { hv_vm_unmap(gpa, size as usize) };
        check_ret(ret).context(error::GuestUnmap { gpa, size })?;
        Ok(())
    }

    fn mark_private_memory(&self, _gpa: u64, _size: u64, _private: bool) -> Result<()> {
        Err(ErrorKind::Unsupported.into()).context(error::EncryptedRegion)
    }

    fn reset(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct HvfIrqSender {
    spi: u32,
}

impl IrqSender for HvfIrqSender {
    fn send(&self) -> Result<()> {
        let ret = unsafe { hv_gic_set_spi(self.spi, true) };
        check_ret(ret).context(error::SendInterrupt)
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

    fn set_masked(&self, _val: bool) -> Result<bool> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct HvfMsiSender;

impl MsiSender for HvfMsiSender {
    type IrqFd = HvfIrqFd;

    fn create_irqfd(&self) -> Result<Self::IrqFd> {
        unimplemented!()
    }

    fn send(&self, addr: u64, data: u32) -> Result<()> {
        let ret = unsafe { hv_gic_send_msi(addr, data) };
        check_ret(ret).context(error::SendInterrupt)
    }
}

#[derive(Debug)]
pub struct HvfIoeventFd {}

impl IoeventFd for HvfIoeventFd {}

impl AsFd for HvfIoeventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unreachable!()
    }
}

#[derive(Debug)]
pub struct HvfIoeventFdRegistry;

impl IoeventFdRegistry for HvfIoeventFdRegistry {
    type IoeventFd = HvfIoeventFd;

    fn create(&self) -> Result<Self::IoeventFd> {
        Err(ErrorKind::Unsupported.into()).context(error::IoeventFd)
    }

    fn deregister(&self, _fd: &Self::IoeventFd) -> Result<()> {
        unreachable!()
    }

    fn register(
        &self,
        _fd: &Self::IoeventFd,
        _gpa: u64,
        _len: u8,
        _data: Option<u64>,
    ) -> Result<()> {
        unreachable!()
    }
}

#[derive(Debug)]
pub struct HvfGicV2;

impl GicV2 for HvfGicV2 {
    fn init(&self) -> Result<()> {
        unreachable!()
    }

    fn get_dist_reg(&self, _cpu_index: u32, _offset: u16) -> Result<u32> {
        unreachable!()
    }

    fn set_dist_reg(&self, _cpu_index: u32, _offset: u16, _val: u32) -> Result<()> {
        unreachable!()
    }

    fn get_cpu_reg(&self, _cpu_index: u32, _offset: u16) -> Result<u32> {
        unreachable!()
    }

    fn set_cpu_reg(&self, _cpu_index: u32, _offset: u16, _val: u32) -> Result<()> {
        unreachable!()
    }

    fn get_num_irqs(&self) -> Result<u32> {
        unreachable!()
    }

    fn set_num_irqs(&self, _val: u32) -> Result<()> {
        unreachable!()
    }
}

#[derive(Debug)]
pub struct HvfGicV3;

impl GicV3 for HvfGicV3 {
    fn init(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct HvfGicV2m;

impl GicV2m for HvfGicV2m {
    fn init(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct HvfIts;

impl Its for HvfIts {
    fn init(&self) -> Result<()> {
        unreachable!()
    }
}

#[derive(Debug)]
pub enum VcpuEvent {
    PowerOn { pc: u64, context: u64 },
    PowerOff,
}

#[derive(Debug)]
pub struct HvfVm {
    gic_config: Mutex<(OsObject, bool)>,
    pub vcpus: Mutex<HashMap<u32, u64>>,
    pub senders: Arc<Mutex<HashMap<MpidrEl1, Sender<VcpuEvent>>>>,
}

impl HvfVm {
    pub fn new() -> Result<Self> {
        let ret = unsafe { hv_vm_create(null_mut()) };
        check_ret(ret).context(error::CreateVm)?;
        Ok(HvfVm {
            gic_config: Mutex::new((OsObject { addr: 0 }, false)),
            vcpus: Mutex::new(HashMap::new()),
            senders: Arc::new(Mutex::new(HashMap::new())),
        })
    }
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
    type GicV2 = HvfGicV2;
    type GicV2m = HvfGicV2m;
    type GicV3 = HvfGicV3;
    type IoeventFdRegistry = HvfIoeventFdRegistry;
    type IrqSender = HvfIrqSender;
    type Its = HvfIts;
    type Memory = HvfMemory;
    type MsiSender = HvfMsiSender;
    type Vcpu = HvfVcpu;

    fn create_ioeventfd_registry(&self) -> Result<Self::IoeventFdRegistry> {
        Ok(HvfIoeventFdRegistry)
    }

    fn create_msi_sender(&self, _devid: u32) -> Result<Self::MsiSender> {
        Ok(HvfMsiSender)
    }

    fn create_vcpu(&self, id: u32) -> Result<Self::Vcpu> {
        let (config, created) = &mut *self.gic_config.lock();
        if config.addr != 0 && !*created {
            let ret = unsafe { hv_gic_create(config.addr as *mut _) };
            check_ret(ret).context(error::CreateDevice)?;
            *created = true;
        }

        HvfVcpu::new(self, id)
    }

    fn create_vm_memory(&mut self) -> Result<Self::Memory> {
        Ok(HvfMemory)
    }

    fn stop_vcpu<T>(&self, id: u32, _handle: &JoinHandle<T>) -> Result<()> {
        let vcpus = self.vcpus.lock();
        let senders = self.senders.lock();
        let Some(vcpu_id) = vcpus.get(&id) else {
            return Err(ErrorKind::NotFound.into()).context(error::StopVcpu);
        };
        let mpidr = encode_mpidr(id);
        let Some(sender) = senders.get(&mpidr) else {
            return Err(ErrorKind::NotFound.into()).context(error::StopVcpu);
        };
        if sender.send(VcpuEvent::PowerOff).is_err() {
            return Err(ErrorKind::BrokenPipe.into()).context(error::StopVcpu);
        };
        let ret = unsafe { hv_vcpus_exit(vcpu_id, 1) };
        check_ret(ret).context(error::StopVcpu)
    }

    fn create_gic_v2(
        &self,
        _distributor_base: u64,
        _cpu_interface_base: u64,
    ) -> Result<Self::GicV2> {
        Err(ErrorKind::Unsupported.into()).context(error::CreateDevice)
    }

    fn create_irq_sender(&self, pin: u8) -> Result<Self::IrqSender> {
        let mut spi_base = 0;
        let mut count = 0;
        let ret = unsafe { hv_gic_get_spi_interrupt_range(&mut spi_base, &mut count) };
        check_ret(ret).context(error::CreateDevice)?;
        Ok(HvfIrqSender {
            spi: spi_base + pin as u32,
        })
    }

    fn create_gic_v3(
        &self,
        distributor_base: u64,
        redistributor_base: u64,
        _redistributor_count: u32,
    ) -> Result<Self::GicV3> {
        let (config, _) = &mut *self.gic_config.lock();
        if config.addr == 0 {
            *config = OsObject {
                addr: unsafe { hv_gic_config_create() } as usize,
            };
        }
        let ptr = config.addr as *mut _;
        let ret = unsafe { hv_gic_config_set_distributor_base(ptr, distributor_base) };
        check_ret(ret).context(error::CreateDevice)?;
        let ret = unsafe { hv_gic_config_set_redistributor_base(ptr, redistributor_base) };
        check_ret(ret).context(error::CreateDevice)?;

        Ok(HvfGicV3)
    }

    fn create_gic_v2m(&self, base: u64) -> Result<Self::GicV2m> {
        let (config, _) = &mut *self.gic_config.lock();
        if config.addr == 0 {
            *config = OsObject {
                addr: unsafe { hv_gic_config_create() } as usize,
            };
        }

        let ptr = config.addr as *mut _;
        let ret = unsafe { hv_gic_config_set_msi_region_base(ptr, base) };
        check_ret(ret).context(error::CreateDevice)?;

        let mut spi_base = 0;
        let mut count = 0;
        let ret = unsafe { hv_gic_get_spi_interrupt_range(&mut spi_base, &mut count) };
        check_ret(ret).context(error::CreateDevice)?;
        let count = cmp::min(count, 987);
        let ret = unsafe { hv_gic_config_set_msi_interrupt_range(ptr, spi_base + 32, count - 32) };
        check_ret(ret).context(error::CreateDevice)?;

        Ok(HvfGicV2m)
    }

    fn create_its(&self, _base: u64) -> Result<Self::Its> {
        Err(ErrorKind::Unsupported.into()).context(error::CreateDevice)
    }
}

#[cfg(test)]
#[path = "vm_test.rs"]
mod tests;
