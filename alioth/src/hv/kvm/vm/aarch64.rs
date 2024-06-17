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

use std::mem::MaybeUninit;
use std::os::fd::{FromRawFd, OwnedFd};

use snafu::ResultExt;

use crate::hv::kvm::bindings::{
    KvmCreateDevice, KvmDevArmVgicCtrl, KvmDevArmVgicGrp, KvmDevType, KvmDeviceAttr,
    KvmVgicV2AddrType,
};
use crate::hv::kvm::ioctls::{kvm_create_device, kvm_get_device_attr, kvm_set_device_attr};
use crate::hv::kvm::vm::KvmVm;
use crate::hv::kvm::Result;
use crate::hv::{error, GicV2};

#[derive(Debug)]
pub struct KvmGicV2 {
    fd: OwnedFd,
}

impl KvmGicV2 {
    fn set_attr<T>(&self, group: u32, attr: u64, val: &T) -> Result<()> {
        let attr = KvmDeviceAttr {
            group,
            attr,
            addr: val as *const _ as _,
            _flags: 0,
        };
        unsafe { kvm_set_device_attr(&self.fd, &attr) }.context(error::SetVmParam)?;
        Ok(())
    }

    fn get_attr<T>(&self, group: u32, attr: u64) -> Result<T> {
        let mut val = MaybeUninit::uninit();
        let attr = KvmDeviceAttr {
            group,
            attr,
            addr: val.as_mut_ptr() as _,
            _flags: 0,
        };
        unsafe { kvm_get_device_attr(&self.fd, &attr) }.context(error::SetVmParam)?;
        Ok(unsafe { val.assume_init() })
    }
}

impl GicV2 for KvmGicV2 {
    fn init(&self) -> Result<()> {
        let attr = KvmDeviceAttr {
            group: KvmDevArmVgicGrp::CTL.raw(),
            attr: KvmDevArmVgicCtrl::INIT.raw(),
            addr: 0,
            _flags: 0,
        };
        unsafe { kvm_set_device_attr(&self.fd, &attr) }.context(error::SetVmParam)?;
        Ok(())
    }

    fn get_dist_reg(&self, cpu_index: u32, offset: u16) -> Result<u32> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        self.get_attr(KvmDevArmVgicGrp::DIST_REGS.raw(), attr)
    }

    fn set_dist_reg(&self, cpu_index: u32, offset: u16, val: u32) -> Result<()> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        self.set_attr(KvmDevArmVgicGrp::DIST_REGS.raw(), attr, &val)
    }

    fn get_cpu_reg(&self, cpu_index: u32, offset: u16) -> Result<u32> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        self.get_attr(KvmDevArmVgicGrp::CPU_REGS.raw(), attr)
    }
    fn set_cpu_reg(&self, cpu_index: u32, offset: u16, val: u32) -> Result<()> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        self.set_attr(KvmDevArmVgicGrp::CPU_REGS.raw(), attr, &val)
    }

    fn get_num_irqs(&self) -> Result<u32> {
        self.get_attr(KvmDevArmVgicGrp::NR_IRQS.raw(), 0)
    }

    fn set_num_irqs(&self, val: u32) -> Result<()> {
        self.set_attr(KvmDevArmVgicGrp::NR_IRQS.raw(), 0, &val)
    }
}

impl KvmVm {
    pub fn kvm_create_gic_v2(
        &self,
        distributor_base: u64,
        cpu_interface_base: u64,
    ) -> Result<KvmGicV2> {
        let mut create_device = KvmCreateDevice {
            type_: KvmDevType::ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        };
        unsafe { kvm_create_device(&self.vm, &mut create_device) }.context(error::CreateDevice)?;
        let gic = KvmGicV2 {
            fd: unsafe { OwnedFd::from_raw_fd(create_device.fd) },
        };
        gic.set_attr(
            KvmDevArmVgicGrp::ADDR.raw(),
            KvmVgicV2AddrType::DIST.raw(),
            &distributor_base,
        )?;
        gic.set_attr(
            KvmDevArmVgicGrp::ADDR.raw(),
            KvmVgicV2AddrType::CPU.raw(),
            &cpu_interface_base,
        )?;
        Ok(gic)
    }
}
