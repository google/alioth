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

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use snafu::ResultExt;

use crate::arch::intr::{MsiAddrHi, MsiAddrLo};
use crate::arch::ioapic::NUM_PINS;
use crate::arch::sev::{SevPolicy, SevStatus, SnpPageType, SnpPolicy};
use crate::hv::kvm::sev::SevFd;
use crate::hv::kvm::{KvmVm, kvm_error};
use crate::hv::{Coco, Kvm, Result, VmConfig, error};
use crate::sys::kvm::{
    KvmCap, KvmCreateGuestMemfd, KvmVmType, KvmX2apicApiFlag, kvm_create_guest_memfd,
    kvm_memory_encrypt_op, kvm_set_identity_map_addr, kvm_set_tss_addr,
};
use crate::sys::sev::{
    KvmSevCmd, KvmSevCmdId, KvmSevInit, KvmSevLaunchMeasure, KvmSevLaunchStart,
    KvmSevLaunchUpdateData, KvmSevSnpLaunchFinish, KvmSevSnpLaunchStart, KvmSevSnpLaunchUpdate,
};

pub fn translate_msi_addr(addr_lo: u32, addr_hi: u32) -> (u32, u32) {
    let mut addr_lo = MsiAddrLo(addr_lo);
    let mut addr_hi = MsiAddrHi(addr_hi);
    if addr_lo.virt_dest_id_hi() == 0 || addr_lo.remappable() || addr_hi.dest_id_hi() != 0 {
        return (addr_lo.0, addr_hi.0);
    }

    addr_hi.set_dest_id_hi(addr_lo.virt_dest_id_hi() as u32);
    addr_lo.set_virt_dest_id_hi(0);
    (addr_lo.0, addr_hi.0)
}

#[derive(Debug)]
pub struct VmArch {
    pub sev_fd: Option<SevFd>,
}

impl VmArch {
    pub fn new(kvm: &Kvm, config: &VmConfig) -> Result<Self> {
        let sev_fd = if let Some(cv) = &config.coco {
            match cv {
                Coco::AmdSev { .. } | Coco::AmdSnp { .. } => Some(match &kvm.config.dev_sev {
                    Some(dev_sev) => SevFd::new(dev_sev),
                    None => SevFd::new("/dev/sev"),
                }?),
            }
        } else {
            None
        };
        Ok(VmArch { sev_fd })
    }
}

impl KvmVm {
    pub fn determine_vm_type(config: &VmConfig) -> KvmVmType {
        match &config.coco {
            Some(Coco::AmdSnp { .. }) => KvmVmType::SNP,
            _ => KvmVmType::DEFAULT,
        }
    }

    pub fn create_guest_memfd(config: &VmConfig, fd: &OwnedFd) -> Result<Option<OwnedFd>> {
        let memfd = if let Some(Coco::AmdSnp { .. }) = &config.coco {
            let mut request = KvmCreateGuestMemfd {
                size: 1 << 48,
                ..Default::default()
            };
            let ret = unsafe { kvm_create_guest_memfd(fd, &mut request) }
                .context(kvm_error::GuestMemfd)?;
            Some(unsafe { OwnedFd::from_raw_fd(ret) })
        } else {
            None
        };
        Ok(memfd)
    }

    pub fn init(&self, config: &VmConfig) -> Result<()> {
        if self.vm.arch.sev_fd.is_some() {
            match config.coco.as_ref() {
                Some(Coco::AmdSev { policy }) => {
                    if policy.es() {
                        self.sev_op::<()>(KvmSevCmdId::ES_INIT, None)?;
                    } else {
                        self.sev_op::<()>(KvmSevCmdId::INIT, None)?;
                    }
                }
                Some(Coco::AmdSnp { .. }) => {
                    let bitmap = self.vm.check_extension(KvmCap::EXIT_HYPERCALL)?.get();
                    self.vm.enable_cap(KvmCap::EXIT_HYPERCALL, bitmap as u64)?;
                    let mut init = KvmSevInit::default();
                    self.sev_op(KvmSevCmdId::INIT2, Some(&mut init))?;
                    log::debug!("{}: snp init: {init:#x?}", self.vm);
                }
                _ => {}
            }
        }

        let x2apic_caps =
            KvmX2apicApiFlag::USE_32BIT_IDS | KvmX2apicApiFlag::DISABLE_BROADCAST_QUIRK;
        if let Err(e) = self.vm.enable_cap(KvmCap::X2APIC_API, x2apic_caps.bits()) {
            log::error!("Failed to enable KVM_CAP_X2APIC_API: {e:?}");
        }
        self.vm.enable_cap(KvmCap::SPLIT_IRQCHIP, NUM_PINS as u64)?;
        // TODO should be in parameters
        unsafe { kvm_set_tss_addr(&self.vm.fd, 0xf000_0000) }.context(error::SetVmParam)?;
        unsafe { kvm_set_identity_map_addr(&self.vm.fd, &0xf000_3000) }
            .context(error::SetVmParam)?;
        Ok(())
    }

    fn sev_op<T>(&self, cmd: KvmSevCmdId, data: Option<&mut T>) -> Result<()> {
        let Some(sev_fd) = &self.vm.arch.sev_fd else {
            unreachable!("SevFd is not initialized")
        };
        let mut req = KvmSevCmd {
            sev_fd: sev_fd.as_fd().as_raw_fd() as u32,
            data: match data {
                Some(p) => p as *mut T as _,
                None => 0,
            },
            id: cmd,
            error: SevStatus::SUCCESS,
        };
        unsafe { kvm_memory_encrypt_op(&self.vm.fd, &mut req) }.context(error::MemEncrypt)?;
        if req.error != SevStatus::SUCCESS {
            return error::SevErr { code: req.error }.fail();
        }
        Ok(())
    }

    pub fn kvm_sev_launch_start(&self, policy: SevPolicy) -> Result<()> {
        let mut start = KvmSevLaunchStart {
            policy,
            ..Default::default()
        };
        self.sev_op(KvmSevCmdId::LAUNCH_START, Some(&mut start))?;
        Ok(())
    }

    pub fn kvm_sev_launch_update_data(&self, range: &mut [u8]) -> Result<()> {
        let mut update_data = KvmSevLaunchUpdateData {
            uaddr: range.as_mut_ptr() as u64,
            len: range.len() as u32,
        };
        self.sev_op(KvmSevCmdId::LAUNCH_UPDATE_DATA, Some(&mut update_data))?;
        Ok(())
    }

    pub fn kvm_sev_launch_update_vmsa(&self) -> Result<()> {
        self.sev_op::<()>(KvmSevCmdId::LAUNCH_UPDATE_VMSA, None)?;
        Ok(())
    }

    pub fn kvm_sev_launch_measure(&self) -> Result<Vec<u8>> {
        let mut empty = KvmSevLaunchMeasure { uaddr: 0, len: 0 };
        let _ = self.sev_op(KvmSevCmdId::LAUNCH_MEASURE, Some(&mut empty));
        assert_ne!(empty.len, 0);
        let mut buf = vec![0u8; empty.len as usize];
        let mut measure = KvmSevLaunchMeasure {
            uaddr: buf.as_mut_ptr() as u64,
            len: buf.len() as u32,
        };
        self.sev_op(KvmSevCmdId::LAUNCH_MEASURE, Some(&mut measure))?;
        Ok(buf)
    }

    pub fn kvm_sev_launch_finish(&self) -> Result<()> {
        self.sev_op::<()>(KvmSevCmdId::LAUNCH_FINISH, None)?;
        Ok(())
    }

    pub fn kvm_snp_launch_start(&self, policy: SnpPolicy) -> Result<()> {
        let mut start = KvmSevSnpLaunchStart {
            policy,
            ..Default::default()
        };
        self.sev_op(KvmSevCmdId::SNP_LAUNCH_START, Some(&mut start))?;
        Ok(())
    }

    pub fn kvm_snp_launch_update(
        &self,
        range: &mut [u8],
        gpa: u64,
        type_: SnpPageType,
    ) -> Result<()> {
        let mut update = KvmSevSnpLaunchUpdate {
            uaddr: range.as_mut_ptr() as _,
            len: range.len() as _,
            gfn_start: gpa >> 12,
            type_: type_ as _,
            ..Default::default()
        };
        self.sev_op(KvmSevCmdId::SNP_LAUNCH_UPDATE, Some(&mut update))?;
        Ok(())
    }

    pub fn kvm_snp_launch_finish(&self) -> Result<()> {
        let mut finish = KvmSevSnpLaunchFinish::default();
        self.sev_op(KvmSevCmdId::SNP_LAUNCH_FINISH, Some(&mut finish))?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "vm_x86_64_test.rs"]
mod test;
