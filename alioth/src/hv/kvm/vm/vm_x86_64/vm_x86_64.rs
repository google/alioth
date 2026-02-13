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

pub mod sev;

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

use snafu::ResultExt;

use crate::arch::intr::{MsiAddrHi, MsiAddrLo};
use crate::arch::ioapic::NUM_PINS;
use crate::hv::kvm::sev::SevFd;
use crate::hv::kvm::{KvmVm, kvm_error};
use crate::hv::{Coco, Kvm, Result, VmConfig, error};
use crate::sys::kvm::{
    KvmCap, KvmCreateGuestMemfd, KvmVmType, KvmX2apicApiFlag, kvm_create_guest_memfd,
    kvm_set_identity_map_addr, kvm_set_tss_addr,
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

#[derive(Debug, Default)]
pub struct VmArch {
    pub sev_fd: Option<SevFd>,
}

impl VmArch {
    pub fn new(kvm: &Kvm, config: &VmConfig) -> Result<Self> {
        let Some(coco) = &config.coco else {
            return Ok(VmArch::default());
        };
        match coco {
            Coco::AmdSev { .. } | Coco::AmdSnp { .. } => {
                let default_dev = Path::new("/dev/sev");
                let dev_sev = kvm.config.dev_sev.as_deref().unwrap_or(default_dev);
                let fd = SevFd::new(dev_sev)?;
                Ok(VmArch { sev_fd: Some(fd) })
            }
            Coco::IntelTdx { attr } => todo!("Intel TDX {attr:?}"),
        }
    }
}

impl KvmVm {
    pub fn determine_vm_type(config: &VmConfig) -> KvmVmType {
        let Some(coco) = &config.coco else {
            return KvmVmType::DEFAULT;
        };
        match coco {
            Coco::AmdSev { .. } => KvmVmType::DEFAULT,
            Coco::AmdSnp { .. } => KvmVmType::SNP,
            Coco::IntelTdx { .. } => KvmVmType::TDX,
        }
    }

    pub fn create_guest_memfd(config: &VmConfig, fd: &OwnedFd) -> Result<Option<OwnedFd>> {
        let Some(coco) = &config.coco else {
            return Ok(None);
        };
        if !matches!(coco, Coco::AmdSnp { .. } | Coco::IntelTdx { .. }) {
            return Ok(None);
        }
        let mut gmem = KvmCreateGuestMemfd {
            size: 1 << 48,
            ..Default::default()
        };
        let fd = unsafe { kvm_create_guest_memfd(fd, &mut gmem) }.context(kvm_error::GuestMemfd)?;
        Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn init(&self, config: &VmConfig) -> Result<()> {
        if let Some(coco) = &config.coco {
            match coco {
                Coco::AmdSev { policy } => self.sev_init(*policy),
                Coco::AmdSnp { .. } => self.snp_init(),
                Coco::IntelTdx { attr } => todo!("Intel TDX {attr:?}"),
            }?;
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
}

#[cfg(test)]
#[path = "vm_x86_64_test.rs"]
mod test;
