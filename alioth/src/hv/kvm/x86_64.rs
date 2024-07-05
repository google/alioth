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

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use snafu::ResultExt;

use crate::hv::kvm::bindings::{KvmCap, KvmCreateGuestMemfd, KvmEnableCap, KvmVmType};
use crate::hv::kvm::ioctls::{
    kvm_check_extension, kvm_create_guest_memfd, kvm_create_irqchip, kvm_enable_cap,
    kvm_set_identity_map_addr, kvm_set_tss_addr,
};
use crate::hv::kvm::sev::bindings::{KvmSevInit, KVM_SEV_ES_INIT, KVM_SEV_INIT, KVM_SEV_INIT2};
use crate::hv::kvm::sev::SevFd;
use crate::hv::kvm::vm::{KvmVm, VmArch};
use crate::hv::kvm::{kvm_error, Kvm};
use crate::hv::{error, Coco, Result, VmConfig};

impl Kvm {
    pub(super) fn determine_vm_type(config: &VmConfig) -> Result<KvmVmType> {
        match &config.coco {
            Some(Coco::AmdSnp { .. }) => Ok(KvmVmType::SNP),
            _ => Ok(KvmVmType::DEFAULT),
        }
    }

    pub(super) fn create_guest_memfd(
        &self,
        config: &VmConfig,
        vm_fd: &OwnedFd,
    ) -> Result<Option<OwnedFd>> {
        let memfd = if let Some(Coco::AmdSnp { .. }) = &config.coco {
            let mut request = KvmCreateGuestMemfd {
                size: 1 << 48,
                ..Default::default()
            };
            let ret = unsafe { kvm_create_guest_memfd(vm_fd, &mut request) }
                .context(kvm_error::GuestMemfd)?;
            Some(unsafe { OwnedFd::from_raw_fd(ret) })
        } else {
            None
        };
        Ok(memfd)
    }

    pub(super) fn create_vm_arch(&self, config: &VmConfig) -> Result<VmArch> {
        let sev_fd = if let Some(cv) = &config.coco {
            match cv {
                Coco::AmdSev { .. } | Coco::AmdSnp { .. } => Some(match &self.config.dev_sev {
                    Some(dev_sev) => SevFd::new(dev_sev),
                    None => SevFd::new("/dev/sev"),
                }?),
            }
        } else {
            None
        };
        Ok(VmArch { sev_fd })
    }

    pub(super) fn vm_init_arch(&self, config: &VmConfig, kvm_vm: &KvmVm) -> Result<()> {
        if kvm_vm.vm.arch.sev_fd.is_some() {
            match config.coco.as_ref() {
                Some(Coco::AmdSev { policy }) => {
                    if policy.es() {
                        kvm_vm.sev_op::<()>(KVM_SEV_ES_INIT, None)?;
                    } else {
                        kvm_vm.sev_op::<()>(KVM_SEV_INIT, None)?;
                    }
                }
                Some(Coco::AmdSnp { .. }) => {
                    let bitmap = unsafe { kvm_check_extension(&kvm_vm.vm, KvmCap::EXIT_HYPERCALL) }
                        .context(kvm_error::CheckExtension {
                            ext: "KVM_CAP_EXIT_HYPERCALL",
                        })?;
                    if bitmap != 0 {
                        let request = KvmEnableCap {
                            cap: KvmCap::EXIT_HYPERCALL,
                            args: [bitmap as _, 0, 0, 0],
                            flags: 0,
                            pad: [0; 64],
                        };
                        unsafe { kvm_enable_cap(&kvm_vm.vm, &request) }.context(
                            kvm_error::EnableCap {
                                cap: "KVM_CAP_EXIT_HYPERCALL",
                            },
                        )?;
                    }
                    let mut init = KvmSevInit::default();
                    kvm_vm.sev_op(KVM_SEV_INIT2, Some(&mut init))?;
                    log::debug!("vm-{}: snp init: {init:#x?}", kvm_vm.vm.as_raw_fd());
                }
                _ => {}
            }
        }
        unsafe { kvm_create_irqchip(&kvm_vm.vm) }.context(error::CreateDevice)?;
        // TODO should be in parameters
        unsafe { kvm_set_tss_addr(&kvm_vm.vm, 0xf000_0000) }.context(error::SetVmParam)?;
        unsafe { kvm_set_identity_map_addr(&kvm_vm.vm, &0xf000_3000) }
            .context(error::SetVmParam)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::hv::kvm::{Kvm, KvmConfig};
    use crate::hv::Hypervisor;

    #[test]
    #[cfg_attr(not(feature = "test-hv"), ignore)]
    fn test_get_supported_cpuid() {
        let kvm = Kvm::new(KvmConfig::default()).unwrap();
        let mut kvm_cpuid_exist = false;
        let supported_cpuids = kvm.get_supported_cpuids().unwrap();
        for cpuid in &supported_cpuids {
            if cpuid.func == 0x4000_0000
                && cpuid.ebx.to_le_bytes() == *b"KVMK"
                && cpuid.ecx.to_le_bytes() == *b"VMKV"
                && cpuid.edx.to_le_bytes() == *b"M\0\0\0"
            {
                kvm_cpuid_exist = true;
            }
        }
        assert!(kvm_cpuid_exist);
    }
}
