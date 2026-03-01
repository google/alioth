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

pub(crate) mod sev;
pub(crate) mod tdx;

use std::arch::x86_64::CpuidResult;
use std::collections::HashMap;

use snafu::ResultExt;

use crate::arch::cpuid::CpuidIn;
#[cfg(target_arch = "x86_64")]
use crate::hv::Coco;
use crate::hv::{Kvm, Result, error};
use crate::sys::kvm::{
    KVM_CPUID_FEATURES, KVM_MAX_CPUID_ENTRIES, KvmCap, KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2,
    KvmCpuidFeature, KvmX2apicApiFlag, kvm_get_supported_cpuid,
};

impl From<KvmCpuidEntry2> for (CpuidIn, CpuidResult) {
    fn from(value: KvmCpuidEntry2) -> Self {
        let in_ = CpuidIn {
            func: value.function,
            index: if value.flags.contains(KvmCpuid2Flag::SIGNIFCANT_INDEX) {
                Some(value.index)
            } else {
                None
            },
        };
        let result = CpuidResult {
            eax: value.eax,
            ebx: value.ebx,
            ecx: value.ecx,
            edx: value.edx,
        };
        (in_, result)
    }
}

impl Kvm {
    pub fn get_supported_cpuids(
        &self,
        coco: Option<&Coco>,
    ) -> Result<HashMap<CpuidIn, CpuidResult>> {
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: KVM_MAX_CPUID_ENTRIES as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        unsafe { kvm_get_supported_cpuid(&self.fd, &mut kvm_cpuid2) }.context(error::GuestCpuid)?;
        let mut cpuids: HashMap<_, _> = kvm_cpuid2
            .entries
            .into_iter()
            .filter(|e| e.eax != 0 || e.ebx != 0 || e.ecx != 0 || e.edx != 0)
            .take(kvm_cpuid2.nent as usize)
            .map(From::from)
            .collect();

        let leaf_features = CpuidIn {
            func: KVM_CPUID_FEATURES,
            index: None,
        };
        if let Some(entry) = cpuids.get_mut(&leaf_features) {
            if let Ok(ext) = self.check_extension(KvmCap::X2APIC_API)
                && KvmX2apicApiFlag::from_bits_retain(ext.get() as u64).contains(
                    KvmX2apicApiFlag::USE_32BIT_IDS | KvmX2apicApiFlag::DISABLE_BROADCAST_QUIRK,
                )
            {
                // Enable KVM_FEATURE_MSI_EXT_DEST_ID if KVM_CAP_X2APIC_API is supported
                entry.eax |= KvmCpuidFeature::MSI_EXT_DEST_ID.bits();
            }
            if matches!(coco, Some(Coco::IntelTdx { .. })) {
                entry.eax &= tdx::SUPPORTED_KVM_FEATURES;
            }
        }

        Ok(cpuids)
    }
}

#[cfg(test)]
#[path = "kvm_x86_64_test.rs"]
mod tests;
