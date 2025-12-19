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

use std::arch::x86_64::CpuidResult;
use std::collections::HashMap;

use snafu::ResultExt;

use crate::arch::cpuid::CpuidIn;
use crate::hv::{Kvm, Result, error};
use crate::sys::kvm::{
    KVM_CPUID_FEATURES, KVM_MAX_CPUID_ENTRIES, KvmCap, KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2,
    KvmCpuidFeature, KvmX2apicApiFlag, kvm_get_supported_cpuid,
};

impl Kvm {
    pub fn get_supported_cpuids(&self) -> Result<HashMap<CpuidIn, CpuidResult>> {
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: KVM_MAX_CPUID_ENTRIES as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        unsafe { kvm_get_supported_cpuid(&self.fd, &mut kvm_cpuid2) }.context(error::GuestCpuid)?;
        let map_f = |e: &KvmCpuidEntry2| {
            let in_ = CpuidIn {
                func: e.function,
                index: if e.flags.contains(KvmCpuid2Flag::SIGNIFCANT_INDEX) {
                    Some(e.index)
                } else {
                    None
                },
            };
            let out = CpuidResult {
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
            };
            (in_, out)
        };
        let mut cpuids: HashMap<_, _> = kvm_cpuid2
            .entries
            .iter()
            .take(kvm_cpuid2.nent as usize)
            .map(map_f)
            .collect();

        // Enable KVM_FEATURE_MSI_EXT_DEST_ID if KVM_CAP_X2APIC_API is supported
        let ext = self.check_extension(KvmCap::X2APIC_API)?;
        let flag = KvmX2apicApiFlag::from_bits_retain(ext as u64);
        let x2apic_flags =
            KvmX2apicApiFlag::USE_32BIT_IDS | KvmX2apicApiFlag::DISABLE_BROADCAST_QUIRK;
        let leaf_features = CpuidIn {
            func: KVM_CPUID_FEATURES,
            index: None,
        };
        if let Some(entry) = cpuids.get_mut(&leaf_features)
            && flag.contains(x2apic_flags)
        {
            entry.eax |= KvmCpuidFeature::MSI_EXT_DEST_ID.bits();
        }

        Ok(cpuids)
    }
}

#[cfg(test)]
#[path = "kvm_x86_64_test.rs"]
mod tests;
