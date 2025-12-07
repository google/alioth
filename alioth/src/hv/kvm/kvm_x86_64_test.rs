// Copyright 2025 Google LLC
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

use crate::hv::Hypervisor;
use crate::hv::kvm::{Kvm, KvmConfig};

#[test]
#[cfg_attr(not(feature = "test-hv"), ignore)]
fn test_get_supported_cpuid() {
    let kvm = Kvm::new(KvmConfig::default()).unwrap();
    let mut kvm_cpuid_exist = false;
    let supported_cpuids = kvm.get_supported_cpuids().unwrap();
    for (in_, out) in &supported_cpuids {
        if in_.func == 0x4000_0000
            && out.ebx.to_le_bytes() == *b"KVMK"
            && out.ecx.to_le_bytes() == *b"VMKV"
            && out.edx.to_le_bytes() == *b"M\0\0\0"
        {
            kvm_cpuid_exist = true;
        }
    }
    assert!(kvm_cpuid_exist);
}
