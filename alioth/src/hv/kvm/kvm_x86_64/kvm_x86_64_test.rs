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

use std::arch::x86_64::CpuidResult;

use rstest::rstest;

use crate::arch::cpuid::CpuidIn;
use crate::hv::kvm::{Kvm, KvmConfig};
use crate::sys::kvm::{KVM_CPUID_SIGNATURE, KvmCpuid2Flag, KvmCpuidEntry2};

#[test]
#[cfg_attr(not(feature = "test-hv"), ignore)]
fn test_get_supported_cpuid() {
    let kvm = Kvm::new(KvmConfig::default()).unwrap();
    let mut kvm_cpuid_exist = false;
    let supported_cpuids = kvm.get_supported_cpuids(None).unwrap();
    for (in_, out) in &supported_cpuids {
        if in_.func == KVM_CPUID_SIGNATURE
            && out.ebx.to_le_bytes() == *b"KVMK"
            && out.ecx.to_le_bytes() == *b"VMKV"
            && out.edx.to_le_bytes() == *b"M\0\0\0"
        {
            kvm_cpuid_exist = true;
        }
    }
    assert!(kvm_cpuid_exist);
}

#[rstest]
#[case(
    KvmCpuidEntry2 {
        function: 0,
        index: 1,
        flags: KvmCpuid2Flag::empty(),
        eax: 0x10,
        ebx: u32::from_le_bytes(*b"Auth"),
        ecx: u32::from_le_bytes(*b"cAMD"),
        edx: u32::from_le_bytes(*b"enti"),
        padding: [0; 3],
    },
    (
        CpuidIn {
            func: 0,
            index: None,
        },
        CpuidResult {
            eax: 0x10,
            ebx: u32::from_le_bytes(*b"Auth"),
            ecx: u32::from_le_bytes(*b"cAMD"),
            edx: u32::from_le_bytes(*b"enti"),
        }
    )
)]
#[case(
    KvmCpuidEntry2 {
        function: 0xb,
        index: 0,
        flags: KvmCpuid2Flag::SIGNIFCANT_INDEX,
        eax: 0x0,
        ebx: 0x0,
        ecx: 0x0,
        edx: 0x6d,
        padding: [0; 3],
    },
    (
        CpuidIn {
            func: 0xb,
            index: Some(0),
        },
        CpuidResult {
            eax: 0x0,
            ebx: 0x0,
            ecx: 0x0,
            edx: 0x6d,
        }
    )
)]
fn test_convert_cpuid_entry(
    #[case] value: KvmCpuidEntry2,
    #[case] expected: (CpuidIn, CpuidResult),
) {
    let got: (CpuidIn, CpuidResult) = value.into();
    assert_eq!(got, expected)
}
