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

use rstest::rstest;

use crate::arch::sev::{SevPolicy, SnpPolicy};
use crate::arch::tdx::TdAttr;
use crate::hv::kvm::vm::KvmVm;
use crate::hv::kvm::vm::x86_64::translate_msi_addr;
use crate::hv::{Coco, VmConfig};
use crate::sys::kvm::KvmVmType;

#[rstest]
#[case(0, 0)]
#[case(0xfee0_0010, 0xfee0_0010)]
#[case(0xfee0_1000, 0xfee0_1000)]
#[case(0x100_fee0_1000, 0x100_fee0_1000)]
#[case(0xfee0_1020, 0x100_fee0_1000)]
fn test_translate_msi_addr(#[case] addr: u64, #[case] expected: u64) {
    let (lo, hi) = translate_msi_addr(addr as u32, (addr >> 32) as u32);
    assert_eq!((lo as u64) | ((hi as u64) << 32), expected);
}

#[rstest]
#[case(VmConfig { coco: None }, KvmVmType::DEFAULT)]
#[case(
    VmConfig {
        coco: Some(Coco::AmdSev {
            policy: SevPolicy(0x5)
        })
    },
    KvmVmType::DEFAULT
)]
#[case(
    VmConfig {
        coco: Some(Coco::AmdSnp {
            policy: SnpPolicy(0x30000)
        })
    },
    KvmVmType::SNP
)]
#[case(
    VmConfig {
        coco: Some(Coco::IntelTdx {
            attr: TdAttr::empty()
        })
    },
    KvmVmType::TDX
)]
fn test_determine_vm_type(#[case] config: VmConfig, #[case] vm_type: KvmVmType) {
    assert_eq!(KvmVm::determine_vm_type(&config), vm_type)
}
