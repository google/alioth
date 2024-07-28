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

use bitfield::bitfield;
use serde::{Deserialize, Serialize};

bitfield! {
    #[derive(Copy, Clone, Serialize, Deserialize)]
    pub struct SevPolicy(u32);
    impl Debug;
    pub no_debug, set_no_debug: 0;
    pub no_ks, set_no_ks: 1;
    pub es, set_es: 2;
    pub no_send, set_no_send: 3;
    pub domain, set_domain: 4;
    pub sev, set_sev: 5;
    pub api_major, set_api_major: 23,16;
    pub api_minor, set_api_minor: 31,24;
}

bitfield! {
    /// AMD SEV-SNP guest policy
    ///
    /// From SEV SNP Firmware ABI Specification, Revision 1.55, Sec.4.3.
    #[derive(Copy, Clone, Serialize, Deserialize)]
    pub struct SnpPolicy(u64);
    impl Debug;
    pub api_minor, set_api_minor: 7,0;
    pub api_major, set_api_major: 15,8;
    pub smt, set_smt: 16;
    pub reserved_1, set_reserved_1: 17;
    pub migrate_ma, set_migrate_ma: 18;
    pub debug, set_debug: 19;
    pub single_socket, set_single_socket: 20;
    pub cxl_allow, set_cxl_allow: 21;
    pub mem_aes_256_xts, set_mem_aes_256_xts: 22;
    pub rapl_dis, set_rapl_dis: 23;
    pub ciphertext_hiding, set_ciphertext_hiding: 24;
}

/// AMD SEV-SNP launch update page type.
///
/// From SEV SNP Firmware ABI Specification, Revision 1.55, Table 67.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SnpPageType {
    /// A normal data page.
    Normal = 1,
    /// A VMSA page.
    Vmsa = 2,
    /// A page full of zeros.
    Zero = 3,
    /// A page that is encrypted but not measured.
    Unmeasured = 4,
    /// A page for the firmware to store secrets for the guest.
    Secrets = 5,
    /// A page for the hypervisor to provide CPUID function values.
    Cpuid = 6,
}
