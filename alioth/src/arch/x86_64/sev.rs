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
use serde_aco::Help;

pub const SEV_RET_SUCCESS: u32 = 0;
pub const SEV_RET_INVALID_PLATFORM_STATE: u32 = 1;
pub const SEV_RET_INVALID_GUEST_STATE: u32 = 2;
pub const SEV_RET_INAVLID_CONFIG: u32 = 3;
pub const SEV_RET_INVALID_LEN: u32 = 4;
pub const SEV_RET_ALREADY_OWNED: u32 = 5;
pub const SEV_RET_INVALID_CERTIFICATE: u32 = 6;
pub const SEV_RET_POLICY_FAILURE: u32 = 7;
pub const SEV_RET_INACTIVE: u32 = 8;
pub const SEV_RET_INVALID_ADDRESS: u32 = 9;
pub const SEV_RET_BAD_SIGNATURE: u32 = 10;
pub const SEV_RET_BAD_MEASUREMENT: u32 = 11;
pub const SEV_RET_ASID_OWNED: u32 = 12;
pub const SEV_RET_INVALID_ASID: u32 = 13;
pub const SEV_RET_WBINVD_REQUIRED: u32 = 14;
pub const SEV_RET_DFFLUSH_REQUIRED: u32 = 15;
pub const SEV_RET_INVALID_GUEST: u32 = 16;
pub const SEV_RET_INVALID_COMMAND: u32 = 17;
pub const SEV_RET_ACTIVE: u32 = 18;
pub const SEV_RET_HWSEV_RET_PLATFORM: u32 = 19;
pub const SEV_RET_HWSEV_RET_UNSAFE: u32 = 20;
pub const SEV_RET_UNSUPPORTED: u32 = 21;
pub const SEV_RET_INVALID_PARAM: u32 = 22;
pub const SEV_RET_RESOURCE_LIMIT: u32 = 23;
pub const SEV_RET_SECURE_DATA_INVALID: u32 = 24;

bitfield! {
    /// AMD SEV guest policy
    ///
    /// From Secure Encrypted Virtualization API Version 0.24, Revision 3.24, Ch.2, Table 2.
    #[derive(Copy, Clone, Serialize, Deserialize, Help)]
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
    /// From SEV SNP Firmware ABI Specification, Revision 1.55, Sec.4.3, Table 9.
    #[derive(Copy, Clone, Serialize, Deserialize, Help)]
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct SevUserDataStatus {
    pub api_major: u8,
    pub api_minor: u8,
    pub state: u8,
    pub flags: u32,
    pub build: u8,
    pub guest_count: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SevUserDataPekCsr {
    pub address: u64,
    pub length: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SevUserDataPekCertImport {
    pub pek_cert_address: u64,
    pub pek_cert_len: u32,
    pub oca_cert_address: u64,
    pub oca_cert_len: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SevUserDataPdhCertExport {
    pub pdh_cert_address: u64,
    pub pdh_cert_len: u32,
    pub cert_chain_address: u64,
    pub cert_chain_len: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SevUserDataGetId {
    pub socket1: [u8; 64],
    pub socket2: [u8; 64],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SevUserDataGetId2 {
    pub address: u64,
    pub length: u32,
}
