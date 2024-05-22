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

#![allow(dead_code)]

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

#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct SevIssueCmd {
    pub cmd: u32,
    pub data: u64,
    pub error: u32,
}

pub const KVM_SEV_INIT: u32 = 0;
pub const KVM_SEV_ES_INIT: u32 = 1;
pub const KVM_SEV_LAUNCH_START: u32 = 2;
pub const KVM_SEV_LAUNCH_UPDATE_DATA: u32 = 3;
pub const KVM_SEV_LAUNCH_UPDATE_VMSA: u32 = 4;
pub const KVM_SEV_LAUNCH_SECRET: u32 = 5;
pub const KVM_SEV_LAUNCH_MEASURE: u32 = 6;
pub const KVM_SEV_LAUNCH_FINISH: u32 = 7;
pub const KVM_SEV_SEND_START: u32 = 8;
pub const KVM_SEV_SEND_UPDATE_DATA: u32 = 9;
pub const KVM_SEV_SEND_UPDATE_VMSA: u32 = 10;
pub const KVM_SEV_SEND_FINISH: u32 = 11;
pub const KVM_SEV_RECEIVE_START: u32 = 12;
pub const KVM_SEV_RECEIVE_UPDATE_DATA: u32 = 13;
pub const KVM_SEV_RECEIVE_UPDATE_VMSA: u32 = 14;
pub const KVM_SEV_RECEIVE_FINISH: u32 = 15;
pub const KVM_SEV_GUEST_STATUS: u32 = 16;
pub const KVM_SEV_DBG_DECRYPT: u32 = 17;
pub const KVM_SEV_DBG_ENCRYPT: u32 = 18;
pub const KVM_SEV_CERT_EXPORT: u32 = 19;
pub const KVM_SEV_GET_ATTESTATION_REPORT: u32 = 20;
pub const KVM_SEV_SEND_CANCEL: u32 = 21;
pub const KVM_SEV_NR_MAX: u32 = 22;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevCmd {
    pub id: u32,
    pub data: u64,
    pub error: u32,
    pub sev_fd: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmSevLaunchStart {
    pub handle: u32,
    pub policy: u32,
    pub dh_uaddr: u64,
    pub dh_len: u32,
    pub session_uaddr: u64,
    pub session_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevLaunchUpdateData {
    pub uaddr: u64,
    pub len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevLaunchSecret {
    pub hdr_uaddr: u64,
    pub hdr_len: u32,
    pub guest_uaddr: u64,
    pub guest_len: u32,
    pub trans_uaddr: u64,
    pub trans_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevLaunchMeasure {
    pub uaddr: u64,
    pub len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevGuestStatus {
    pub handle: u32,
    pub policy: u32,
    pub state: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevDbg {
    pub src_uaddr: u64,
    pub dst_uaddr: u64,
    pub len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevAttestationReport {
    pub mnonce: [u8; 16],
    pub uaddr: u64,
    pub len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevSendStart {
    pub policy: u32,
    pub pdh_cert_uaddr: u64,
    pub pdh_cert_len: u32,
    pub plat_certs_uaddr: u64,
    pub plat_certs_len: u32,
    pub amd_certs_uaddr: u64,
    pub amd_certs_len: u32,
    pub session_uaddr: u64,
    pub session_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevSendUpdateData {
    pub hdr_uaddr: u64,
    pub hdr_len: u32,
    pub guest_uaddr: u64,
    pub guest_len: u32,
    pub trans_uaddr: u64,
    pub trans_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevReceiveStart {
    pub handle: u32,
    pub policy: u32,
    pub pdh_uaddr: u64,
    pub pdh_len: u32,
    pub session_uaddr: u64,
    pub session_len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevReceiveUpdateData {
    pub hdr_uaddr: u64,
    pub hdr_len: u32,
    pub guest_uaddr: u64,
    pub guest_len: u32,
    pub trans_uaddr: u64,
    pub trans_len: u32,
}
