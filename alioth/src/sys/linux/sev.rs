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

use crate::ioctl_writeread;

pub const SEV_PLATFORM_STATUS: u32 = 1;

#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct SevIssueCmd {
    pub cmd: u32,
    pub data: u64,
    pub error: u32,
}

pub const SEV_IOC_TYPE: u8 = b'S';

ioctl_writeread!(sev_issue_cmd, SEV_IOC_TYPE, 0x0, SevIssueCmd);

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
pub const KVM_SEV_INIT2: u32 = 22;
pub const KVM_SEV_SNP_LAUNCH_START: u32 = 100;
pub const KVM_SEV_SNP_LAUNCH_UPDATE: u32 = 101;
pub const KVM_SEV_SNP_LAUNCH_FINISH: u32 = 102;

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
pub struct KvmSevInit {
    pub vmsa_features: u64,
    pub flags: u32,
    pub ghcb_version: u16,
    pub pad1: u16,
    pub pad2: [u32; 8],
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

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmSevSnpLaunchStart {
    pub policy: u64,
    pub gosvw: [u8; 16],
    pub flags: u16,
    pub pad0: [u8; 6],
    pub pad1: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmSevSnpLaunchUpdate {
    pub gfn_start: u64,
    pub uaddr: u64,
    pub len: u64,
    pub type_: u8,
    pub pad0: u8,
    pub flags: u16,
    pub pad1: u32,
    pub pad2: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct KvmSevSnpLaunchFinish {
    pub id_block_uaddr: u64,
    pub id_auth_uaddr: u64,
    pub id_block_en: u8,
    pub auth_key_en: u8,
    pub vcek_disabled: u8,
    pub host_data: [u8; 32],
    pub pad0: [u8; 3],
    pub flags: u16,
    pub pad1: [u64; 4],
}
