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

use crate::arch::sev::{SevPolicy, SevStatus, SnpPolicy};
use crate::{c_enum, ioctl_writeread};

c_enum! {
    pub struct SevCmd(u32);
    {
        PLATFORM_STATUS = 1;
    }
}

#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct SevIssueCmd {
    pub cmd: SevCmd,
    pub data: u64,
    pub error: SevStatus,
}

pub const SEV_IOC_TYPE: u8 = b'S';

ioctl_writeread!(sev_issue_cmd, SEV_IOC_TYPE, 0x0, SevIssueCmd);

c_enum! {
    pub struct KvmSevCmdId(u32);
    {
        INIT = 0;
        ES_INIT = 1;
        LAUNCH_START = 2;
        LAUNCH_UPDATE_DATA = 3;
        LAUNCH_UPDATE_VMSA = 4;
        LAUNCH_SECRET = 5;
        LAUNCH_MEASURE = 6;
        LAUNCH_FINISH = 7;
        SEND_START = 8;
        SEND_UPDATE_DATA = 9;
        SEND_UPDATE_VMSA = 10;
        SEND_FINISH = 11;
        RECEIVE_START = 12;
        RECEIVE_UPDATE_DATA = 13;
        RECEIVE_UPDATE_VMSA = 14;
        RECEIVE_FINISH = 15;
        GUEST_STATUS = 16;
        DBG_DECRYPT = 17;
        DBG_ENCRYPT = 18;
        CERT_EXPORT = 19;
        GET_ATTESTATION_REPORT = 20;
        SEND_CANCEL = 21;
        INIT2 = 22;
        SNP_LAUNCH_START = 100;
        SNP_LAUNCH_UPDATE = 101;
        SNP_LAUNCH_FINISH = 102;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KvmSevCmd {
    pub id: KvmSevCmdId,
    pub data: u64,
    pub error: SevStatus,
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
    pub policy: SevPolicy,
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
    pub policy: SnpPolicy,
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
