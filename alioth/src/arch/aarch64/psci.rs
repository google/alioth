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

use crate::c_enum;

c_enum! {
    /// https://developer.arm.com/documentation/den0022/latest/
    pub struct PsciFunc(u32);
    {
        PSCI_VERSION = 0x8400_0000;
        CPU_SUSPEND_32 = 0x8400_0001;
        CPU_SUSPEND_64 = 0xc400_0001;
        CPU_OFF = 0x8400_0002;
        CPU_ON_32 = 0x8400_0003;
        CPU_ON_64 = 0xc400_0003;
        AFFINITY_INFO_32 = 0x8400_0004;
        AFFINITY_INFO_64 = 0xc400_0004;
        MIGRATE_32 = 0x8400_0005;
        MIGRATE_64 = 0xc400_0005;
        MIGRATE_INFO_TYPE = 0x8400_0006;
        MIGRATE_INFO_UP_CPU_32 = 0x8400_0007;
        MIGRATE_INFO_UP_CPU_64 = 0xc400_0007;
        SYSTEM_OFF = 0x8400_0008;
        SYSTEM_OFF2_32 = 0x8400_0015;
        SYSTEM_OFF2_64 = 0xc400_0015;
        SYSTEM_RESET = 0x8400_0009;
        SYSTEM_RESET2_32 = 0x8400_0012;
        SYSTEM_RESET2_64 = 0xc400_0012;
        MEM_PROTECT = 0x8400_0013;
        MEM_PROTECT_CHECK_RANGE_32 = 0x8400_0014;
        MEM_PROTECT_CHECK_RANGE_64 = 0xc400_0014;
        PSCI_FEATURES = 0x8400_000a;
        CPU_FREEZE = 0x8400_000b;
        CPU_DEFAULT_SUSPEND_32 = 0x8400_000c;
        CPU_DEFAULT_SUSPEND_64 = 0xc400_000c;
        NODE_HW_STATE_32 = 0x8400_000d;
        NODE_HW_STATE_64 = 0xc400_000d;
        SYSTEM_SUSPEND_32 = 0x8400_000e;
        SYSTEM_SUSPEND_64 = 0xc400_000e;
        PSCI_SET_SUSPEND_MODE = 0x8400_000f;
        PSCI_STAT_RESIDENCY_32 = 0x8400_0010;
        PSCI_STAT_RESIDENCY_64 = 0xc400_0010;
        PSCI_STAT_COUNT_32 = 0x8400_0011;
        PSCI_STAT_COUNT_64 = 0xc400_0011;
    }
}

pub const PSCI_VERSION_1_1: u32 = (1 << 16) | 1;

c_enum! {
    /// https://developer.arm.com/documentation/den0022/latest/
    pub struct PsciMigrateInfo(u32);
    {
        CAPABLE = 0;
        INCAPABLE = 1;
        NOT_REQUIRED = 2;
    }
}
