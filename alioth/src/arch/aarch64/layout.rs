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

pub const MMIO_32_START: u64 = 0x1000_0000; // 256 MiB

pub const GIC_MSI_START: u64 = 0x1000_0000; // 64 KiB for GICv2m, 128 KiB for GICv3, 192 KiB for GICv4.1
pub const GIC_DIST_START: u64 = 0x1003_0000; // size = 64 KiB

pub const GIC_V2_CPU_INTERFACE_START: u64 = 0x1000_4000; // size 8 KiB
pub const GIC_V3_REDIST_START: u64 = 0x1004_0000; // size = 128 KiB * num_cpu

pub const PL011_START: u64 = 0x2fff_f000;

pub const MMIO_32_END: u64 = 0x3000_0000; // 768 MiB, size = 512 MiB
pub const PCIE_CONFIG_START: u64 = 0x3000_0000; // 768 MiB

pub const RAM_32_START: u64 = 0x4000_0000; // 1 GiB

pub const DEVICE_TREE_START: u64 = 0x4000_0000; // 1 GiB
pub const DEVICE_TREE_LIMIT: u64 = 0x20_0000; // 2 MiB

pub const KERNEL_IMAGE_START: u64 = 0x4020_0000; // 1 GiB + 2 MiB

pub const RAM_32_END: u64 = 0xc000_0000; // 3 GiB
pub const RAM_32_SIZE: u64 = RAM_32_END - RAM_32_START; // 2 GiB

pub const PCIE_MMIO_32_PREFETCHABLE_START: u64 = 0xc000_0000; // 3 GiB
pub const PCIE_MMIO_32_PREFETCHABLE_END: u64 = 0xe000_0000; // 3.5 GiB, size = 512 MiB

pub const PCIE_MMIO_32_NON_PREFETCHABLE_START: u64 = 0xe000_0000; // 3.5 GiB
pub const PCIE_MMIO_32_NON_PREFETCHABLE_END: u64 = 0x1_0000_0000; // 4 GiB, size = 512 MiB

pub const MEM_64_START: u64 = 0x1_0000_0000; // 4GiB
pub const PAGE_SIZE: u64 = 0x1000; // 4KiB
