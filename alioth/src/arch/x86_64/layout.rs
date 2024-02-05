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

pub const REAL_MODE_IVT_START: usize = 0x0;

pub const BIOS_DATA_AREA_START: usize = 0x400;
pub const BIOS_DATA_END: usize = 0x500;

pub const BOOT_GDT_START: usize = 0x500;
pub const BOOT_GDT_LIMIT: usize = 0x100;
pub const BOOT_IDT_START: usize = 0x600;
pub const BOOT_IDT_LIMIT: usize = 0xa00;

pub const LINUX_BOOT_PARAMS_START: usize = 0x1000; // size: 4KiB
pub const HVM_START_INFO_START: usize = 0x1000; // size: 4KiB

pub const KERNEL_CMD_LINE_START: usize = 0x2000;
pub const KERNEL_CMD_LINE_LIMIT: usize = 0x1000;

pub const BOOT_PAGING_START: usize = 0x3000;
pub const BOOT_PAGING_LIMIT: usize = 0x4000;

pub const EBDA_START: usize = 0x8_0000;
pub const EBDA_END: usize = 0xA_0000;

pub const KERNEL_IMAGE_START: usize = 0x100_0000; // 16 MiB

pub const RAM_32_END: usize = 0x8000_0000; // 2 GiB
pub const RAM_32_SIZE: usize = RAM_32_END; // 2 GiB

pub const MMIO_32_START: usize = 0x8000_0000; // 2 GiB
pub const MMIO_32_END: usize = 0xe000_0000; // 3.5 GiB

pub const PCIE_CONFIG_START: usize = 0xe000_0000; // 3.5 GiB
pub const PCIE_CONFIG_END: usize = 0xf000_0000; // 3.75 GiB, size = 256 MiB

pub const IOAPIC_START: usize = 0xfec0_0000;
pub const APIC_START: usize = 0xfee0_0000;

pub const MEM_64_START: usize = 0x1_0000_0000; // 4GiB

pub const PAGE_SIZE: usize = 0x1000; // 4KiB
