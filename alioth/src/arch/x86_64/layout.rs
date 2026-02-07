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

pub const REAL_MODE_IVT_START: u64 = 0x0;

pub const BIOS_DATA_AREA_START: u64 = 0x400;
pub const BIOS_DATA_END: u64 = 0x500;

pub const BOOT_GDT_START: u64 = 0x500;
pub const BOOT_GDT_LIMIT: u64 = 0x100;
pub const BOOT_IDT_START: u64 = 0x600;
pub const BOOT_IDT_LIMIT: u64 = 0xa00;

pub const LINUX_BOOT_PARAMS_START: u64 = 0x1000; // size: 4KiB
pub const HVM_START_INFO_START: u64 = 0x1000; // size: 4KiB

pub const KERNEL_CMDLINE_START: u64 = 0x2000;
pub const KERNEL_CMDLINE_LIMIT: u64 = 0x1000;

pub const BOOT_PAGING_START: u64 = 0x3000;
pub const BOOT_PAGING_LIMIT: u64 = 0x4000;

pub const EBDA_START: u64 = 0x8_0000;
pub const EBDA_END: u64 = 0xA_0000;

pub const KERNEL_IMAGE_START: u64 = 0x100_0000; // 16 MiB

pub const RAM_32_END: u64 = 0x8000_0000; // 2 GiB
pub const RAM_32_SIZE: u64 = RAM_32_END; // 2 GiB

pub const PCIE_MMIO_32_PREFETCHABLE_START: u64 = 0x8000_0000; // 2 GiB
pub const PCIE_MMIO_32_PREFETCHABLE_END: u64 = 0xa000_0000; // 2.5 GiB, size = 512 MiB

pub const PCIE_MMIO_32_NON_PREFETCHABLE_START: u64 = 0xa000_0000; // 2.5 GiB
pub const PCIE_MMIO_32_NON_PREFETCHABLE_END: u64 = 0xc000_0000; // 3 GiB, size = 512 MiB

pub const MMIO_32_START: u64 = 0xc000_0000; // 3 GiB
pub const MMIO_32_END: u64 = 0xe000_0000; // 3.5 GiB, size = 512 MiB

pub const PCIE_CONFIG_START: u64 = 0xe000_0000; // 3.5 GiB
pub const PCIE_CONFIG_END: u64 = 0xf000_0000; // 3.75 GiB, size = 256 MiB

pub const IOAPIC_START: u64 = 0xfec0_0000;
pub const IOAPIC_END: u64 = IOAPIC_START + 0x100;

pub const APIC_START: u64 = 0xfee0_0000;

pub const MEM_64_START: u64 = 0x1_0000_0000; // 4GiB

pub const PAGE_SIZE: u64 = 0x1000; // 4KiB

pub const PORT_COM1: u16 = 0x3f8;

pub const PORT_FW_CFG_SELECTOR: u16 = 0x510;
pub const PORT_FW_CFG_DATA: u16 = 0x511;
pub const PORT_FW_CFG_DMA_HI: u16 = 0x514;
pub const PORT_FW_CFG_DMA_LO: u16 = 0x518;

pub const PORT_ACPI_SLEEP_CONTROL: u16 = 0x600;
pub const PORT_ACPI_SLEEP_STATUS: u16 = 0x601;
pub const PORT_ACPI_RESET: u16 = 0x604;

pub const PORT_PCI_ADDRESS: u16 = 0xcf8;
pub const PORT_PCI_DATA: u16 = 0xcfc;
