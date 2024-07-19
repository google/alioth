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
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub const SIG_RSDP: [u8; 8] = *b"RSD PTR ";
pub const SIG_XSDT: [u8; 4] = *b"XSDT";
pub const SIG_FADT: [u8; 4] = *b"FACP";
pub const SIG_MADT: [u8; 4] = *b"APIC";
pub const SIG_MCFG: [u8; 4] = *b"MCFG";
#[allow(dead_code)]
pub const SIG_DSDT: [u8; 4] = *b"DSDT";

pub const RSDP_REVISION: u8 = 2;

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, AsBytes, FromBytes, FromZeroes)]
pub struct AcpiTableRsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_physical_address: u32,
    pub length: u32,
    pub xsdt_physical_address: [u32; 2],
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, AsBytes, FromBytes, FromZeroes)]
pub struct AcpiTableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub asl_compiler_id: [u8; 4],
    pub asl_compiler_revision: u32,
}

pub const XSDT_REVISION: u8 = 1;

#[repr(C, align(4))]
#[derive(Debug, Clone)]
pub struct AcpiTableXsdt<const N: usize> {
    pub header: AcpiTableHeader,
    pub entries: [[u32; 2]; N],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, AsBytes, Default, FromBytes, FromZeroes)]
pub struct AcpiGenericAddress {
    pub space_id: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_width: u8,
    pub address: [u32; 2],
}

pub const FADT_MAJOR_VERSION: u8 = 6;
pub const FADT_MINOR_VERSION: u8 = 4;

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, AsBytes, FromBytes, FromZeroes)]
pub struct AcpiTableFadt {
    pub header: AcpiTableHeader,
    pub facs: u32,
    pub dsdt: u32,
    pub model: u8,
    pub preferred_profile: u8,
    pub sci_interrupt: u16,
    pub smi_command: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4_bios_request: u8,
    pub pstate_control: u8,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm2_control_block: u32,
    pub pm_timer_block: u32,
    pub gpe0_block: u32,
    pub gpe1_block: u32,
    pub pm1_event_length: u8,
    pub pm1_control_length: u8,
    pub pm2_control_length: u8,
    pub pm_timer_length: u8,
    pub gpe0_block_length: u8,
    pub gpe1_block_length: u8,
    pub gpe1_base: u8,
    pub cst_control: u8,
    pub c2_latency: u16,
    pub c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,
    pub boot_flags: u8,
    pub boot_flags_hi: u8,
    pub reserved: u8,
    pub flags: u32,
    pub reset_register: AcpiGenericAddress,
    pub reset_value: u8,
    pub arm_boot_flags: u8,
    pub arm_boot_flags_hi: u8,
    pub minor_revision: u8,
    pub xfacs: [u32; 2],
    pub xdsdt: [u32; 2],
    pub xpm1a_event_block: AcpiGenericAddress,
    pub xpm1b_event_block: AcpiGenericAddress,
    pub xpm1a_control_block: AcpiGenericAddress,
    pub xpm1b_control_block: AcpiGenericAddress,
    pub xpm2_control_block: AcpiGenericAddress,
    pub xpm_timer_block: AcpiGenericAddress,
    pub xgpe0_block: AcpiGenericAddress,
    pub xgpe1_block: AcpiGenericAddress,
    pub sleep_control: AcpiGenericAddress,
    pub sleep_status: AcpiGenericAddress,
    pub hypervisor_id: [u8; 8],
}

pub const MADT_REVISION: u8 = 6;

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, AsBytes, FromBytes, FromZeroes)]
pub struct AcpiTableMadt {
    pub header: AcpiTableHeader,
    pub address: u32,
    pub flags: u32,
}

pub const MADT_IO_APIC: u8 = 1;
pub const MADT_LOCAL_X2APIC: u8 = 9;

#[repr(C)]
#[derive(Debug, Clone, AsBytes, Default, FromBytes, FromZeroes)]
pub struct AcpiSubtableHeader {
    pub type_: u8,
    pub length: u8,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, AsBytes, Default, FromBytes, FromZeroes)]
pub struct AcpiMadtLocalX2apic {
    pub header: AcpiSubtableHeader,
    pub reserved: u16,
    pub local_apic_id: u32,
    pub lapic_flags: u32,
    pub uid: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, AsBytes, Default, FromBytes, FromZeroes)]
pub struct AcpiMadtIoApic {
    pub header: AcpiSubtableHeader,
    pub id: u8,
    pub reserved: u8,
    pub address: u32,
    pub global_irq_base: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, AsBytes, Default, FromBytes, FromZeroes)]
pub struct AcpiMcfgAllocation {
    pub address: [u32; 2],
    pub pci_segment: u16,
    pub start_bus_number: u8,
    pub end_bus_number: u8,
    pub reserved: u32,
}

pub const MCFG_REVISION: u8 = 1;

#[repr(C, align(4))]
#[derive(Debug, Clone)]
pub struct AcpiTableMcfg<const N: usize> {
    pub header: AcpiTableHeader,
    pub reserved: [u8; 8],
    pub allocations: [AcpiMcfgAllocation; N],
}

bitfield! {
    /// Sleep Control Register
    ///
    /// [Spec Table 4.19](https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/04_ACPI_Hardware_Specification/ACPI_Hardware_Specification.html#sleep-control-and-status-registers)
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct FadtSleepControlReg(u8);
    impl Debug;
    pub _reserved2, _:  7, 6;
    pub slp_en, _: 5;
    pub sle_typx, _: 4, 2;
    pub ignore, _: 1;
    pub _reserved1, _: 0;
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::{
        AcpiGenericAddress, AcpiMadtIoApic, AcpiMadtLocalX2apic, AcpiMcfgAllocation, AcpiTableFadt,
        AcpiTableHeader, AcpiTableMadt, AcpiTableMcfg, AcpiTableRsdp, AcpiTableXsdt,
    };

    #[test]
    fn test_size() {
        assert_eq!(size_of::<AcpiTableRsdp>(), 36);
        assert_eq!(size_of::<AcpiTableHeader>(), 36);
        assert_eq!(size_of::<AcpiGenericAddress>(), 12);
        assert_eq!(size_of::<AcpiTableFadt>(), 276);
        assert_eq!(size_of::<AcpiTableMadt>(), 44);
        assert_eq!(size_of::<AcpiMadtIoApic>(), 12);
        assert_eq!(size_of::<AcpiMadtLocalX2apic>(), 16);
        assert_eq!(size_of::<AcpiMcfgAllocation>(), 16);
        assert_eq!(size_of::<AcpiTableMcfg<1>>(), 60);
        assert_eq!(size_of::<AcpiTableXsdt<0>>(), 36);
        assert_eq!(size_of::<AcpiTableXsdt<4>>(), 36 + 4 * 8);
    }
}
