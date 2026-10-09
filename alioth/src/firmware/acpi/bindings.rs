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
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{bitflags, consts};

pub const SIG_RSDP: [u8; 8] = *b"RSD PTR ";

consts! {
    pub struct AcpiSignature([u8; 4]) {
        XSDT = *b"XSDT";
        FADT = *b"FACP";
        MADT = *b"APIC";
        MCFG = *b"MCFG";
        GTDT = *b"GTDT";
        IORT = *b"IORT";
        SPCR = *b"SPCR";
        PPTT = *b"PPTT";
        DSDT = *b"DSDT";
    }
}

pub const RSDP_REVISION: u8 = 2;

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
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
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableHeader {
    pub signature: AcpiSignature,
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

#[derive(Debug, FromBytes)]
#[repr(C, align(4))]
pub struct AcpiTableXsdt<const N: usize> {
    pub header: AcpiTableHeader,
    pub entries: [[u32; 2]; N],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableXsdt3 {
    pub header: AcpiTableHeader,
    pub entries: [[u32; 2]; 3],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableXsdt6 {
    pub header: AcpiTableHeader,
    pub entries: [[u32; 2]; 6],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableXsdt7 {
    pub header: AcpiTableHeader,
    pub entries: [[u32; 2]; 7],
}

consts! {
    #[derive(zerocopy::Unaligned)]
    pub struct AcpiSpaceId(u8) {
        SYSTEM_MEMORY = 0x00;
        SYSTEM_IO = 0x01;
        PCI_CONFIG = 0x02;
        EMBEDDED_CONTROLLER = 0x03;
        SMBUS = 0x04;
        SYSTEM_CMOS = 0x05;
        PCI_BAR_TARGET = 0x06;
        IPMI = 0x07;
        GPIO = 0x08;
        GENERIC_SERIAL_BUS = 0x09;
        PCC = 0x0A;
        FUNCTIONAL_FIXED_HARDWARE = 0x7F;
    }
}

consts! {
    #[derive(zerocopy::Unaligned)]
    pub struct AcpiAccessWidth(u8) {
        UNDEFINED = 0;
        BYTE = 1;
        WORD = 2;
        DWORD = 3;
        QWORD = 4;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiGenericAddress {
    pub space_id: AcpiSpaceId,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_width: AcpiAccessWidth,
    pub address: [u32; 2],
}

pub const FADT_MAJOR_VERSION: u8 = 6;
pub const FADT_MINOR_VERSION: u8 = 4;

bitflags! {
    pub struct AcpiFadtFlag(u32) {
        TMR_VAL_EXT = 1 << 8;
        RESET_REG_SUP = 1 << 10;
        HW_REDUCED_ACPI = 1 << 20;
    }
}

bitflags! {
    pub struct AcpiFadtArmBootFlag(u8) {
        PSCI_COMPLIANT = 1 << 0;
        PSCI_USE_HVC = 1 << 1;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
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
    pub flags: AcpiFadtFlag,
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
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableMadt {
    pub header: AcpiTableHeader,
    pub address: u32,
    pub flags: u32,
}

consts! {
    #[derive(zerocopy::Unaligned)]
    pub struct AcpiMadtType(u8) {
        IO_APIC = 1;
        LOCAL_X2APIC = 9;
        GENERIC_INTERRUPT = 11;
        GENERIC_DISTRIBUTOR = 12;
        GENERIC_MSI_FRAME = 13;
        GENERIC_REDISTRIBUTOR = 14;
        GENERIC_TRANSLATOR = 15;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiSubtableHeader<T = u8> {
    pub r#type: T,
    pub length: u8,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtLocalX2apic {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub reserved: u16,
    pub local_apic_id: u32,
    pub lapic_flags: u32,
    pub uid: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtIoApic {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub id: u8,
    pub reserved: u8,
    pub address: u32,
    pub global_irq_base: u32,
}

bitflags! {
    pub struct AcpiMadtGiccFlag(u32) {
        ENABLED = 1 << 0;
        PERFORMANCE_INTERRUPT_EDGE_TRIGGERED = 1 << 1;
        VGIC_INTERRUPT_EDGE_TRIGGERED = 1 << 2;
        ONLINE_CAPABLE = 1 << 3;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtGenericInterrupt {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub reserved: u16,
    pub cpu_interface_number: u32,
    pub uid: u32,
    pub flags: AcpiMadtGiccFlag,
    pub parking_version: u32,
    pub performance_interrupt: u32,
    pub parked_address: [u32; 2],
    pub base_address: [u32; 2],
    pub gicv_base_address: [u32; 2],
    pub gich_base_address: [u32; 2],
    pub vgic_interrupt: u32,
    pub gicr_base_address: [u32; 2],
    pub arm_mpidr: [u32; 2],
    pub efficiency_class: u8,
    pub reserved2: u8,
    pub spe_interrupt: u16,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtGenericDistributor {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub reserved: u16,
    pub gic_id: u32,
    pub base_address: [u32; 2],
    pub global_irq_base: u32,
    pub version: u8,
    pub reserved2: [u8; 3],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtGenericMsiFrame {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub reserved: u16,
    pub msi_frame_id: u32,
    pub base_address: [u32; 2],
    pub flags: u32,
    pub spi_count: u16,
    pub spi_base: u16,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtGenericRedistributor {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub flags: u8,
    pub reserved: u8,
    pub base_address: [u32; 2],
    pub length: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiMadtGenericTranslator {
    pub header: AcpiSubtableHeader<AcpiMadtType>,
    pub flags: u8,
    pub reserved: u8,
    pub translation_id: u32,
    pub base_address: [u32; 2],
    pub reserved2: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
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

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableMcfg1 {
    pub header: AcpiTableHeader,
    pub reserved: [u8; 8],
    pub allocations: [AcpiMcfgAllocation; 1],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableMcfg3 {
    pub header: AcpiTableHeader,
    pub reserved: [u8; 8],
    pub allocations: [AcpiMcfgAllocation; 3],
}

pub const GTDT_REVISION: u8 = 3;

bitflags! {
    pub struct AcpiGtdtFlag(u32) {
        INTERRUPT_MODE_EDGE = 1 << 0;
        INTERRUPT_POLARITY_ACTIVE_LOW = 1 << 1;
        ALWAYS_ON = 1 << 2;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableGtdt {
    pub header: AcpiTableHeader,
    pub counter_block_address: [u32; 2],
    pub reserved: u32,
    pub secure_el1_interrupt: u32,
    pub secure_el1_flags: AcpiGtdtFlag,
    pub non_secure_el1_interrupt: u32,
    pub non_secure_el1_flags: AcpiGtdtFlag,
    pub virtual_timer_interrupt: u32,
    pub virtual_timer_flags: AcpiGtdtFlag,
    pub non_secure_el2_interrupt: u32,
    pub non_secure_el2_flags: AcpiGtdtFlag,
    pub counter_read_block_address: [u32; 2],
    pub platform_timer_count: u32,
    pub platform_timer_offset: u32,
    pub virtual_el2_timer_gsiv: u32,
    pub virtual_el2_timer_flags: AcpiGtdtFlag,
}

pub const IORT_REVISION: u8 = 5;

consts! {
    #[derive(zerocopy::Unaligned)]
    pub struct AcpiIortNodeType(u8) {
        ITS_GROUP = 0x00;
        NAMED_COMPONENT = 0x01;
        PCI_ROOT_COMPLEX = 0x02;
        SMMU_V1_V2 = 0x03;
        SMMU_V3 = 0x04;
        PMCG = 0x05;
        RMR = 0x06;
        IWB = 0x07;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableIort {
    pub header: AcpiTableHeader,
    pub node_count: u32,
    pub node_offset: u32,
    pub reserved: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiIortNode {
    pub type_: AcpiIortNodeType,
    pub length: [u8; 2],
    pub revision: u8,
    pub identifier: u32,
    pub mapping_count: u32,
    pub mapping_offset: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiIortIdMapping {
    pub input_base: u32,
    pub id_count: u32,
    pub output_base: u32,
    pub output_reference: u32,
    pub flags: u32,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiIortMemoryAccess {
    pub cache_coherency: u32,
    pub hints: u8,
    pub reserved: [u8; 2],
    pub memory_flags: u8,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiIortItsGroup1 {
    pub node: AcpiIortNode,
    pub its_count: u32,
    pub identifiers: [u32; 1],
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiIortRootComplex1 {
    pub node: AcpiIortNode,
    pub memory_properties: AcpiIortMemoryAccess,
    pub ats_attribute: u32,
    pub pci_segment_number: u32,
    pub memory_address_limit: u8,
    pub pasid_capabilities: [u8; 2],
    pub reserved: u8,
    pub flags: u32,
    pub mappings: [AcpiIortIdMapping; 1],
}

pub const SPCR_REVISION: u8 = 2;
pub const SPCR_INTERFACE_ARM_PL011: u8 = 0x03;

bitflags! {
    pub struct AcpiSpcrInterruptType(u8) {
        PC_AT_PIC = 1 << 0;
        IO_APIC = 1 << 1;
        IO_SAPIC = 1 << 2;
        GIC = 1 << 3;
        PLIC_APLIC = 1 << 4;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTableSpcr {
    pub header: AcpiTableHeader,
    pub interface_type: u8,
    pub reserved: [u8; 3],
    pub serial_port: AcpiGenericAddress,
    pub interrupt_type: AcpiSpcrInterruptType,
    pub pc_interrupt: u8,
    pub interrupt: [u8; 4],
    pub baud_rate: u8,
    pub parity: u8,
    pub stop_bits: u8,
    pub flow_control: u8,
    pub terminal_type: u8,
    pub language: u8,
    pub pci_device_id: u16,
    pub pci_vendor_id: u16,
    pub pci_bus: u8,
    pub pci_device: u8,
    pub pci_function: u8,
    pub pci_flags: [u8; 4],
    pub pci_segment: u8,
    pub uart_clk_freq: [u8; 4],
}

pub const PPTT_REVISION: u8 = 2;

consts! {
    #[derive(zerocopy::Unaligned)]
    pub struct AcpiPpttType(u8) {
        PROCESSOR = 0;
        CACHE = 1;
        ID = 2;
    }
}

bitflags! {
    pub struct AcpiPpttFlag(u32) {
        PHYSICAL_PACKAGE = 1 << 0;
        ACPI_PROCESSOR_ID_VALID = 1 << 1;
        ACPI_PROCESSOR_IS_THREAD = 1 << 2;
        ACPI_LEAF_NODE = 1 << 3;
        ACPI_IDENTICAL = 1 << 4;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiTablePptt {
    pub header: AcpiTableHeader,
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct AcpiPpttProcessor {
    pub header: AcpiSubtableHeader<AcpiPpttType>,
    pub reserved: u16,
    pub flags: AcpiPpttFlag,
    pub parent: u32,
    pub acpi_processor_id: u32,
    pub number_of_priv_resources: u32,
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
#[path = "bindings_test.rs"]
mod tests;
