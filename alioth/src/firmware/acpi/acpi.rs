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

pub mod bindings;
pub mod reg;

use std::mem::{offset_of, size_of};

use zerocopy::{transmute, FromBytes, IntoBytes};

use crate::arch::layout::PCIE_CONFIG_START;
#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{
    APIC_START, IOAPIC_START, PORT_ACPI_RESET, PORT_ACPI_SLEEP_CONTROL, PORT_ACPI_SLEEP_STATUS,
};
use crate::utils::wrapping_sum;

use self::bindings::{
    AcpiGenericAddress, AcpiMadtIoApic, AcpiMadtLocalX2apic, AcpiMcfgAllocation,
    AcpiSubtableHeader, AcpiTableFadt, AcpiTableHeader, AcpiTableMadt, AcpiTableMcfg1,
    AcpiTableRsdp, AcpiTableXsdt3, FADT_MAJOR_VERSION, FADT_MINOR_VERSION, MADT_IO_APIC,
    MADT_LOCAL_X2APIC, MADT_REVISION, MCFG_REVISION, RSDP_REVISION, SIG_FADT, SIG_MADT, SIG_MCFG,
    SIG_RSDP, SIG_XSDT, XSDT_REVISION,
};
use self::reg::FADT_RESET_VAL;

const OEM_ID: [u8; 6] = *b"ALIOTH";

fn default_header() -> AcpiTableHeader {
    AcpiTableHeader {
        checksum: 0,
        oem_id: OEM_ID,
        oem_table_id: *b"ALIOTHVM",
        oem_revision: 1,
        asl_compiler_id: *b"ALTH",
        asl_compiler_revision: 1,
        ..Default::default()
    }
}

// https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#root-system-description-pointer-rsdp-structure
pub fn create_rsdp(xsdt_addr: u64) -> AcpiTableRsdp {
    AcpiTableRsdp {
        signature: SIG_RSDP,
        oem_id: OEM_ID,
        revision: RSDP_REVISION,
        length: size_of::<AcpiTableRsdp>() as u32,
        xsdt_physical_address: transmute!(xsdt_addr),
        ..Default::default()
    }
}

// https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#extended-system-description-table-fields-xsdt
pub fn create_xsdt(entries: [u64; 3]) -> AcpiTableXsdt3 {
    let total_length = size_of::<AcpiTableHeader>() + size_of::<u64>() * 3;
    let entries = entries.map(|e| transmute!(e));
    AcpiTableXsdt3 {
        header: AcpiTableHeader {
            signature: SIG_XSDT,
            length: total_length as u32,
            revision: XSDT_REVISION,
            ..default_header()
        },
        entries,
    }
}

// https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#fadt-format
pub fn create_fadt(dsdt_addr: u64) -> AcpiTableFadt {
    AcpiTableFadt {
        header: AcpiTableHeader {
            signature: SIG_FADT,
            revision: FADT_MAJOR_VERSION,
            length: size_of::<AcpiTableFadt>() as u32,
            ..default_header()
        },
        reset_register: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: transmute!(PORT_ACPI_RESET as u64),
        },
        reset_value: FADT_RESET_VAL,
        sleep_control: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: transmute!(PORT_ACPI_SLEEP_CONTROL as u64),
        },
        sleep_status: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: transmute!(PORT_ACPI_SLEEP_STATUS as u64),
        },
        flags: (1 << 20) | (1 << 10),
        minor_revision: FADT_MINOR_VERSION,
        hypervisor_id: *b"ALIOTH  ",
        xdsdt: transmute!(dsdt_addr),
        ..Default::default()
    }
}

// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#multiple-apic-description-table-madt
#[cfg(target_arch = "x86_64")]
pub fn create_madt(num_cpu: u32) -> (AcpiTableMadt, AcpiMadtIoApic, Vec<AcpiMadtLocalX2apic>) {
    let total_length = size_of::<AcpiTableMadt>()
        + size_of::<AcpiMadtIoApic>()
        + num_cpu as usize * size_of::<AcpiMadtLocalX2apic>();
    let mut checksum = 0u8;

    let mut madt = AcpiTableMadt {
        header: AcpiTableHeader {
            signature: SIG_MADT,
            length: total_length as u32,
            revision: MADT_REVISION,
            ..default_header()
        },
        address: APIC_START as u32,
        flags: 0,
    };
    checksum = checksum.wrapping_sub(wrapping_sum(madt.as_bytes()));

    let io_apic = AcpiMadtIoApic {
        header: AcpiSubtableHeader {
            type_: MADT_IO_APIC,
            length: size_of::<AcpiMadtIoApic>() as u8,
        },
        id: 0,
        address: IOAPIC_START as u32,
        global_irq_base: 0,
        ..Default::default()
    };
    checksum = checksum.wrapping_sub(wrapping_sum(io_apic.as_bytes()));

    let mut x2apics = vec![];
    for i in 0..num_cpu {
        let x2apic = AcpiMadtLocalX2apic {
            header: AcpiSubtableHeader {
                type_: MADT_LOCAL_X2APIC,
                length: size_of::<AcpiMadtLocalX2apic>() as u8,
            },
            local_apic_id: i,
            uid: i,
            lapic_flags: 1,
            ..Default::default()
        };
        checksum = checksum.wrapping_sub(wrapping_sum(x2apic.as_bytes()));
        x2apics.push(x2apic);
    }
    madt.header.checksum = checksum;

    (madt, io_apic, x2apics)
}

pub fn create_mcfg() -> AcpiTableMcfg1 {
    let mut mcfg = AcpiTableMcfg1 {
        header: AcpiTableHeader {
            signature: SIG_MCFG,
            length: size_of::<AcpiTableMcfg1>() as u32,
            revision: MCFG_REVISION,
            ..default_header()
        },
        reserved: [0; 8],
        allocations: [AcpiMcfgAllocation {
            address: transmute!(PCIE_CONFIG_START),
            pci_segment: 0,
            start_bus_number: 0,
            end_bus_number: 0,
            ..Default::default()
        }],
    };
    mcfg.header.checksum = 0u8.wrapping_sub(wrapping_sum(mcfg.as_bytes()));
    mcfg
}

pub struct AcpiTable {
    pub(crate) rsdp: AcpiTableRsdp,
    pub(crate) tables: Vec<u8>,
    pub(crate) table_pointers: Vec<usize>,
    pub(crate) table_checksums: Vec<(usize, usize)>,
}

impl AcpiTable {
    pub fn relocate(&mut self, table_addr: u64) {
        let old_addr: u64 = transmute!(self.rsdp.xsdt_physical_address);
        self.rsdp.xsdt_physical_address = transmute!(table_addr);

        let sum = wrapping_sum(&self.rsdp.as_bytes()[0..20]);
        self.rsdp.checksum = self.rsdp.checksum.wrapping_sub(sum);
        let ext_sum = wrapping_sum(self.rsdp.as_bytes());
        self.rsdp.extended_checksum = self.rsdp.extended_checksum.wrapping_sub(ext_sum);

        for pointer in self.table_pointers.iter() {
            let (old_val, _) = u64::read_from_prefix(&self.tables[*pointer..]).unwrap();
            let new_val = old_val.wrapping_sub(old_addr).wrapping_add(table_addr);
            IntoBytes::write_to_prefix(&new_val, &mut self.tables[*pointer..]).unwrap();
        }

        for (start, len) in self.table_checksums.iter() {
            let sum = wrapping_sum(&self.tables[*start..(*start + *len)]);
            let checksum = &mut self.tables[start + offset_of!(AcpiTableHeader, checksum)];
            *checksum = checksum.wrapping_sub(sum);
        }
    }

    pub fn rsdp(&self) -> &AcpiTableRsdp {
        &self.rsdp
    }

    pub fn tables(&self) -> &[u8] {
        &self.tables
    }

    pub fn pointers(&self) -> &[usize] {
        &self.table_pointers
    }

    pub fn checksums(&self) -> &[(usize, usize)] {
        &self.table_checksums
    }

    pub fn take(self) -> (AcpiTableRsdp, Vec<u8>) {
        (self.rsdp, self.tables)
    }
}
