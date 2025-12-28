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

use std::mem::{offset_of, size_of, size_of_val};

use zerocopy::{transmute, AsBytes, FromBytes, FromZeroes};

use crate::arch::layout::PCIE_CONFIG_START;
#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{APIC_START, IOAPIC_START};
use crate::unsafe_impl_zerocopy;

use bindings::{
    AcpiGenericAddress, AcpiMadtIoApic, AcpiMadtLocalX2apic, AcpiMcfgAllocation,
    AcpiSubtableHeader, AcpiTableFadt, AcpiTableHeader, AcpiTableMadt, AcpiTableMcfg,
    AcpiTableRsdp, AcpiTableXsdt, FADT_MAJOR_VERSION, FADT_MINOR_VERSION, MADT_IO_APIC,
    MADT_LOCAL_X2APIC, MADT_REVISION, MCFG_REVISION, RSDP_REVISION, SIG_FADT, SIG_MADT, SIG_MCFG,
    SIG_RSDP, SIG_XSDT, XSDT_REVISION,
};

unsafe_impl_zerocopy!(AcpiTableMcfg<1>, FromBytes, FromZeroes, AsBytes);
unsafe_impl_zerocopy!(AcpiTableXsdt<3>, FromBytes, FromZeroes, AsBytes);

const DSDT_DSDTTBL_HEADER: [u8; 324] = [
    0x44, 0x53, 0x44, 0x54, 0x43, 0x01, 0x00, 0x00, 0x02, 0x37, 0x41, 0x4c, 0x49, 0x4f, 0x54, 0x48,
    0x41, 0x4c, 0x49, 0x4f, 0x54, 0x48, 0x56, 0x4d, 0x01, 0x00, 0x00, 0x00, 0x49, 0x4e, 0x54, 0x4c,
    0x25, 0x09, 0x20, 0x20, 0x5b, 0x82, 0x37, 0x2e, 0x5f, 0x53, 0x42, 0x5f, 0x43, 0x4f, 0x4d, 0x31,
    0x08, 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x05, 0x01, 0x08, 0x5f, 0x55, 0x49, 0x44, 0x01,
    0x08, 0x5f, 0x53, 0x54, 0x41, 0x0a, 0x0f, 0x08, 0x5f, 0x43, 0x52, 0x53, 0x11, 0x10, 0x0a, 0x0d,
    0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x00, 0x08, 0x22, 0x10, 0x00, 0x79, 0x00, 0x08, 0x5f, 0x53,
    0x35, 0x5f, 0x12, 0x04, 0x01, 0x0a, 0x05, 0x5b, 0x82, 0x4a, 0x0d, 0x2e, 0x5f, 0x53, 0x42, 0x5f,
    0x50, 0x43, 0x49, 0x30, 0x08, 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x0a, 0x08, 0x08, 0x5f,
    0x43, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x0a, 0x03, 0x08, 0x5f, 0x53, 0x45, 0x47, 0x00, 0x08, 0x5f,
    0x55, 0x49, 0x44, 0x00, 0x14, 0x32, 0x5f, 0x44, 0x53, 0x4d, 0x04, 0xa0, 0x29, 0x93, 0x68, 0x11,
    0x13, 0x0a, 0x10, 0xd0, 0x37, 0xc9, 0xe5, 0x53, 0x35, 0x7a, 0x4d, 0x91, 0x17, 0xea, 0x4d, 0x19,
    0xc3, 0x43, 0x4d, 0xa0, 0x09, 0x93, 0x6a, 0x00, 0xa4, 0x11, 0x03, 0x01, 0x21, 0xa0, 0x07, 0x93,
    0x6a, 0x0a, 0x05, 0xa4, 0x00, 0xa4, 0x00, 0x08, 0x5f, 0x43, 0x52, 0x53, 0x11, 0x46, 0x07, 0x0a,
    0x72, 0x88, 0x0d, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x47, 0x01, 0xf8, 0x0c, 0xf8, 0x0c, 0x01, 0x08, 0x87, 0x17, 0x00, 0x00, 0x0c, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x60, 0x8a, 0x2b, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0x00,
    0x00, 0x88, 0x0d, 0x00, 0x01, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0x00,
    0xf0, 0x79, 0x00, 0x00,
];

#[inline]
fn wrapping_sum<'a, T>(data: T) -> u8
where
    T: IntoIterator<Item = &'a u8>,
{
    data.into_iter().fold(0u8, |accu, e| accu.wrapping_add(*e))
}

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
fn create_rsdp(xsdt_addr: u64) -> AcpiTableRsdp {
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
fn create_xsdt<const N: usize>(entries: [u64; N]) -> AcpiTableXsdt<N> {
    let total_length = size_of::<AcpiTableHeader>() + size_of::<u64>() * N;
    let entries = entries.map(|e| transmute!(e));
    AcpiTableXsdt {
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
fn create_fadt(dsdt_addr: u64) -> AcpiTableFadt {
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
            address: transmute!(0x604u64),
        },
        reset_value: 0x1,
        sleep_control: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: transmute!(0x600u64),
        },
        sleep_status: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: transmute!(0x601u64),
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
fn create_madt(num_cpu: u32) -> (AcpiTableMadt, AcpiMadtIoApic, Vec<AcpiMadtLocalX2apic>) {
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

fn create_mcfg() -> AcpiTableMcfg<1> {
    let mut mcfg = AcpiTableMcfg {
        header: AcpiTableHeader {
            signature: SIG_MCFG,
            length: size_of::<AcpiTableMcfg<1>>() as u32,
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
    rsdp: AcpiTableRsdp,
    tables: Vec<u8>,
    table_pointers: Vec<usize>,
    table_checksums: Vec<(usize, usize)>,
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
            let old_val: u64 = FromBytes::read_from_prefix(&self.tables[*pointer..]).unwrap();
            let new_val = old_val.wrapping_sub(old_addr).wrapping_add(table_addr);
            AsBytes::write_to_prefix(&new_val, &mut self.tables[*pointer..]).unwrap();
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

pub fn create_acpi(num_cpu: u32) -> AcpiTable {
    let mut table_bytes = Vec::new();
    let mut pointers = vec![];
    let mut checksums = vec![];

    let mut xsdt: AcpiTableXsdt<3> = FromZeroes::new_zeroed();
    let offset_xsdt = 0;
    table_bytes.extend(xsdt.as_bytes());

    let offset_dsdt = offset_xsdt + size_of_val(&xsdt);
    table_bytes.extend(DSDT_DSDTTBL_HEADER);

    let offset_fadt = offset_dsdt + size_of_val(&DSDT_DSDTTBL_HEADER);
    debug_assert_eq!(offset_fadt % 4, 0);
    let fadt = create_fadt(offset_dsdt as u64);
    let pointer_fadt_to_dsdt = offset_fadt + offset_of!(AcpiTableFadt, xdsdt);
    table_bytes.extend(fadt.as_bytes());
    pointers.push(pointer_fadt_to_dsdt);
    checksums.push((offset_fadt, size_of_val(&fadt)));

    let offset_madt = offset_fadt + size_of_val(&fadt);
    debug_assert_eq!(offset_madt % 4, 0);
    let (madt, madt_ioapic, madt_apics) = create_madt(num_cpu);
    table_bytes.extend(madt.as_bytes());
    table_bytes.extend(madt_ioapic.as_bytes());
    for apic in madt_apics {
        table_bytes.extend(apic.as_bytes());
    }

    let offset_mcfg = offset_madt + madt.header.length as usize;
    debug_assert_eq!(offset_mcfg % 4, 0);
    let mcfg = create_mcfg();
    table_bytes.extend(mcfg.as_bytes());

    debug_assert_eq!(offset_xsdt % 4, 0);
    let xsdt_entries = [offset_fadt as u64, offset_madt as u64, offset_mcfg as u64];
    xsdt = create_xsdt(xsdt_entries);
    xsdt.write_to_prefix(&mut table_bytes);
    for index in 0..xsdt_entries.len() {
        pointers.push(offset_xsdt + offset_of!(AcpiTableXsdt<3>, entries) + index * 8);
    }
    checksums.push((offset_xsdt, size_of_val(&xsdt)));

    let rsdp = create_rsdp(offset_xsdt as u64);

    AcpiTable {
        rsdp,
        tables: table_bytes,
        table_checksums: checksums,
        table_pointers: pointers,
    }
}
