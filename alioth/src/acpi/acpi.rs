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

use std::mem::{size_of, size_of_val};

use zerocopy::AsBytes;

use crate::arch::layout::PCIE_CONFIG_START;
#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{APIC_START, IOAPIC_START};
use crate::{align_up, unsafe_impl_zerocopy};

use bindings::{
    AcpiGenericAddress, AcpiMadtIoApic, AcpiMadtLocalX2apic, AcpiMcfgAllocation,
    AcpiSubtableHeader, AcpiTableFadt, AcpiTableHeader, AcpiTableMadt, AcpiTableMcfg,
    AcpiTableRsdp, AcpiTableXsdt, FADT_MAJOR_VERSION, FADT_MINOR_VERSION, MADT_IO_APIC,
    MADT_LOCAL_X2APIC, MADT_REVISION, MCFG_REVISION, RSDP_REVISION, SIG_FADT, SIG_MADT, SIG_MCFG,
    SIG_RSDP, SIG_XSDT, XSDT_REVISION,
};

unsafe_impl_zerocopy!(AcpiTableMcfg<1>, FromBytes, FromZeroes, AsBytes);
unsafe_impl_zerocopy!(AcpiTableXsdt<3>, FromBytes, FromZeroes, AsBytes);

pub const DSDT_DSDTTBL_HEADER: [u8; 324] = [
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
fn gencsum<'a, T>(data: T) -> u8
where
    T: IntoIterator<Item = &'a u8>,
{
    (!wrapping_sum(data)).wrapping_add(1)
}

#[inline]
fn wrapping_sum<'a, T>(data: T) -> u8
where
    T: IntoIterator<Item = &'a u8>,
{
    data.into_iter().fold(0u8, |accu, e| accu.wrapping_add(*e))
}

fn encode_addr64(addr: usize) -> [u32; 2] {
    [addr as u32, (addr >> 32) as u32]
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
pub fn create_rsdp(xsdt_addr: usize) -> AcpiTableRsdp {
    let mut rsdp = AcpiTableRsdp {
        signature: SIG_RSDP,
        oem_id: OEM_ID,
        revision: RSDP_REVISION,
        length: size_of::<AcpiTableRsdp>() as u32,
        xsdt_physical_address: encode_addr64(xsdt_addr),
        ..Default::default()
    };
    rsdp.checksum = gencsum(&rsdp.as_bytes()[0..20]);
    rsdp.extended_checksum = gencsum(rsdp.as_bytes());
    rsdp
}

// https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#extended-system-description-table-fields-xsdt
pub fn create_xsdt(entries: [usize; 3]) -> AcpiTableXsdt<3> {
    let total_length = size_of::<AcpiTableHeader>() + size_of::<u64>() * 3;
    let entries = entries.map(encode_addr64);
    let mut xsdt = AcpiTableXsdt {
        header: AcpiTableHeader {
            signature: SIG_XSDT,
            length: total_length as u32,
            revision: XSDT_REVISION,
            ..default_header()
        },
        entries,
    };
    xsdt.header.checksum = gencsum(xsdt.as_bytes());
    xsdt
}

// https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#fadt-format
pub fn create_fadt(dsdt_addr: usize) -> AcpiTableFadt {
    let mut fadt = AcpiTableFadt {
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
            address: encode_addr64(0x604),
        },
        reset_value: 0x1,
        sleep_control: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: encode_addr64(0x600),
        },
        sleep_status: AcpiGenericAddress {
            space_id: 1,
            bit_width: 8,
            bit_offset: 0,
            access_width: 1,
            address: encode_addr64(0x601),
        },
        flags: (1 << 20) | (1 << 10),
        minor_revision: FADT_MINOR_VERSION,
        hypervisor_id: *b"ALIOTH  ",
        xdsdt: encode_addr64(dsdt_addr),
        ..Default::default()
    };
    fadt.header.checksum = gencsum(fadt.as_bytes());
    fadt
}

// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#multiple-apic-description-table-madt
#[cfg(target_arch = "x86_64")]
pub fn create_madt(num_cpu: u32) -> (AcpiTableMadt, AcpiMadtIoApic, Vec<AcpiMadtLocalX2apic>) {
    let total_length = size_of::<AcpiTableMadt>()
        + size_of::<AcpiMadtIoApic>()
        + num_cpu as usize * size_of::<AcpiMadtLocalX2apic>();

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

    let mut x2apics = vec![];
    let mut sums = vec![
        wrapping_sum(madt.as_bytes()),
        wrapping_sum(io_apic.as_bytes()),
    ];

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
        sums.push(wrapping_sum(x2apic.as_bytes()));
        x2apics.push(x2apic);
    }

    madt.header.checksum = gencsum(&sums);

    (madt, io_apic, x2apics)
}

pub fn create_mcfg() -> AcpiTableMcfg<1> {
    let mut mcfg = AcpiTableMcfg {
        header: AcpiTableHeader {
            signature: SIG_MCFG,
            length: size_of::<AcpiTableMcfg<1>>() as u32,
            revision: MCFG_REVISION,
            ..default_header()
        },
        reserved: [0; 8],
        allocations: [AcpiMcfgAllocation {
            address: encode_addr64(PCIE_CONFIG_START),
            pci_segment: 0,
            start_bus_number: 0,
            end_bus_number: 0,
            ..Default::default()
        }],
    };
    mcfg.header.checksum = gencsum(mcfg.as_bytes());
    mcfg
}

#[cfg(target_arch = "x86_64")]
pub fn create_acpi_tables(start: usize, num_cpu: u32) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend(AcpiTableRsdp::default().as_bytes());

    let dsdt_addr = start + size_of::<AcpiTableRsdp>();
    buf.extend(&DSDT_DSDTTBL_HEADER);

    let fadt_addr = align_up!(dsdt_addr + size_of_val(&DSDT_DSDTTBL_HEADER), 4);
    let fadt = create_fadt(dsdt_addr);
    buf.extend(fadt.as_bytes());
    log::trace!("fadt: {:#x?}", fadt);

    let madt_addr = fadt_addr + size_of_val(&fadt);
    let (madt, madt_ioapic, madt_apics) = create_madt(num_cpu);
    buf.extend(madt.as_bytes());
    buf.extend(madt_ioapic.as_bytes());
    for apic in madt_apics.iter() {
        buf.extend(apic.as_bytes());
    }
    log::trace!("madt: {:#x?} {:#x?} {:#x?}", madt, madt_ioapic, madt_apics);

    let mcfg_addr = madt_addr + madt.header.length as usize;
    let mcfg = create_mcfg();
    log::trace!("mcfg: {:#x?}", mcfg);
    buf.extend(mcfg.as_bytes());

    let xsdt_addr = mcfg_addr + size_of_val(&mcfg);
    let xsdt = create_xsdt([fadt_addr, madt_addr, mcfg_addr]);
    log::trace!("xsdt: {:#x?}", xsdt);
    buf.extend(xsdt.as_bytes());

    let rsdp = create_rsdp(xsdt_addr);
    buf[0..size_of_val(&rsdp)].copy_from_slice(rsdp.as_bytes());

    buf
}
