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

use std::mem::{offset_of, size_of};

use zerocopy::{Immutable, IntoBytes};

use crate::device::fw_cfg::{FILE_NAME_SIZE, FwCfgContent, FwCfgItem, create_file_name};
use crate::firmware::acpi::AcpiTable;
use crate::firmware::acpi::bindings::{AcpiTableHeader, AcpiTableRsdp};

pub const COMMAND_ALLOCATE: u32 = 0x1;
pub const COMMAND_ADD_POINTER: u32 = 0x2;
pub const COMMAND_ADD_CHECKSUM: u32 = 0x3;

pub const ALLOC_ZONE_HIGH: u8 = 0x1;
pub const ALLOC_ZONE_FSEG: u8 = 0x2;

pub const FW_CFG_FILENAME_TABLE_LOADER: &str = "etc/table-loader";
pub const FW_CFG_FILENAME_RSDP: &str = "acpi/rsdp";
pub const FW_CFG_FILENAME_ACPI_TABLES: &str = "acpi/tables";

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
pub struct Allocate {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    align: u32,
    zone: u8,
    _pad: [u8; 63],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
pub struct AddPointer {
    command: u32,
    dst: [u8; FILE_NAME_SIZE],
    src: [u8; FILE_NAME_SIZE],
    offset: u32,
    size: u8,
    _pad: [u8; 7],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
pub struct AddChecksum {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    offset: u32,
    start: u32,
    len: u32,
    _pad: [u8; 56],
}

fn create_intra_pointer(name: &str, offset: usize, size: u8) -> AddPointer {
    AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(name),
        src: create_file_name(name),
        offset: offset as u32,
        size,
        _pad: [0; 7],
    }
}

fn create_acpi_table_checksum(offset: usize, len: usize) -> AddChecksum {
    AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: (offset + offset_of!(AcpiTableHeader, checksum)) as u32,
        start: offset as u32,
        len: len as u32,
        _pad: [0; 56],
    }
}

pub fn create_acpi_loader(mut acpi_table: AcpiTable) -> [FwCfgItem; 3] {
    acpi_table.relocate(0);
    let mut table_loader_bytes: Vec<u8> = Vec::new();
    let allocate_rsdp = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        align: 4,
        zone: ALLOC_ZONE_FSEG,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_rsdp.as_bytes());

    let allocate_tables = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        align: 4,
        zone: ALLOC_ZONE_HIGH,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_tables.as_bytes());

    for pinter_offset in acpi_table.pointers().iter() {
        let pinter = create_intra_pointer(FW_CFG_FILENAME_ACPI_TABLES, *pinter_offset, 8);
        table_loader_bytes.extend(pinter.as_bytes());
    }
    for (offset, len) in acpi_table.checksums().iter() {
        let checksum = create_acpi_table_checksum(*offset, *len);
        table_loader_bytes.extend(checksum.as_bytes());
    }
    let pointer_rsdp_to_xsdt = AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(FW_CFG_FILENAME_RSDP),
        src: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: offset_of!(AcpiTableRsdp, xsdt_physical_address) as u32,
        size: 8,
        _pad: [0; 7],
    };
    table_loader_bytes.extend(pointer_rsdp_to_xsdt.as_bytes());
    let checksum_rsdp = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(AcpiTableRsdp, checksum) as u32,
        start: 0,
        len: offset_of!(AcpiTableRsdp, length) as u32,
        _pad: [0; 56],
    };
    let checksum_rsdp_ext = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(AcpiTableRsdp, extended_checksum) as u32,
        start: 0,
        len: size_of::<AcpiTableRsdp>() as u32,
        _pad: [0; 56],
    };
    table_loader_bytes.extend(checksum_rsdp.as_bytes());
    table_loader_bytes.extend(checksum_rsdp_ext.as_bytes());

    let table_loader = FwCfgItem {
        name: FW_CFG_FILENAME_TABLE_LOADER.to_owned(),
        content: FwCfgContent::Bytes(table_loader_bytes),
    };
    let (rsdp, tables) = acpi_table.take();
    let acpi_rsdp = FwCfgItem {
        name: FW_CFG_FILENAME_RSDP.to_owned(),
        content: FwCfgContent::Bytes(rsdp.as_bytes().to_owned()),
    };
    let apci_tables = FwCfgItem {
        name: FW_CFG_FILENAME_ACPI_TABLES.to_owned(),
        content: FwCfgContent::Bytes(tables),
    };
    [table_loader, acpi_rsdp, apci_tables]
}

#[cfg(test)]
#[path = "acpi_test.rs"]
mod tests;
