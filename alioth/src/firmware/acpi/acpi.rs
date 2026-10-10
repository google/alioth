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

use std::mem::offset_of;

use zerocopy::{FromBytes, IntoBytes, transmute};

use crate::utils::wrapping_sum;

use self::bindings::{AcpiTableHeader, AcpiTableRsdp};

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

        for pointer in self.table_pointers.iter() {
            let (old_val, _) = u64::read_from_prefix(&self.tables[*pointer..]).unwrap();
            let new_val = old_val.wrapping_sub(old_addr).wrapping_add(table_addr);
            IntoBytes::write_to_prefix(&new_val, &mut self.tables[*pointer..]).unwrap();
        }
    }

    pub fn update_checksums(&mut self) {
        let sum = wrapping_sum(&self.rsdp.as_bytes()[0..20]);
        self.rsdp.checksum = self.rsdp.checksum.wrapping_sub(sum);
        let ext_sum = wrapping_sum(self.rsdp.as_bytes());
        self.rsdp.extended_checksum = self.rsdp.extended_checksum.wrapping_sub(ext_sum);

        for (start, len) in self.table_checksums.iter() {
            let sum = wrapping_sum(&self.tables[*start..(*start + *len)]);
            let checksum = &mut self.tables[start + offset_of!(AcpiTableHeader, checksum)];
            *checksum = checksum.wrapping_sub(sum);
        }
    }

    pub fn clear_checksums(&mut self) {
        for (start, _) in self.table_checksums.iter() {
            let checksum = &mut self.tables[start + offset_of!(AcpiTableHeader, checksum)];
            *checksum = 0;
        }
        self.rsdp.checksum = 0;
        self.rsdp.extended_checksum = 0;
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
