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

#[cfg(test)]
#[path = "dtb_test.rs"]
mod tests;

use std::collections::HashMap;
use std::mem::size_of;

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::align_up;
use crate::firmware::dt::{DeviceTree, Node, PropVal};
use crate::utils::endian::{Bu32, Bu64};

pub const FDT_HEADER_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];
pub const FDT_HEADER_VERSION: u32 = 0x11;
pub const FDT_HEADER_LAST_COMP_VERSION: u32 = 0x10;

pub const FDT_BEGIN_NODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
pub const FDT_END_NODE: [u8; 4] = [0x00, 0x00, 0x00, 0x02];
pub const FDT_PROP: [u8; 4] = [0x00, 0x00, 0x00, 0x03];
pub const FDT_NOP: [u8; 4] = [0x00, 0x00, 0x00, 0x04];
pub const FDT_END: [u8; 4] = [0x00, 0x00, 0x00, 0x09];

fn push_string_align(data: &mut Vec<u8>, s: &str) {
    data.extend(s.as_bytes());
    let padding = align_up!(s.len() + 1, 2) - s.len();
    for _ in 0..padding {
        data.push(b'\0');
    }
}

fn pad_data(data: &mut Vec<u8>) {
    let padding = align_up!(data.len(), 2) - data.len();
    for _ in 0..padding {
        data.push(b'\0');
    }
}

impl PropVal {
    fn write_as_blob(&self, data: &mut Vec<u8>) {
        match self {
            PropVal::Empty => {}
            PropVal::U32(n) | PropVal::PHandle(n) => data.extend(n.to_be_bytes()),
            PropVal::U64(n) => data.extend(n.to_be_bytes()),
            PropVal::String(s) => push_string_align(data, s),
            PropVal::Str(s) => push_string_align(data, s),
            PropVal::Bytes(d) => {
                data.extend(d);
                pad_data(data);
            }
            PropVal::StringList(list) => {
                for s in list {
                    data.extend(s.as_bytes());
                    data.push(b'\0');
                }
                pad_data(data)
            }
            PropVal::U32List(reg) => {
                for v in reg {
                    data.extend(v.to_be_bytes())
                }
            }
            PropVal::U64List(reg) => {
                for v in reg {
                    data.extend(v.to_be_bytes())
                }
            }
        }
    }
}

#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, Debug)]
pub struct FdtHeader {
    magic: Bu32,
    total_size: Bu32,
    off_dt_struct: Bu32,
    off_dt_strings: Bu32,
    off_mem_resvmap: Bu32,
    version: Bu32,
    last_comp_version: Bu32,
    boot_cpuid_phys: Bu32,
    size_dt_strings: Bu32,
    size_dt_struct: Bu32,
}

#[derive(IntoBytes, FromBytes, Immutable, Debug)]
#[repr(C)]
pub struct FdtProp {
    len: Bu32,
    name_off: Bu32,
}

#[derive(IntoBytes, FromBytes, Immutable, Debug)]
#[repr(C)]
struct FdtReserveEntry {
    address: Bu64,
    size: Bu64,
}

#[derive(Debug)]
pub struct StringBlock {
    total_size: usize,
    strings: HashMap<&'static str, usize>,
}

impl StringBlock {
    fn new() -> Self {
        StringBlock {
            total_size: 0,
            strings: HashMap::new(),
        }
    }

    fn add(&mut self, name: &'static str) -> usize {
        if let Some(offset) = self.strings.get(&name) {
            *offset
        } else {
            self.strings.insert(name, self.total_size);
            let ret = self.total_size;
            self.total_size += name.len() + 1;
            ret
        }
    }

    fn write_as_blob(self, data: &mut Vec<u8>) {
        let mut string_offset = self.strings.into_iter().collect::<Vec<_>>();
        string_offset.sort_by_key(|(_, offset)| *offset);
        for (s, _) in string_offset {
            data.extend(s.as_bytes());
            data.push(b'\0');
        }
        pad_data(data)
    }
}

impl Node {
    fn write_as_blob(&self, name: &str, string_block: &mut StringBlock, data: &mut Vec<u8>) {
        data.extend(&FDT_BEGIN_NODE);
        push_string_align(data, name);
        for (prop_name, prop) in self.props.iter() {
            data.extend(&FDT_PROP);
            let fdt_prop = FdtProp {
                len: Bu32::from(prop.size() as u32),
                name_off: Bu32::from(string_block.add(prop_name) as u32),
            };
            data.extend(fdt_prop.as_bytes());
            prop.write_as_blob(data);
        }
        for (node_name, node) in self.nodes.iter() {
            node.write_as_blob(node_name, string_block, data)
        }
        data.extend(&FDT_END_NODE);
    }
}

impl DeviceTree {
    pub fn to_blob(&self) -> Vec<u8> {
        let mut data = vec![0u8; size_of::<FdtHeader>()];

        let off_mem_resvmap = data.len();
        for (addr, size) in &self.reserved_mem {
            let entry = FdtReserveEntry {
                address: Bu64::from(*addr as u64),
                size: Bu64::from(*size as u64),
            };
            data.extend(entry.as_bytes());
        }
        data.extend(FdtReserveEntry::new_zeroed().as_bytes());

        let off_dt_struct = data.len();
        let mut string_block = StringBlock::new();
        self.root.write_as_blob("", &mut string_block, &mut data);
        data.extend(&FDT_END);
        let size_dt_struct = data.len() - off_dt_struct;

        let off_dt_strings = data.len();
        string_block.write_as_blob(&mut data);
        let size_dt_strings = data.len() - off_dt_strings;

        let total_size = data.len();

        let header = FdtHeader {
            magic: Bu32::from(FDT_HEADER_MAGIC),
            total_size: Bu32::from(total_size as u32),
            off_dt_struct: Bu32::from(off_dt_struct as u32),
            off_dt_strings: Bu32::from(off_dt_strings as u32),
            off_mem_resvmap: Bu32::from(off_mem_resvmap as u32),
            version: Bu32::from(FDT_HEADER_VERSION),
            last_comp_version: Bu32::from(FDT_HEADER_LAST_COMP_VERSION),
            boot_cpuid_phys: Bu32::from(self.boot_cpuid_phys),
            size_dt_strings: Bu32::from(size_dt_strings as u32),
            size_dt_struct: Bu32::from(size_dt_struct as u32),
        };
        header.write_to_prefix(&mut data).unwrap();
        data
    }
}
