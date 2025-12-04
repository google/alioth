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

pub mod dtb;

use std::collections::HashMap;
use std::mem::size_of_val;

#[derive(Debug, Clone)]
pub enum PropVal {
    Empty,
    U32(u32),
    U64(u64),
    String(String),
    Str(&'static str),
    PHandle(u32),
    StringList(Vec<String>),
    U32List(Vec<u32>),
    U64List(Vec<u64>),
    Bytes(Vec<u8>),
}

impl PropVal {
    pub fn size(&self) -> usize {
        match self {
            PropVal::Empty => 0,
            PropVal::U32(_) | PropVal::PHandle(_) => 4,
            PropVal::U64(_) => 8,
            PropVal::String(s) => s.len() + 1,
            PropVal::Str(s) => s.len() + 1,
            PropVal::Bytes(d) => d.len(),
            PropVal::U32List(r) => size_of_val(r.as_slice()),
            PropVal::U64List(r) => size_of_val(r.as_slice()),
            PropVal::StringList(l) => l.iter().map(|s| s.len() + 1).sum(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Node {
    pub props: HashMap<&'static str, PropVal>,
    pub nodes: HashMap<String, Node>,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceTree {
    pub root: Node,
    pub reserved_mem: Vec<(usize, usize)>,
    pub boot_cpuid_phys: u32,
}

impl DeviceTree {
    pub fn new() -> Self {
        DeviceTree::default()
    }
}

#[cfg(test)]
#[path = "dt_test.rs"]
mod tests;
