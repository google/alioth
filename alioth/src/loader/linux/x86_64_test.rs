// Copyright 2025 Google LLC
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

use std::env;
use std::path::Path;

use crate::loader::linux::load;
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::mem::{MemRegionEntry, MemRegionType};

#[test]
fn test_load() {
    let pages = ArcMemPages::from_anonymous(30 << 20, None, None).unwrap();
    let ram = RamBus::new();
    ram.add(0, pages).unwrap();

    let entries = [(
        0,
        MemRegionEntry {
            size: 30 << 20,
            type_: MemRegionType::Ram,
        },
    )];
    let dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let path = Path::new(&dir).join("../resources/vmlinuz-x86_64-6.17.y");
    load(&ram, &entries, &path, None, None).unwrap();
}
