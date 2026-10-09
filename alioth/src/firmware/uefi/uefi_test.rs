// Copyright 2026 Google LLC
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

use std::mem::size_of;

use super::{
    EfiConfigTable64, EfiMemoryDesc, EfiRtPropertiesTable, EfiSystemTable64, EfiTableHeader,
    LinuxEfiMemreserve,
};

#[test]
fn test_size() {
    assert_eq!(size_of::<EfiTableHeader>(), 24);
    assert_eq!(size_of::<EfiConfigTable64>(), 24);
    assert_eq!(size_of::<EfiRtPropertiesTable>(), 8);
    assert_eq!(size_of::<LinuxEfiMemreserve>(), 16);
    assert_eq!(size_of::<EfiSystemTable64>(), 120);
    assert_eq!(size_of::<EfiMemoryDesc>(), 40);
}
