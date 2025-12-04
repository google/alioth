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

use std::mem::size_of;

use super::{Elf64Header, Elf64ProgramHeader, Elf64SectionHeader};

#[test]
fn test_size() {
    assert_eq!(size_of::<Elf64Header>(), 0x40);
    assert_eq!(size_of::<Elf64ProgramHeader>(), 0x38);
    assert_eq!(size_of::<Elf64SectionHeader>(), 0x40);
}
