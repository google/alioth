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

pub const MMIO_32_START: usize = 0x1000_0000; // 256 MiB
pub const MMIO_32_END: usize = 0x3000_0000; // 768 MiB, size = 512 MiB
pub const PCIE_CONFIG_START: usize = 0x3000_0000; // 768 MiB
pub const MEM_64_START: usize = 0x1_0000_0000; // 4GiB
pub const PAGE_SIZE: usize = 0x1000; // 4KiB
