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

#[path = "acpi/acpi.rs"]
pub mod acpi;
#[path = "arch/arch.rs"]
pub mod arch;
#[path = "board/board.rs"]
pub mod board;
#[path = "device/device.rs"]
pub mod device;
#[path = "hv/hv.rs"]
pub mod hv;
#[path = "loader/loader.rs"]
pub mod loader;
#[path = "mem/mem.rs"]
pub mod mem;
#[path = "pci/pci.rs"]
pub mod pci;
#[path = "utils/utils.rs"]
pub(crate) mod utils;
#[path = "virtio/virtio.rs"]
pub mod virtio;
pub mod vm;
