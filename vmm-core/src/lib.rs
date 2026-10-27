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
#![allow(clippy::missing_safety_doc)]

use std::sync::Arc;

use crate::host::Hypervisor;
use crate::hw::BoardConfig;
use crate::loader::Payload;
use crate::vm::Machine;

pub mod host;
#[path = "hw/board.rs"]
pub mod hw;
#[path = "loader/loader.rs"]
pub mod loader;
#[path = "mem/mem.rs"]
pub mod mem;
pub mod sync;
pub(crate) mod utils;
#[path = "virtio/virtio.rs"]
pub mod virtio;
pub mod vm;
#[cfg(target_os = "wasi")]
pub mod wasm;

pub fn run(hv: Arc<dyn Hypervisor>) -> Result<(), Box<dyn std::error::Error>> {
    let (boot_info, virtio_specs) = hv.core_get_boot_info()?;

    let payload = boot_info.exec_type.map(|exec_type| Payload {
        exec_type,
        kernel_size: boot_info.kernel_size,
        initramfs_size: boot_info.initramfs_size,
        cmd_line: boot_info.cmd_line,
    });

    let mut vm = Machine::new(
        Arc::clone(&hv),
        BoardConfig {
            mem_size: boot_info.mem_size,
            num_cpu: boot_info.num_cpus,
        },
    )?;
    vm.add_com1()?;

    if let Some(payload) = payload {
        vm.add_payload(payload);
    }

    for spec in virtio_specs {
        vm.add_virtio_spec(spec)?;
    }

    vm.boot()?;

    for result in vm.wait() {
        result?;
    }

    Ok(())
}
