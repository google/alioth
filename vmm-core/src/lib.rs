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
#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::host::abi::{
    EXEC_TYPE_LINUX, EXEC_TYPE_PVH, MAX_VIRTIO_DEVS, ShmBootInfo, ShmVirtioDeviceSpec,
};
use crate::host::{CoreBootInfo, VirtioDeviceSpec, VmmCoreBridge, VmmHostCore};
use crate::hw::BoardConfig;
use crate::loader::{ExecType, Payload};
use crate::vm::Machine;

pub mod alloc_wasm;
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
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub fn read_boot_config(
    bridge: &dyn VmmCoreBridge,
) -> Result<(CoreBootInfo, Vec<VirtioDeviceSpec>), host::HvError> {
    let mut raw_boot = ShmBootInfo::default();
    let mut raw_devs = vec![ShmVirtioDeviceSpec::default(); MAX_VIRTIO_DEVS];
    let num_devs = bridge.boot_info(&mut raw_boot, &mut raw_devs)?;
    raw_devs.truncate(num_devs);

    let exec_type = match raw_boot.exec_type {
        EXEC_TYPE_LINUX => Some(ExecType::Linux),
        EXEC_TYPE_PVH => Some(ExecType::Pvh),
        _ => None,
    };
    let cmd_line_len = (raw_boot.cmd_line_len as usize).min(raw_boot.cmd_line.len());
    let cmd_line = if cmd_line_len > 0 {
        Some(String::from_utf8_lossy(&raw_boot.cmd_line[..cmd_line_len]).into_owned())
    } else {
        None
    };
    let initramfs_size = if raw_boot.initramfs_size > 0 {
        Some(raw_boot.initramfs_size)
    } else {
        None
    };
    let boot_info = CoreBootInfo {
        num_cpus: raw_boot.num_cpus,
        mem_size: raw_boot.mem_size as usize,
        exec_type,
        kernel_size: raw_boot.kernel_size,
        initramfs_size,
        cmd_line,
    };

    let mut specs = Vec::with_capacity(raw_devs.len());
    for raw in raw_devs {
        let name_len = (raw.name_len as usize).min(raw.name.len());
        let name = String::from_utf8_lossy(&raw.name[..name_len]).into_owned();
        let cfg_len = (raw.config_len as usize).min(raw.config_bytes.len());
        let config_bytes = raw.config_bytes[..cfg_len].to_vec();
        specs.push(VirtioDeviceSpec {
            dev: raw.dev as u32,
            name,
            device_id: raw.device_id,
            device_features: raw.device_features,
            num_queues: raw.num_queues,
            config_bytes,
        });
    }
    Ok((boot_info, specs))
}

/// Construct, configure, and initialize the VM [`Machine`] from `bridge` boot metadata.
pub fn init_machine(
    hv: Arc<dyn VmmHostCore>,
    bridge: Arc<dyn VmmCoreBridge>,
) -> Result<Machine, vm::Error> {
    let (boot_info, virtio_specs) = read_boot_config(bridge.as_ref())?;

    let payload = boot_info.exec_type.map(|exec_type| Payload {
        exec_type,
        kernel_size: boot_info.kernel_size,
        initramfs_size: boot_info.initramfs_size,
        cmd_line: boot_info.cmd_line,
    });

    let mut vm = Machine::new(
        hv,
        bridge,
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

    vm.init_vm()?;
    Ok(vm)
}
