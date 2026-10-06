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

use crate::hw::BoardConfig;
use crate::kvm::Kvm;
use crate::loader::{ExecType, Payload};
use crate::virtio::dev::blk::BlockParam;
use crate::vm::Machine;

#[path = "hw/board.rs"]
pub mod hw;
mod config;
#[path = "kvm/kvm.rs"]
pub mod kvm;
#[path = "loader/loader.rs"]
pub mod loader;
#[path = "mem/mem.rs"]
pub mod mem;
#[path = "utils/utils.rs"]
pub(crate) mod utils;
#[path = "virtio/virtio.rs"]
pub mod virtio;
pub mod vm;

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: `{} -c $CONFIG_FILENAME_TOML`.",
        env!("CARGO_PKG_NAME")
    );
    std::process::exit(1)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1].as_str() != "-c" {
        print_usage_and_exit();
    }
    let config = config::parse_config(args[2].as_str())?;

    let log_file = std::fs::File::create(config.log_file.as_path())
        .expect(format!("Error creating log file {:?}", config.log_file).as_str());
    simplelog::WriteLogger::init(config.log_level, simplelog::Config::default(), log_file).unwrap();

    let payload = if let Some(kernel) = config.kernel {
        Some(Payload {
            exec_type: ExecType::Linux,
            executable: kernel,
            initramfs: config.initramfs,
            cmd_line: config.cmd_line,
        })
    } else if let Some(pvh_kernel) = config.pvh {
        Some(Payload {
            executable: pvh_kernel,
            exec_type: ExecType::Pvh,
            initramfs: config.initramfs,
            cmd_line: config.cmd_line,
        })
    } else {
        None
    };

    let mut vm = Machine::new(
        Kvm::new()?,
        BoardConfig {
            mem_size: config.mem_size,
            num_cpu: config.num_cpus,
        },
    )?;
    vm.add_com1()?;

    if let Some(payload) = payload {
        vm.add_payload(payload);
    }

    for (net_dev_name, net_dev_param) in config.net {
        vm.add_virtio_dev(net_dev_name, net_dev_param)?;
    }
    for (index, blk) in config.blk.into_iter().enumerate() {
        let param = BlockParam { path: blk.into() };
        vm.add_virtio_dev(format!("virtio-blk-{index}"), param)?;
    }

    vm.boot()?;

    for result in vm.wait() {
        result?;
    }

    Ok(())
}
