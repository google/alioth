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

use crate::hv::Kvm;
use crate::loader::Payload;
use crate::virtio::dev::blk::BlockParam;
use crate::vm::{BoardConfig, Machine};

#[path = "arch/arch.rs"]
pub mod arch;
pub mod board;
mod config;
#[path = "firmware/firmware.rs"]
pub mod firmware;
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

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: `{} -c $CONFIG_FILENAME_TOML`.",
        env!("CARGO_PKG_NAME")
    );
    std::process::exit(1)
}

fn run() -> Result<(), vm::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1].as_str() != "-c" {
        print_usage_and_exit();
    }
    let config = config::parse_config(args[2].as_str())?;

    let log_file = std::fs::File::create(config.log_file.as_path()).map_err(|source| {
        vm::Error::LogFileCreate {
            path: config.log_file.clone(),
            source,
        }
    })?;
    simplelog::WriteLogger::init(config.log_level, simplelog::Config::default(), log_file).unwrap();

    let payload = Payload {
        executable: config.kernel,
        initramfs: config.initramfs,
        cmd_line: config.cmd_line,
    };

    let vm = Arc::new(Machine::new(
        Kvm::new()?,
        BoardConfig {
            mem_size: config.mem_size,
            num_cpu: config.num_cpus,
        },
    )?);
    vm.add_com1()?;
    vm.add_payload(payload);

    for (net_dev_name, net_dev_param) in config.net {
        vm.add_virtio_dev(net_dev_name, net_dev_param)?;
    }
    for (index, blk) in config.blk.into_iter().enumerate() {
        let param = BlockParam { path: blk };
        vm.add_virtio_dev(format!("virtio-blk-{index}"), param)?;
    }

    vm.clone().boot()?;

    for result in vm.wait() {
        result?;
    }

    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
