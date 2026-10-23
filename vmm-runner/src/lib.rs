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

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread::ThreadId;

use crate::host::Hypervisor;
use crate::hw::BoardConfig;
use crate::loader::{ExecType, Payload};
use crate::virtio::dev::blk::BlockParam;
use crate::vm::Machine;

pub mod config;
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

struct PerThreadLogWriter {
    path: PathBuf,
    files: HashMap<ThreadId, File>,
}

impl PerThreadLogWriter {
    fn new(path: PathBuf) -> io::Result<Self> {
        let file = File::create(&path)?;
        let mut files = HashMap::new();
        files.insert(std::thread::current().id(), file);
        Ok(Self { path, files })
    }

    fn current_file(&mut self) -> io::Result<&mut File> {
        let tid = std::thread::current().id();
        if !self.files.contains_key(&tid) {
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.files.insert(tid, f);
        }
        Ok(self.files.get_mut(&tid).unwrap())
    }
}

impl Write for PerThreadLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.current_file()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.current_file()?.flush()
    }
}

pub fn run(
    config_filename: &str,
    hv: Box<dyn Hypervisor>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config::parse_config(config_filename)?;

    let log_writer = PerThreadLogWriter::new(config.log_file.clone())
        .unwrap_or_else(|e| panic!("Error creating log file {:?}: {e}", config.log_file));
    simplelog::WriteLogger::init(config.log_level, simplelog::Config::default(), log_writer)
        .unwrap();

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
        hv.as_ref(),
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
        let param = BlockParam { path: blk };
        vm.add_virtio_dev(format!("virtio-blk-{index}"), param)?;
    }

    vm.boot()?;

    for result in vm.wait() {
        result?;
    }

    Ok(())
}
