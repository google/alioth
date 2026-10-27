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

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::ThreadId;

use crate::host::{ExecKind, Handle, IoBootConfig, IoBridgeEvent, IoHost, Token};
use crate::virtio::dev::blk::{Block, BlockParam};
use crate::virtio::dev::net::Net;
use crate::virtio::dev::{RuntimeVirtioDevice, VirtioDevice};

pub mod config;
pub mod host;
pub mod sync;
#[path = "virtio/virtio.rs"]
pub mod virtio;
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
    host: Arc<dyn IoHost>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config::parse_config(config_filename)?;

    let log_writer = PerThreadLogWriter::new(config.log_file.clone())
        .unwrap_or_else(|e| panic!("Error creating log file {:?}: {e}", config.log_file));
    simplelog::WriteLogger::init(config.log_level, simplelog::Config::default(), log_writer)
        .unwrap();

    let (exec_kind, kernel_path) = if let Some(kernel) = config.kernel {
        (Some(ExecKind::Linux), Some(kernel))
    } else if let Some(pvh) = config.pvh {
        (Some(ExecKind::Pvh), Some(pvh))
    } else {
        (None, None)
    };

    let boot_cfg = IoBootConfig {
        num_cpus: config.num_cpus,
        mem_size: config.mem_size,
        exec_kind,
        kernel_path,
        initramfs_path: config.initramfs,
        cmd_line: config.cmd_line,
    };

    let serial = host.create_serial_console()?;

    let mut devices: Vec<Box<dyn RuntimeVirtioDevice>> = Vec::new();
    let mut specs = Vec::new();

    for (net_dev_name, net_dev_param) in config.net {
        let dev_handle = devices.len() as Handle;
        let token = Token(dev_handle);
        let name = Arc::new(net_dev_name);
        let net = Net::build(net_dev_param, name.clone(), host.as_ref())?;
        let vdev = VirtioDevice::new(dev_handle, name, token, net, host.clone());
        specs.push(vdev.spec());
        devices.push(Box::new(vdev));
    }

    for (index, blk_path) in config.blk.into_iter().enumerate() {
        let dev_handle = devices.len() as Handle;
        let token = Token(dev_handle);
        let name = Arc::new(format!("virtio-blk-{index}"));
        let blk = Block::new(BlockParam { path: blk_path }, name.clone(), host.as_ref())?;
        let vdev = VirtioDevice::new(dev_handle, name, token, blk, host.clone());
        specs.push(vdev.spec());
        devices.push(Box::new(vdev));
    }

    host.io_register_vm_config(&boot_cfg, &specs)?;

    let mut ctrl_a_pending = false;
    loop {
        match host.io_next_event()? {
            IoBridgeEvent::VirtioStart {
                dev,
                driver_features,
                queues,
            } => {
                if let Some(d) = devices.get(dev as usize) {
                    d.start(driver_features, &queues)?;
                }
            }
            IoBridgeEvent::VirtioNotify { dev, queue_index } => {
                if let Some(d) = devices.get(dev as usize) {
                    d.notify_queue(queue_index)?;
                }
            }
            IoBridgeEvent::VirtioReset { dev } => {
                if let Some(d) = devices.get(dev as usize) {
                    d.reset()?;
                }
            }
            IoBridgeEvent::Poll(poll_ev) => {
                if let Some(d) = devices.iter().find(|d| d.token() == poll_ev.token()) {
                    d.handle_poll_event(&poll_ev)?;
                }
            }
            IoBridgeEvent::SerialInput => {
                let mut rx_buf = VecDeque::new();
                if let Some(len) = serial.read_input(&mut rx_buf)? {
                    if len > 0 {
                        let mut forward = Vec::with_capacity(len);
                        let mut should_shutdown = false;
                        for b in rx_buf {
                            if ctrl_a_pending {
                                ctrl_a_pending = false;
                                match b {
                                    b'q' | b'x' => {
                                        should_shutdown = true;
                                        break;
                                    }
                                    0x01 => forward.push(0x01),
                                    other => {
                                        forward.push(0x01);
                                        forward.push(other);
                                    }
                                }
                            } else if b == 0x01 {
                                ctrl_a_pending = true;
                            } else {
                                forward.push(b);
                            }
                        }
                        if !forward.is_empty() {
                            host.io_serial_push_rx(&forward)?;
                        }
                        if should_shutdown {
                            let _ = host.io_request_shutdown();
                            break;
                        }
                    }
                }
            }
            IoBridgeEvent::SerialTx(bytes) => {
                for b in bytes {
                    serial.write_byte(b)?;
                }
            }
            IoBridgeEvent::Shutdown => break,
        }
    }

    let _ = serial.shutdown();
    Ok(())
}
