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

use crate::host::{
    ExecKind, GuestMemAccess, Handle, IoBootConfig, IoBridgeEvent, IoHost, Token,
};
use crate::sync::RwLock;
use crate::virtio::dev::blk::{Block, BlockParam};
use crate::virtio::dev::iommu::{EndpointDmaView, IommuState, VirtioIommu};
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

fn configured_escape_byte() -> u8 {
    std::env::var("VMM_ESCAPE_BYTE")
        .ok()
        .and_then(|raw| {
            let s = raw.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok()
            } else if s.len() == 2 && s.starts_with('^') {
                let c = s.as_bytes()[1].to_ascii_uppercase();
                (b'A'..=b'Z').contains(&c).then_some(c - b'A' + 1)
            } else {
                s.parse::<u8>().ok()
            }
        })
        .unwrap_or(0x01)
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

    let iommu_state = if config.iommu {
        let state = Arc::new(RwLock::new(IommuState::new()));
        let dev_handle = devices.len() as Handle;
        let token = Token(dev_handle);
        let name = Arc::new(String::from("virtio-iommu"));
        let iommu_dev = VirtioIommu::new(name.clone(), state.clone());
        let raw_mem: Arc<dyn GuestMemAccess> = host.clone();
        // Place virtio-iommu at `00:01.0` (`0x0008`), matching Cloud Hypervisor.
        let vdev = VirtioDevice::new_with_memory(
            dev_handle,
            name,
            token,
            0x0008,
            iommu_dev,
            host.clone(),
            raw_mem,
        );
        specs.push(vdev.spec());
        devices.push(Box::new(vdev));
        Some(state)
    } else {
        None
    };

    let blk_count = config.blk.len();
    for (index, blk_path) in config.blk.into_iter().enumerate() {
        let dev_handle = devices.len() as Handle;
        let token = Token(dev_handle);
        let name = Arc::new(format!("virtio-blk-{index}"));
        let blk = Block::new(BlockParam { path: blk_path }, name.clone(), host.as_ref())?;
        let vdev = if let Some(ref iommu) = iommu_state {
            // Primary disk at `00:02.0` (`0x0010`), matching `pci_device_id=2` in CHV.
            let bdf = ((2 + index) as u16) << 3;
            let dma: Arc<dyn GuestMemAccess> =
                Arc::new(EndpointDmaView::new(bdf, iommu.clone(), host.clone()));
            VirtioDevice::new_with_memory(dev_handle, name, token, bdf, blk, host.clone(), dma)
        } else {
            VirtioDevice::new(dev_handle, name, token, blk, host.clone())
        };
        specs.push(vdev.spec());
        devices.push(Box::new(vdev));
    }

    let net_base_slot = 2 + blk_count.max(1);
    for (net_idx, (net_dev_name, net_dev_param)) in config.net.into_iter().enumerate() {
        let dev_handle = devices.len() as Handle;
        let token = Token(dev_handle);
        let name = Arc::new(net_dev_name);
        let net = Net::build(net_dev_param, name.clone(), host.as_ref())?;
        let vdev = if let Some(ref iommu) = iommu_state {
            // Primary NIC at `00:03.0` (`0x0018`), matching `pci_device_id=3` in CHV.
            let bdf = ((net_base_slot + net_idx) as u16) << 3;
            let dma: Arc<dyn GuestMemAccess> =
                Arc::new(EndpointDmaView::new(bdf, iommu.clone(), host.clone()));
            VirtioDevice::new_with_memory(dev_handle, name, token, bdf, net, host.clone(), dma)
        } else {
            VirtioDevice::new(dev_handle, name, token, net, host.clone())
        };
        specs.push(vdev.spec());
        devices.push(Box::new(vdev));
    }

    host.io_register_vm_config(&boot_cfg, &specs)?;

    let escape_byte = configured_escape_byte();
    let mut escape_pending = false;
    loop {
        match host.io_next_event()? {
            IoBridgeEvent::VirtioStart {
                dev,
                driver_features,
                queues,
            } => {
                if let Some(d) = devices.get(dev as usize)
                    && let Err(e) = d.start(driver_features, &queues)
                {
                    log::error!("virtio dev {dev}: start failed: {e}");
                }
            }
            IoBridgeEvent::VirtioNotify { dev, queue_index } => {
                if let Some(d) = devices.get(dev as usize)
                    && let Err(e) = d.notify_queue(queue_index)
                {
                    log::error!("virtio dev {dev}: queue {queue_index} fault: {e}");
                }
            }
            IoBridgeEvent::VirtioConfigWrite { dev, offset, data } => {
                if let Some(d) = devices.get(dev as usize) {
                    d.write_config(offset, &data);
                }
            }
            IoBridgeEvent::VirtioReset { dev } => {
                if let Some(d) = devices.get(dev as usize)
                    && let Err(e) = d.reset()
                {
                    log::error!("virtio dev {dev}: reset failed: {e}");
                }
            }
            IoBridgeEvent::Poll(poll_ev) => {
                if let Some(d) = devices.iter().find(|d| d.token() == poll_ev.token())
                    && let Err(e) = d.handle_poll_event(&poll_ev)
                {
                    log::error!("virtio dev {}: poll fault: {e}", d.dev_handle());
                }
            }
            IoBridgeEvent::SerialInput => {
                let mut rx_buf = VecDeque::new();
                if let Some(len) = serial.read_input(&mut rx_buf)?
                    && len > 0
                {
                    let mut forward = Vec::with_capacity(len);
                    let mut should_shutdown = false;
                    for b in rx_buf {
                        if escape_pending {
                            escape_pending = false;
                            match b {
                                b'q' | b'x' => {
                                    should_shutdown = true;
                                    break;
                                }
                                _ if b == escape_byte => forward.push(escape_byte),
                                other => {
                                    forward.push(escape_byte);
                                    forward.push(other);
                                }
                            }
                        } else if b == escape_byte {
                            escape_pending = true;
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
