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

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use thiserror::Error;

use crate::host::{self, Hypervisor, VirtioDeviceSpec};
use crate::hw::pci::bus::PciBus;
use crate::hw::pci::{self, PciDevice};
use crate::hw::serial::Serial;
use crate::hw::{
    self, ArchBoard, Board, BoardConfig, STATE_CREATED, STATE_RUNNING, STATE_SHUTDOWN,
};
use crate::loader::{self, Payload};
use crate::mem::Memory;
use crate::sync::{Condvar, Mutex, RwLock};
use crate::virtio::pci::VirtioPciDevice;
use crate::{mem, virtio};

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] host::Error),

    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("host io: {0}")]
    HostIo(#[from] std::io::Error),

    #[error("loader: {0}")]
    Loader(#[from] loader::Error),

    #[error("board: {0}")]
    Board(#[from] hw::Error),

    #[error("PCI bus: {0}")]
    PciBus(#[from] pci::Error),

    #[error("Virtio: {0}")]
    Virtio(#[from] virtio::Error),

    #[error("ACPI bytes exceed EBDA area")]
    AcpiTooLong,

    #[error("cannot handle {0:#x?}")]
    VmExit(String),
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Machine {
    board: Arc<Board>,
    event_rx: Receiver<u32>,
    event_tx: Sender<u32>,
}

impl Machine {
    pub fn new(hv: Arc<dyn Hypervisor>, config: BoardConfig) -> Result<Self, Error> {
        let mut vm = hv.create_vm()?;
        let vm_memory = vm.create_vm_memory()?;
        let memory = Memory::new(vm_memory);
        let arch = ArchBoard::new(hv.as_ref())?;

        let board = Board {
            hv,
            vm,
            memory,
            arch,
            config,
            state: AtomicU8::new(STATE_CREATED),
            payload: RwLock::new(None),
            vcpus: Arc::new(RwLock::new(Vec::new())),
            mp_sync: Arc::new((Mutex::new(0), Condvar::new())),
            io_devs: RwLock::new(Vec::new()),
            com1: RwLock::new(None),
            pci_bus: PciBus::new(),
            pci_devs: RwLock::new(Vec::new()),
        };

        let (event_tx, event_rx) = mpsc::channel();
        Ok(Machine {
            board: Arc::new(board),
            event_rx,
            event_tx,
        })
    }

    pub fn add_com1(&self) -> Result<(), Error> {
        let com1_intx_sender = self.board.vm.create_intx_sender(4)?;
        let com1 = Arc::new(Serial::new(
            0x3f8,
            com1_intx_sender,
            self.board.hv.clone(),
        )?);
        *self.board.com1.write() = Some(com1.clone());
        self.board.io_devs.write().push((0x3f8, com1));
        Ok(())
    }

    pub fn add_pci_dev(&mut self, dev: PciDevice) -> Result<(), Error> {
        let config = dev.dev.config();
        let bdf = self.board.pci_bus.add(None, config.clone())?;
        let header = config.get_header();
        header.set_bdf(bdf);
        log::info!("{} located at {bdf}", dev.name);
        self.board.pci_devs.write().push(dev);
        Ok(())
    }

    pub fn add_virtio_spec(&mut self, spec: VirtioDeviceSpec) -> Result<Arc<VirtioPciDevice>, Error> {
        let dev = Arc::new(VirtioPciDevice::from_spec(spec, self.board.hv.clone())?);
        let pci_dev = PciDevice::new(dev.name.clone(), dev.clone());
        self.add_pci_dev(pci_dev)?;
        Ok(dev)
    }

    pub fn add_payload(&mut self, payload: Payload) {
        *self.board.payload.write() = Some(payload)
    }

    pub fn boot(&mut self) -> Result<(), Error> {
        let mut vcpus = self.board.vcpus.write();
        for vcpu_id in 0..self.board.config.num_cpu {
            let (boot_tx, boot_rx) = mpsc::channel();
            let event_tx = self.event_tx.clone();
            let board = self.board.clone();
            let handle = thread::Builder::new()
                .name(format!("vcpu_{vcpu_id}"))
                .spawn(move || board.run_vcpu(vcpu_id, event_tx, boot_rx))?;
            self.event_rx.recv().unwrap();
            vcpus.push((handle, boot_tx));
        }

        self.board.state.store(STATE_RUNNING, Ordering::Release);
        for (_, boot_tx) in vcpus.iter() {
            boot_tx.send(()).unwrap();
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Vec<Result<()>> {
        if let Err(e) = self.board.run_serial_rx_loop() {
            log::error!("serial rx loop error: {e}");
        }

        if self
            .board
            .state
            .compare_exchange(
                STATE_RUNNING,
                STATE_SHUTDOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let vcpus = self.board.vcpus.read();
            for vcpu_id in 0..vcpus.len() {
                let _ = self.board.vm.stop_vcpu(vcpu_id as u32);
            }
        }

        let num_vcpus = self.board.vcpus.read().len();
        for _ in 0..num_vcpus {
            let _ = self.event_rx.recv();
        }

        let _ = self.board.hv.core_notify_shutdown();

        let mut vcpus = self.board.vcpus.write();
        vcpus
            .drain(..)
            .enumerate()
            .map(|(id, (handle, _))| match handle.join() {
                Err(e) => {
                    log::error!("cannot join vcpu {id}: {e:?}");
                    Ok(())
                }
                Ok(r) => r.map_err(Error::Board),
            })
            .collect()
    }
}
