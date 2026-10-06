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
use std::sync::atomic::AtomicU8;

use parking_lot::RwLock;
use thiserror::Error;

use crate::host::{self, Hypervisor, MsiSender, Token};
use crate::hw::pci::bus::PciBus;
use crate::hw::pci::{self, PciDevice};
use crate::hw::serial::Serial;
use crate::hw::{self, ArchBoard, Board, BoardConfig, STATE_CREATED};
use crate::loader::{self, Payload};
use crate::mem::Memory;
use crate::virtio::dev::{DevParam, Virtio, VirtioDevice};
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
    next_token: u64,
}

impl Machine {
    pub fn new(hv: &dyn Hypervisor, config: BoardConfig) -> Result<Self, Error> {
        let mut vm = hv.create_vm()?;
        let vm_memory = vm.create_vm_memory()?;
        let memory = Memory::new(vm_memory);
        let arch = ArchBoard::new(hv)?;

        let board = Board {
            vm,
            memory,
            arch,
            config,
            state: AtomicU8::new(STATE_CREATED),
            payload: RwLock::new(None),
            vcpus: RwLock::new(Vec::new()),
            io_devs: RwLock::new(Vec::new()),
            com1: RwLock::new(None),
            virtio_devs: RwLock::new(Vec::new()),
            pci_bus: PciBus::new(),
            pci_devs: RwLock::new(Vec::new()),
        };

        let machine = Machine {
            board: Arc::new(board),
            next_token: 0,
        };
        Ok(machine)
    }

    pub fn add_com1(&self) -> Result<(), Error> {
        let com1_intx_sender = self.board.vm.create_intx_sender(4)?;
        let com1_console = self.board.vm.create_serial_console()?;
        let com1 = Arc::new(Serial::new(0x3f8, com1_intx_sender, com1_console)?);
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

    #[allow(clippy::type_complexity)]
    pub fn add_virtio_dev<D, P>(
        &mut self,
        name: String,
        param: P,
    ) -> Result<Arc<VirtioPciDevice<D, Box<dyn MsiSender>>>, Error>
    where
        P: DevParam<Device = D>,
        D: Virtio,
    {
        let name = Arc::new(name);
        let token = Token(self.next_token);
        self.next_token += 1;
        let dev = param.build(name.clone(), self.board.vm.as_ref())?;
        let virtio_dev =
            VirtioDevice::new(name.clone(), token, dev, self.board.memory.ram_bus().clone())?;
        let msi_sender = self.board.vm.create_msi_sender()?;
        let dev = VirtioPciDevice::new(virtio_dev, msi_sender)?;
        self.board.virtio_devs.write().push(dev.dev.clone());
        let dev = Arc::new(dev);
        let pci_dev = PciDevice::new(name.clone(), dev.clone());
        self.add_pci_dev(pci_dev)?;
        Ok(dev)
    }

    pub fn add_payload(&mut self, payload: Payload) {
        *self.board.payload.write() = Some(payload)
    }

    pub fn boot(&mut self) -> Result<(), Error> {
        self.board.boot()?;
        Ok(())
    }

    pub fn wait(&mut self) -> Vec<Result<()>> {
        vec![self.board.run_event_loop().map_err(Error::Board)]
    }
}
