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

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display, Formatter};
use core::mem::size_of;
use core::sync::atomic::AtomicU8;

use crate::host::{self, HostCaps, VirtioDeviceSpec, VmmCoreBridge, VmmHostCore};
use crate::hw::ioapic::IoApic;
use crate::hw::pci::bus::PciBus;
use crate::hw::pci::{self, PciDevice};
use crate::hw::serial::Serial;
use crate::hw::{
    self, ArchBoard, Board, BoardConfig, STATE_CREATED, StackAlign16, VcpuCommSlot,
    WORKER_STACK_SIZE,
};
use crate::loader::{self, Payload};
use crate::mem::Memory;
use crate::sync::RwLock;
use crate::virtio::pci::VirtioPciDevice;
use crate::{mem, virtio};

#[derive(Debug)]
pub enum Error {
    Hv(host::Error),
    Memory(mem::Error),
    Loader(loader::Error),
    Board(hw::Error),
    PciBus(pci::Error),
    Virtio(virtio::Error),
    AcpiTooLong,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hv(e) => write!(f, "hypervisor: {e}"),
            Self::Memory(e) => write!(f, "memory: {e}"),
            Self::Loader(e) => write!(f, "loader: {e}"),
            Self::Board(e) => write!(f, "board: {e}"),
            Self::PciBus(e) => write!(f, "PCI bus: {e}"),
            Self::Virtio(e) => write!(f, "Virtio: {e}"),
            Self::AcpiTooLong => f.write_str("ACPI bytes exceed EBDA area"),
        }
    }
}

impl core::error::Error for Error {}

impl From<host::Error> for Error {
    fn from(e: host::Error) -> Self {
        Self::Hv(e)
    }
}

impl From<mem::Error> for Error {
    fn from(e: mem::Error) -> Self {
        Self::Memory(e)
    }
}

impl From<loader::Error> for Error {
    fn from(e: loader::Error) -> Self {
        Self::Loader(e)
    }
}

impl From<hw::Error> for Error {
    fn from(e: hw::Error) -> Self {
        Self::Board(e)
    }
}

impl From<pci::Error> for Error {
    fn from(e: pci::Error) -> Self {
        Self::PciBus(e)
    }
}

impl From<virtio::Error> for Error {
    fn from(e: virtio::Error) -> Self {
        Self::Virtio(e)
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub struct Machine {
    pub board: Arc<Board>,
}

impl Machine {
    pub fn new(
        hv: Arc<dyn VmmHostCore>,
        bridge: Arc<dyn VmmCoreBridge>,
        config: BoardConfig,
    ) -> Result<Self, Error> {
        let memory = Memory::new(hv.clone());
        let arch = ArchBoard::new(hv.as_ref())?;
        let ioapic = (!hv.caps().contains(HostCaps::HW_IOAPIC))
            .then(|| Arc::new(IoApic::new(hv.clone())));

        let num_cpus_alloc = config.num_cpu.max(1) as usize;
        let comm_pages = (0..num_cpus_alloc)
            .map(|_| VcpuCommSlot::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        // Disjoint 64 KiB stacks for `0..num_cpu` vCPUs plus 1 `bridge_rx` worker.
        let num_worker_slots = num_cpus_alloc + 1;
        let stack_units = num_worker_slots * (WORKER_STACK_SIZE / size_of::<StackAlign16>());
        let worker_stacks = vec![StackAlign16([0u8; 16]); stack_units].into_boxed_slice();

        let board = Board {
            hv,
            bridge,
            memory,
            comm_pages,
            worker_stacks,
            arch,
            config,
            state: AtomicU8::new(STATE_CREATED),
            payload: RwLock::new(None),
            ioapic,
            io_devs: RwLock::new(Vec::new()),
            com1: RwLock::new(None),
            pci_bus: PciBus::new(),
            pci_devs: RwLock::new(Vec::new()),
        };

        Ok(Machine {
            board: Arc::new(board),
        })
    }

    pub fn add_com1(&self) -> Result<(), Error> {
        let com1 = Arc::new(Serial::new(
            0x3f8,
            4,
            self.board.hv.clone(),
            self.board.ioapic.clone(),
            self.board.bridge.clone(),
        ));
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

    pub fn add_virtio_spec(
        &mut self,
        spec: VirtioDeviceSpec,
    ) -> Result<Arc<VirtioPciDevice>, Error> {
        let dev = Arc::new(VirtioPciDevice::from_spec(
            spec,
            self.board.hv.clone(),
            self.board.bridge.clone(),
        )?);
        let pci_dev = PciDevice::new(dev.name.clone(), dev.clone());
        self.add_pci_dev(pci_dev)?;
        Ok(dev)
    }

    pub fn add_payload(&mut self, payload: Payload) {
        *self.board.payload.write() = Some(payload)
    }

    pub fn init_vm(&self) -> Result<(), Error> {
        self.board.init_vm()?;
        Ok(())
    }
}
