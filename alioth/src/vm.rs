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

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use parking_lot::{Condvar, Mutex, RwLock};
use snafu::{ResultExt, Snafu};

#[cfg(target_arch = "aarch64")]
use crate::arch::layout::PL011_START;
#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{PORT_COM1, PORT_FW_CFG_SELECTOR};
use crate::board::{ArchBoard, Board, BoardConfig, STATE_CREATED, STATE_RUNNING};
#[cfg(target_arch = "x86_64")]
use crate::device::fw_cfg::{FwCfg, FwCfgItemParam};
#[cfg(target_arch = "aarch64")]
use crate::device::pl011::Pl011;
use crate::device::pvpanic::PvPanic;
#[cfg(target_arch = "x86_64")]
use crate::device::serial::Serial;
use crate::errors::{trace_error, DebugTrace};
use crate::hv::{Hypervisor, IoeventFdRegistry, Vm, VmConfig};
use crate::loader::Payload;
use crate::mem::Memory;
#[cfg(target_arch = "aarch64")]
use crate::mem::{MemRegion, MemRegionType};
use crate::pci::bus::PciBus;
use crate::pci::{Bdf, PciDevice};
use crate::virtio::dev::{DevParam, Virtio, VirtioDevice};
use crate::virtio::pci::VirtioPciDevice;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Failed to create board"), context(false))]
    CreateBoard { source: Box<crate::board::Error> },
    #[snafu(display("Failed to create VCPU-{id} thread"))]
    VcpuThread { id: u32, error: std::io::Error },
    #[snafu(display("Failed to create a console"))]
    CreateConsole { error: std::io::Error },
    #[snafu(display("Failed to create fw-cfg device"))]
    FwCfg { error: std::io::Error },
    #[snafu(display("Failed to create a VirtIO device"), context(false))]
    CreateVirtio { source: Box<crate::virtio::Error> },
    #[snafu(display("Guest memory is not backed by sharable file descriptors"))]
    MemNotSharedFd,
    #[snafu(display("VCPU-{id} error"))]
    VcpuError {
        id: u32,
        source: Box<crate::board::Error>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Machine<H>
where
    H: Hypervisor,
{
    board: Arc<Board<H::Vm>>,
    event_rx: Receiver<u32>,
    _event_tx: Sender<u32>,
}

pub type VirtioPciDev<D, H> = VirtioPciDevice<
    D,
    <<H as Hypervisor>::Vm as Vm>::MsiSender,
    <<<H as Hypervisor>::Vm as Vm>::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd,
>;

impl<H> Machine<H>
where
    H: Hypervisor + 'static,
{
    pub fn new(hv: H, config: BoardConfig) -> Result<Self> {
        let vm_config = VmConfig {
            coco: config.coco.clone(),
        };
        let mut vm = hv.create_vm(&vm_config)?;
        let vm_memory = vm.create_vm_memory()?;
        let memory = Memory::new(vm_memory);
        let arch = ArchBoard::new(&hv, &vm, &config)?;

        let board = Arc::new(Board {
            vm,
            memory,
            arch,
            config,
            state: AtomicU8::new(STATE_CREATED),
            payload: RwLock::new(None),
            vcpus: Arc::new(RwLock::new(Vec::new())),
            mp_sync: Arc::new((Mutex::new(0), Condvar::new())),
            io_devs: RwLock::new(Vec::new()),
            #[cfg(target_arch = "aarch64")]
            mmio_devs: RwLock::new(Vec::new()),
            pci_bus: PciBus::new(),
            #[cfg(target_arch = "x86_64")]
            fw_cfg: Mutex::new(None),
            #[cfg(target_os = "linux")]
            default_ioas: RwLock::new(None),
        });

        let (event_tx, event_rx) = mpsc::channel();

        let mut vcpus = board.vcpus.write();
        for vcpu_id in 0..board.config.num_cpu {
            let (boot_tx, boot_rx) = mpsc::channel();
            let event_tx = event_tx.clone();
            let board = board.clone();
            let handle = thread::Builder::new()
                .name(format!("vcpu_{}", vcpu_id))
                .spawn(move || board.run_vcpu(vcpu_id, event_tx, boot_rx))
                .context(error::VcpuThread { id: vcpu_id })?;
            event_rx.recv().unwrap();
            vcpus.push((handle, boot_tx));
        }
        drop(vcpus);

        board.arch_init()?;

        let machine = Machine {
            board,
            event_rx,
            _event_tx: event_tx,
        };

        Ok(machine)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_com1(&self) -> Result<(), Error> {
        let irq_sender = self.board.vm.create_irq_sender(4)?;
        let com1 = Serial::new(PORT_COM1, irq_sender).context(error::CreateConsole)?;
        self.board.io_devs.write().push((PORT_COM1, Arc::new(com1)));
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn add_pl011(&self) -> Result<(), Error> {
        let irq_line = self.board.vm.create_irq_sender(1)?;
        let pl011_dev = Pl011::new(PL011_START, irq_line).context(error::CreateConsole)?;
        self.board.mmio_devs.write().push((
            PL011_START,
            Arc::new(MemRegion::with_emulated(
                Arc::new(pl011_dev),
                MemRegionType::Hidden,
            )),
        ));
        Ok(())
    }

    pub fn add_pci_dev(&mut self, bdf: Option<Bdf>, dev: PciDevice) -> Result<(), Error> {
        let name = dev.name.clone();
        let bdf = if let Some(bdf) = bdf {
            bdf
        } else {
            self.board.pci_bus.reserve(None, name.clone()).unwrap()
        };
        let config = dev.dev.config();
        self.board.pci_bus.add(bdf, dev);
        let header = config.get_header();
        header.set_bdf(bdf);
        log::info!("{bdf}: device: {name}");
        Ok(())
    }

    pub fn add_pvpanic(&mut self) -> Result<(), Error> {
        let dev = PvPanic::new();
        let pci_dev = PciDevice::new("pvpanic".to_owned().into(), Arc::new(dev));
        self.add_pci_dev(None, pci_dev)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_fw_cfg(
        &mut self,
        params: impl Iterator<Item = FwCfgItemParam>,
    ) -> Result<Arc<Mutex<FwCfg>>, Error> {
        let items = params
            .map(|p| p.build())
            .collect::<Result<Vec<_>, _>>()
            .context(error::FwCfg)?;
        let fw_cfg = Arc::new(Mutex::new(
            FwCfg::new(self.board.memory.ram_bus(), items).context(error::FwCfg)?,
        ));
        let mut io_devs = self.board.io_devs.write();
        io_devs.push((PORT_FW_CFG_SELECTOR, fw_cfg.clone()));
        *self.board.fw_cfg.lock() = Some(fw_cfg.clone());
        Ok(fw_cfg)
    }

    pub fn add_virtio_dev<D, P>(
        &mut self,
        name: String,
        param: P,
    ) -> Result<Arc<VirtioPciDev<D, H>>, Error>
    where
        P: DevParam<Device = D>,
        D: Virtio,
    {
        if param.needs_mem_shared_fd() && !self.board.config.mem.has_shared_fd() {
            return error::MemNotSharedFd.fail();
        }
        let name = Arc::new(name);
        let bdf = self.board.pci_bus.reserve(None, name.clone()).unwrap();
        let dev = param.build(name.clone())?;
        let registry = self.board.vm.create_ioeventfd_registry()?;
        let virtio_dev = VirtioDevice::new(
            name.clone(),
            dev,
            self.board.memory.ram_bus(),
            &registry,
            self.board.config.coco.is_some(),
        )?;
        let msi_sender = self.board.vm.create_msi_sender(
            #[cfg(target_arch = "aarch64")]
            u32::from(bdf.0),
        )?;
        let dev = VirtioPciDevice::new(virtio_dev, msi_sender, registry)?;
        let dev = Arc::new(dev);
        let pci_dev = PciDevice::new(name.clone(), dev.clone());
        self.add_pci_dev(Some(bdf), pci_dev)?;
        Ok(dev)
    }

    pub fn add_payload(&mut self, payload: Payload) {
        *self.board.payload.write() = Some(payload)
    }

    pub fn boot(&mut self) -> Result<(), Error> {
        let vcpus = self.board.vcpus.read();
        self.board.state.store(STATE_RUNNING, Ordering::Release);
        for (_, boot_tx) in vcpus.iter() {
            boot_tx.send(()).unwrap();
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Vec<Result<()>> {
        self.event_rx.recv().unwrap();
        let vcpus = self.board.vcpus.read();
        for _ in 1..vcpus.len() {
            self.event_rx.recv().unwrap();
        }
        drop(vcpus);
        let mut vcpus = self.board.vcpus.write();
        vcpus
            .drain(..)
            .enumerate()
            .map(|(id, (handle, _))| match handle.join() {
                Err(e) => {
                    log::error!("cannot join vcpu {}: {:?}", id, e);
                    Ok(())
                }
                Ok(r) => r.context(error::Vcpu { id: id as u32 }),
            })
            .collect()
    }
}
