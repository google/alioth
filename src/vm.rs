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
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use thiserror::Error;
use zerocopy::AsBytes;

use crate::arch::layout::{EBDA_START, PCIE_CONFIG_START};
use crate::board::ArchBoard;
use crate::board::serial::Serial;
use crate::firmware::acpi::bindings::AcpiTableRsdp;
use crate::firmware::acpi::create_acpi;
use crate::hv::{self, Kvm, Vcpu, Vm, VmEntry, VmExit};
use crate::loader::{self, InitState, Payload, xen};
use crate::mem::mmio::Mmio;
use crate::mem::{self, AddrOpt, MemRegion, MemRegionType, Memory};
use crate::pci::bus::{CONFIG_ADDRESS, PciBus};
use crate::pci::config::Command;
use crate::pci::{self, PciBar, PciDevice};
use crate::virtio;
use crate::virtio::dev::{DevParam, Virtio, VirtioDevice};
use crate::virtio::pci::VirtioPciDevice;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] hv::Error),

    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("host io: {0}")]
    HostIo(#[from] std::io::Error),

    #[error("loader: {0}")]
    Loader(#[from] loader::Error),

    #[error("PCI bus: {0}")]
    PciBus(#[from] pci::Error),

    #[error("virtio: {0}")]
    Virtio(#[from] virtio::Error),

    #[error("config: {0}")]
    Config(#[from] crate::config::Error),

    #[error("failed to create log file {path:?}: {source}")]
    LogFileCreate {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot handle {0:#x?}")]
    VmExit(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub const STATE_CREATED: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_SHUTDOWN: u8 = 2;
pub const STATE_REBOOT_PENDING: u8 = 3;

#[derive(Debug, Clone, Copy)]
pub struct BoardConfig {
    pub mem_size: usize,
    pub num_cpu: u32,
}

type VcpuGuard<'a> = RwLockReadGuard<'a, Vec<(JoinHandle<Result<()>>, Sender<()>)>>;

pub struct Machine {
    // VM State (formerly Board)
    pub vm: Vm,
    pub memory: Arc<Memory>,
    #[allow(clippy::type_complexity)]
    pub vcpus: Arc<RwLock<Vec<(JoinHandle<Result<()>>, Sender<()>)>>>,
    pub arch: ArchBoard,
    pub config: BoardConfig,
    pub state: AtomicU8,
    pub payload: RwLock<Option<Payload>>,
    pub mp_sync: Arc<(Mutex<u32>, Condvar)>,
    pub io_devs: RwLock<Vec<(u16, Arc<dyn Mmio>)>>,
    pub pci_bus: PciBus,
    pub pci_devs: RwLock<Vec<PciDevice>>,

    // Thread Management (formerly Machine)
    event_rx: Mutex<Receiver<u32>>,
    event_tx: Sender<u32>,
}

impl Machine {
    pub fn new(hv: Kvm, config: BoardConfig) -> Result<Self, Error> {
        let mut vm = hv.create_vm()?;
        let vm_memory = vm.create_vm_memory()?;
        let memory = Arc::new(Memory::new(vm_memory));
        let arch = ArchBoard::new(&hv)?;

        let (event_tx, event_rx) = mpsc::channel();

        let machine = Machine {
            vm,
            memory,
            arch,
            config,
            state: AtomicU8::new(STATE_CREATED),
            payload: RwLock::new(None),
            vcpus: Arc::new(RwLock::new(Vec::new())),
            mp_sync: Arc::new((Mutex::new(0), Condvar::new())),
            io_devs: RwLock::new(Vec::new()),
            pci_bus: PciBus::new(),
            pci_devs: RwLock::new(Vec::new()),
            event_rx: Mutex::new(event_rx),
            event_tx,
        };
        Ok(machine)
    }

    pub fn add_com1(&self) -> Result<(), Error> {
        let com1_intx_sender = self.vm.create_intx_sender(4)?;
        let com1 = Serial::new(0x3f8, com1_intx_sender)?;
        self.io_devs.write().push((0x3f8, Arc::new(com1)));
        Ok(())
    }

    pub fn add_pci_dev(&self, dev: PciDevice) -> Result<(), Error> {
        let config = dev.dev.config();
        let bdf = self.pci_bus.add(None, config.clone())?;
        let header = config.get_header();
        header.set_bdf(bdf);
        log::info!("{} located at {bdf}", dev.name);
        self.pci_devs.write().push(dev);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn add_virtio_dev<D, P>(
        &self,
        name: String,
        param: P,
    ) -> Result<Arc<VirtioPciDevice<D>>, Error>
    where
        P: DevParam<Device = D>,
        D: Virtio,
    {
        let name = Arc::new(name);
        let dev = param.build(name.clone())?;
        let virtio_dev = VirtioDevice::new(name.clone(), dev, self.memory.clone())?;
        let msi_sender = self.vm.create_msi_sender()?;
        let dev = VirtioPciDevice::new(virtio_dev, msi_sender)?;
        let dev = Arc::new(dev);
        let pci_dev = PciDevice::new(name.clone(), dev.clone());
        self.add_pci_dev(pci_dev)?;
        Ok(dev)
    }

    pub fn add_payload(&self, payload: Payload) {
        *self.payload.write() = Some(payload)
    }

    pub fn boot(self: Arc<Self>) -> Result<(), Error> {
        if let Some(payload) = self.payload.read().as_ref() {
            xen::check_pvh_note(&payload.executable)?;
        }
        let mut vcpus = self.vcpus.write();
        for vcpu_id in 0..self.config.num_cpu {
            let (boot_tx, boot_rx) = mpsc::channel();
            let event_tx = self.event_tx.clone();
            let machine = Arc::clone(&self);
            let handle = thread::Builder::new()
                .name(format!("vcpu_{vcpu_id}"))
                .spawn(move || machine.run_vcpu(vcpu_id, event_tx, boot_rx))?;
            self.event_rx.lock().recv().unwrap();
            vcpus.push((handle, boot_tx));
        }
        self.state.store(STATE_RUNNING, Ordering::Release);
        for (_, boot_tx) in vcpus.iter() {
            boot_tx.send(()).unwrap();
        }
        Ok(())
    }

    pub fn wait(&self) -> Vec<Result<()>> {
        self.event_rx.lock().recv().unwrap();
        let vcpus = self.vcpus.read();
        for _ in 1..vcpus.len() {
            self.event_rx.lock().recv().unwrap();
        }
        drop(vcpus);
        let mut vcpus = self.vcpus.write();
        vcpus
            .drain(..)
            .enumerate()
            .map(|(id, (handle, _))| match handle.join() {
                Err(e) => {
                    log::error!("cannot join vcpu {id}: {e:?}");
                    Ok(())
                }
                Ok(r) => r,
            })
            .collect()
    }

    // Formerly Board methods
    pub fn create_firmware_data(&self, _init_state: &InitState) -> Result<()> {
        let mut acpi_table = create_acpi(self.config.num_cpu);
        acpi_table.relocate((EBDA_START + size_of::<AcpiTableRsdp>()) as u64);
        self.memory.write_range(
            EBDA_START,
            size_of::<AcpiTableRsdp>(),
            acpi_table.rsdp().as_bytes(),
        )?;
        self.memory.write_range(
            EBDA_START + size_of::<AcpiTableRsdp>(),
            acpi_table.tables().len(),
            acpi_table.tables(),
        )?;
        Ok(())
    }

    fn load_payload(&self) -> Result<InitState, Error> {
        let payload = self.payload.read();
        let Some(payload) = payload.as_ref() else {
            log::error!("Missing payload");
            return Err(Error::Config(crate::config::Error::MissingKernel));
        };
        let mem_regions = self.memory.mem_region_entries();
        let init_state = xen::load(
            &self.memory,
            &mem_regions,
            &payload.executable,
            payload.cmd_line.as_deref(),
            payload.initramfs.as_ref(),
        )?;
        Ok(init_state)
    }

    fn add_pci_devs(&self) -> Result<()> {
        self.memory
            .add_io_dev(Some(CONFIG_ADDRESS), self.pci_bus.io_bus.clone())?;
        self.memory.add_region(
            AddrOpt::Fixed(PCIE_CONFIG_START),
            Arc::new(MemRegion::with_emulated(
                self.pci_bus.segment.clone(),
                MemRegionType::Reserved,
            )),
        )?;
        for dev in self.pci_devs.read().iter() {
            let config = dev.dev.config();
            let header = config.get_header();
            for (index, bar) in header.bars.iter().enumerate() {
                if let PciBar::Mem64(region) = bar {
                    let addr = self.memory.add_region(AddrOpt::Above4G, region.clone())?;
                    log::info!("{}: BAR {index} located at {addr:#x}", dev.name);
                }
            }
            header.set_command(Command::MEM | Command::IO);
        }
        Ok(())
    }

    fn vcpu_loop(&self, vcpu: &mut Vcpu, id: u32) -> Result<bool, Error> {
        let mut vm_entry = VmEntry::None;
        loop {
            let vm_exit = vcpu.run(vm_entry)?;
            vm_entry = match vm_exit {
                VmExit::Io { port, write, size } => self.memory.handle_io(port, write, size)?,
                VmExit::Mmio { addr, write, size } => self.memory.handle_mmio(addr, write, size)?,
                VmExit::Shutdown => {
                    log::info!("vcpu {id} requested shutdown");
                    break Ok(false);
                }
                VmExit::Reboot => {
                    break Ok(true);
                }
                VmExit::Interrupted => {
                    let state = self.state.load(Ordering::Acquire);
                    match state {
                        STATE_SHUTDOWN => VmEntry::Shutdown,
                        STATE_REBOOT_PENDING => VmEntry::Reboot,
                        _ => VmEntry::None,
                    }
                }
                VmExit::Unknown(msg) => break Err(Error::VmExit(msg)),
            };
        }
    }

    fn sync_vcpus(&self, vcpus: &VcpuGuard) {
        let (lock, cvar) = &*self.mp_sync;
        let mut count = lock.lock();
        *count += 1;
        if *count == vcpus.len() as u32 {
            *count = 0;
            cvar.notify_all();
        } else {
            cvar.wait(&mut count)
        }
    }

    fn run_vcpu_inner(
        &self,
        id: u32,
        event_tx: &Sender<u32>,
        boot_rx: &Receiver<()>,
    ) -> Result<(), Error> {
        let mut vcpu = self.vm.create_vcpu(id)?;
        event_tx.send(id).unwrap();
        self.init_vcpu(id, &mut vcpu)?;
        boot_rx.recv().unwrap();
        if self.state.load(Ordering::Acquire) != STATE_RUNNING {
            return Ok(());
        }
        loop {
            let vcpus = self.vcpus.read();
            if id == 0 {
                self.create_ram()?;
                for (port, dev) in self.io_devs.read().iter() {
                    self.memory.add_io_dev(Some(*port), dev.clone())?;
                }
                self.add_pci_devs()?;
                log::info!("will load payload");
                let init_state = self.load_payload()?;
                log::info!("did load payload");
                self.init_boot_vcpu(&mut vcpu, &init_state)?;
                self.create_firmware_data(&init_state)?;
            }
            drop(vcpus);

            let reboot = self.vcpu_loop(&mut vcpu, id)?;

            let new_state = if reboot {
                STATE_REBOOT_PENDING
            } else {
                STATE_SHUTDOWN
            };
            let vcpus = self.vcpus.read();
            match self.state.compare_exchange(
                STATE_RUNNING,
                new_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(STATE_RUNNING) => {
                    for (vcpu_id, (handle, _)) in vcpus.iter().enumerate() {
                        if id != vcpu_id as u32 {
                            log::info!("vcpu{id} to kill {vcpu_id}");
                            Vm::stop_vcpu(vcpu_id as u32, handle)?;
                        }
                    }
                }
                Err(s) if s == new_state => {}
                Ok(s) | Err(s) => {
                    log::error!("unexpected state: {s}");
                }
            }

            if new_state == STATE_SHUTDOWN {
                break Ok(());
            }

            self.sync_vcpus(&vcpus);

            match self.state.compare_exchange(
                STATE_REBOOT_PENDING,
                STATE_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(STATE_REBOOT_PENDING) | Err(STATE_RUNNING) => {}
                _ => break Ok(()),
            }

            if id == 0 {
                self.memory.reset()?;
            }
        }
    }

    pub fn run_vcpu(
        &self,
        id: u32,
        event_tx: Sender<u32>,
        boot_rx: Receiver<()>,
    ) -> Result<(), Error> {
        let ret = self.run_vcpu_inner(id, &event_tx, &boot_rx);
        self.state.store(STATE_SHUTDOWN, Ordering::Release);
        if ret.is_err() {
            log::error!("vcpu {id} failed: {ret:?}");
            let vcpus = self.vcpus.read();
            for (vcpu_id, (handle, _)) in vcpus.iter().enumerate() {
                if id != vcpu_id as u32 {
                    let _ = Vm::stop_vcpu(vcpu_id as u32, handle);
                }
            }
        }
        event_tx.send(id).unwrap();
        ret
    }
}
