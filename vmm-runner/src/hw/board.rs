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

use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use thiserror::Error;
use zerocopy::AsBytes;

use crate::host::{self, Vcpu, Vm, VmEntry, VmExit};
use crate::loader::{self, ExecType, InitState, Payload, linux, xen};
use crate::mem::mmio::Mmio;
use crate::mem::{self, AddrOpt, MemRegion, MemRegionType, Memory};

#[path = "firmware/firmware.rs"]
pub mod firmware;
pub mod hw_x86_64;
pub use hw_x86_64::*;
#[path = "pci/pci.rs"]
pub mod pci;
pub mod serial;

use firmware::acpi::bindings::AcpiTableRsdp;
use firmware::acpi::create_acpi;
use layout::{EBDA_START, PCIE_CONFIG_START};
use pci::bus::{CONFIG_ADDRESS, PciBus};
use pci::config::Command;
use pci::{PciBar, PciDevice};

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] host::Error),

    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("PCI bus: {0}")]
    PciBus(#[from] pci::Error),

    #[error("loader: {0}")]
    Loader(#[from] loader::Error),

    #[error("cannot handle {0:#x?}")]
    VmExit(String),

    #[error("host io: {0}")]
    HostIo(#[from] std::io::Error),

    #[error("ACPI bytes exceed EBDA area")]
    AcpiTooLong,

    #[error("memory too small")]
    MemoryTooSmall,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub const STATE_CREATED: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_SHUTDOWN: u8 = 2;
pub const STATE_REBOOT_PENDING: u8 = 3;

pub struct BoardConfig {
    pub mem_size: usize,
    pub num_cpu: u32,
}

type VcpuGuard<'a> = RwLockReadGuard<'a, Vec<(JoinHandle<Result<()>>, Sender<()>)>>;

pub struct Board {
    pub vm: Box<dyn Vm>,
    pub memory: Memory,
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
}

impl Board {
    pub fn create_firmware_data(&self, _init_state: &InitState) -> Result<()> {
        let ram = self.memory.ram_bus();
        let mut acpi_table = create_acpi(self.config.num_cpu);
        acpi_table.relocate((EBDA_START + size_of::<AcpiTableRsdp>()) as u64);
        ram.write_range(
            EBDA_START as u64,
            size_of::<AcpiTableRsdp>(),
            acpi_table.rsdp().as_bytes(),
        )?;
        ram.write_range(
            (EBDA_START + size_of::<AcpiTableRsdp>()) as u64,
            acpi_table.tables().len(),
            acpi_table.tables(),
        )?;
        Ok(())
    }

    fn load_payload(&self) -> Result<InitState, Error> {
        let payload = self.payload.read();
        let Some(payload) = payload.as_ref() else {
            return Ok(InitState::default());
        };
        let mem_regions = self.memory.mem_region_entries();
        let init_state = match payload.exec_type {
            ExecType::Linux => linux::load(
                &self.memory.ram_bus(),
                &mem_regions,
                &payload.executable,
                payload.cmd_line.as_deref(),
                payload.initramfs.as_ref(),
            )?,
            ExecType::Pvh => xen::load(
                &self.memory.ram_bus(),
                &mem_regions,
                &payload.executable,
                payload.cmd_line.as_deref(),
                payload.initramfs.as_ref(),
            )?,
        };
        Ok(init_state)
    }

    fn add_pci_devs(&self) -> Result<()> {
        self.memory
            .add_io_dev(Some(CONFIG_ADDRESS), self.pci_bus.io_bus.clone())?;
        self.memory.add_region(
            AddrOpt::Fixed(PCIE_CONFIG_START as u64),
            Arc::new(MemRegion::with_emulated(
                self.pci_bus.segment.clone(),
                MemRegionType::Reserved,
            )),
        )?;
        for dev in self.pci_devs.read().iter() {
            let config = dev.dev.config();
            let header = config.get_header();
            for (index, bar) in header.bars.iter().enumerate() {
                match bar {
                    PciBar::Empty => {}
                    PciBar::Mem32(region) => {
                        let addr = self.memory.add_region(AddrOpt::Below4G, region.clone())?;
                        log::info!("{}: BAR {index} located at {addr:#x}", dev.name);
                    }
                    PciBar::Mem64(region) => {
                        let addr = self.memory.add_region(AddrOpt::Above4G, region.clone())?;
                        log::info!("{}: BAR {index} located at {addr:#x}", dev.name);
                    }
                    PciBar::Io(region) => {
                        let addr = self.memory.add_io_region(None, region.clone())?;
                        log::info!("{}: IO BAR {index} located at {addr:#x}", dev.name);
                    }
                }
            }
            header.set_command(Command::MEM | Command::IO);
        }
        Ok(())
    }

    fn vcpu_loop(&self, vcpu: &mut dyn Vcpu, id: u32) -> Result<bool, Error> {
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
        self.init_vcpu(id, vcpu.as_mut())?;
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
                let init_state = self.load_payload()?;
                self.init_boot_vcpu(vcpu.as_mut(), &init_state)?;
                self.create_firmware_data(&init_state)?;
            }
            drop(vcpus);

            let reboot = self.vcpu_loop(vcpu.as_mut(), id)?;

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
                    for (vcpu_id, _) in vcpus.iter().enumerate() {
                        if id != vcpu_id as u32 {
                            log::info!("vcpu{id} to kill {vcpu_id}");
                            self.vm.stop_vcpu(vcpu_id as u32)?;
                        }
                    }
                }
                Err(s) if s == new_state => {}
                Ok(s) | Err(s) => {
                    log::error!("unexpected state: {s}");
                }
            }

            self.sync_vcpus(&vcpus);

            if new_state == STATE_SHUTDOWN {
                break Ok(());
            }

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
        event_tx.send(id).unwrap();
        ret
    }
}
