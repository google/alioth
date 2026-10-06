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

use parking_lot::RwLock;
use thiserror::Error;
use zerocopy::AsBytes;

use crate::host::{self, PollEvent, Vcpu, Vm, VmEntry, VmEvent, VmExit};
use crate::loader::{self, ExecType, InitState, Payload, linux, xen};
use crate::mem::mmio::Mmio;
use crate::mem::{self, AddrOpt, MemRegion, MemRegionType, Memory};
use crate::virtio;
use crate::virtio::dev::VirtioEventHandler;

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
use serial::Serial;

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

    #[error("virtio: {0}")]
    Virtio(#[from] virtio::Error),

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

pub struct Board {
    pub vm: Box<dyn Vm>,
    pub memory: Memory,
    pub vcpus: RwLock<Vec<Box<dyn Vcpu>>>,
    pub arch: ArchBoard,
    pub config: BoardConfig,
    pub state: AtomicU8,
    pub payload: RwLock<Option<Payload>>,
    pub io_devs: RwLock<Vec<(u16, Arc<dyn Mmio>)>>,
    pub com1: RwLock<Option<Arc<Serial>>>,
    pub virtio_devs: RwLock<Vec<Arc<dyn VirtioEventHandler>>>,
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

    fn setup_system(&self, vcpus: &mut [Box<dyn Vcpu>]) -> Result<()> {
        self.create_ram()?;
        for (port, dev) in self.io_devs.read().iter() {
            self.memory.add_io_dev(Some(*port), dev.clone())?;
        }
        self.add_pci_devs()?;
        let init_state = self.load_payload()?;
        if let Some(vcpu0) = vcpus.first_mut() {
            self.init_boot_vcpu(vcpu0.as_mut(), &init_state)?;
        }
        self.create_firmware_data(&init_state)?;
        Ok(())
    }

    pub fn boot(&self) -> Result<()> {
        let mut vcpus = self.vcpus.write();
        for id in 0..self.config.num_cpu {
            let mut vcpu = self.vm.create_vcpu(id)?;
            self.init_vcpu(id, vcpu.as_mut())?;
            vcpus.push(vcpu);
        }
        self.setup_system(&mut vcpus)?;
        self.state.store(STATE_RUNNING, Ordering::Release);
        for id in 0..self.config.num_cpu {
            self.vm.resume_vcpu(id, VmEntry::None)?;
        }
        Ok(())
    }

    fn initiate_stop(
        &self,
        trigger_id: u32,
        new_state: u8,
        vcpu_active: &[bool],
    ) -> Result<()> {
        if self
            .state
            .compare_exchange(
                STATE_RUNNING,
                new_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            for (vcpu_id, &active) in vcpu_active.iter().enumerate() {
                if trigger_id != vcpu_id as u32 && active {
                    log::info!("vcpu{trigger_id} to kill {vcpu_id}");
                    self.vm.stop_vcpu(vcpu_id as u32)?;
                }
            }
        }
        Ok(())
    }

    fn handle_poll_event(&self, event: &PollEvent) -> Result<()> {
        let devs = self.virtio_devs.read();
        for dev in devs.iter() {
            if dev.token() == event.token() {
                dev.handle_poll_event(event)?;
            }
        }
        Ok(())
    }

    pub fn run_event_loop(&self) -> Result<()> {
        let num_cpu = self.config.num_cpu as usize;
        let mut vcpu_active = vec![true; num_cpu];
        let mut fatal_err: Option<Error> = None;

        while vcpu_active.iter().any(|&a| a) {
            let event = self.vm.next_event()?;
            match event {
                VmEvent::SerialInput => {
                    if let Some(com1) = self.com1.read().as_ref() {
                        com1.handle_input()?;
                    }
                }
                VmEvent::Poll(poll_event) => {
                    self.handle_poll_event(&poll_event)?;
                }
                VmEvent::VcpuExit { id, exit } => {
                    let state = self.state.load(Ordering::Acquire);
                    if state != STATE_RUNNING {
                        vcpu_active[id as usize] = false;
                    } else {
                        let step: Result<Option<VmEntry>> = match exit {
                            VmExit::Io { port, write, size } => {
                                Ok(Some(self.memory.handle_io(port, write, size)?))
                            }
                            VmExit::Mmio { addr, write, size } => {
                                Ok(Some(self.memory.handle_mmio(addr, write, size)?))
                            }
                            VmExit::Shutdown => {
                                log::info!("vcpu {id} requested shutdown");
                                Ok(Some(VmEntry::Shutdown))
                            }
                            VmExit::Reboot => Ok(Some(VmEntry::Reboot)),
                            VmExit::Interrupted => Ok(Some(VmEntry::None)),
                            VmExit::Unknown(msg) => Err(Error::VmExit(msg)),
                        };

                        match step {
                            Ok(Some(VmEntry::Shutdown)) => {
                                vcpu_active[id as usize] = false;
                                self.initiate_stop(id, STATE_SHUTDOWN, &vcpu_active)?;
                            }
                            Ok(Some(VmEntry::Reboot)) => {
                                vcpu_active[id as usize] = false;
                                self.initiate_stop(id, STATE_REBOOT_PENDING, &vcpu_active)?;
                            }
                            Ok(Some(entry)) => {
                                self.vm.resume_vcpu(id, entry)?;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                vcpu_active[id as usize] = false;
                                fatal_err = Some(e);
                                self.initiate_stop(id, STATE_SHUTDOWN, &vcpu_active)?;
                            }
                        }
                    }

                    if vcpu_active.iter().all(|&a| !a) {
                        let final_state = self.state.load(Ordering::Acquire);
                        if final_state == STATE_REBOOT_PENDING && fatal_err.is_none() {
                            self.memory.reset()?;
                            let mut vcpus = self.vcpus.write();
                            self.setup_system(&mut vcpus)?;
                            drop(vcpus);
                            self.state.store(STATE_RUNNING, Ordering::Release);
                            for vcpu_id in 0..self.config.num_cpu {
                                vcpu_active[vcpu_id as usize] = true;
                                self.vm.resume_vcpu(vcpu_id, VmEntry::None)?;
                            }
                        } else {
                            self.state.store(STATE_SHUTDOWN, Ordering::Release);
                            for vcpu_id in 0..self.config.num_cpu {
                                let _ = self.vm.resume_vcpu(vcpu_id, VmEntry::Shutdown);
                            }
                            break;
                        }
                    }
                }
            }
        }

        if let Some(err) = fatal_err {
            Err(err)
        } else {
            Ok(())
        }
    }
}
