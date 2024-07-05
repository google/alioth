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

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use thiserror::Error;

use crate::arch::layout::{
    MEM_64_START, PCIE_CONFIG_START, PCIE_MMIO_32_NON_PREFETCHABLE_END,
    PCIE_MMIO_32_NON_PREFETCHABLE_START, PCIE_MMIO_32_PREFETCHABLE_END,
    PCIE_MMIO_32_PREFETCHABLE_START, RAM_32_SIZE,
};
use crate::device::fw_cfg::FwCfg;
use crate::hv::{self, Coco, Vcpu, Vm, VmEntry, VmExit};
#[cfg(target_arch = "x86_64")]
use crate::loader::xen;
use crate::loader::{self, firmware, linux, ExecType, InitState, Payload};
use crate::mem::emulated::Mmio;
use crate::mem::{self, AddrOpt, MemRegion, MemRegionType, Memory};
use crate::pci;
use crate::pci::bus::PciBus;
#[cfg(target_arch = "x86_64")]
use crate::pci::bus::CONFIG_ADDRESS;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::ArchBoard;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::ArchBoard;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] hv::Error),

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

type Result<T, E = Error> = std::result::Result<T, E>;

pub const STATE_CREATED: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_SHUTDOWN: u8 = 2;
pub const STATE_REBOOT_PENDING: u8 = 3;

pub const PCIE_MMIO_64_SIZE: u64 = 1 << 40;

pub struct BoardConfig {
    pub mem_size: u64,
    pub num_cpu: u32,
    pub coco: Option<Coco>,
}

impl BoardConfig {
    pub fn pcie_mmio_64_start(&self) -> u64 {
        (self.mem_size.saturating_sub(RAM_32_SIZE) + MEM_64_START).next_power_of_two()
    }
}

type VcpuGuard<'a> = RwLockReadGuard<'a, Vec<(JoinHandle<Result<()>>, Sender<()>)>>;
type VcpuHandle = (JoinHandle<Result<()>>, Sender<()>);

pub struct Board<V>
where
    V: Vm,
{
    pub vm: V,
    pub memory: Memory,
    pub vcpus: Arc<RwLock<Vec<VcpuHandle>>>,
    pub arch: ArchBoard<V>,
    pub config: BoardConfig,
    pub state: AtomicU8,
    pub payload: RwLock<Option<Payload>>,
    pub mp_sync: Arc<(Mutex<u32>, Condvar)>,
    pub io_devs: RwLock<Vec<(u16, Arc<dyn Mmio>)>>,
    #[cfg(target_arch = "aarch64")]
    pub mmio_devs: RwLock<Vec<(AddrOpt, Arc<MemRegion>)>>,
    pub pci_bus: PciBus,
    pub fw_cfg: Mutex<Option<Arc<Mutex<FwCfg>>>>,
}

impl<V> Board<V>
where
    V: Vm,
{
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
            #[cfg(target_arch = "x86_64")]
            ExecType::Pvh => xen::load(
                &self.memory.ram_bus(),
                &mem_regions,
                &payload.executable,
                payload.cmd_line.as_deref(),
                payload.initramfs.as_ref(),
            )?,
            ExecType::Firmware => {
                let (init_state, mut rom) = firmware::load(&self.memory, &payload.executable)?;
                self.setup_firmware(&mut rom)?;
                init_state
            }
        };
        Ok(init_state)
    }

    fn add_pci_devs(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        self.memory
            .add_io_dev(Some(CONFIG_ADDRESS), self.pci_bus.io_bus.clone())?;
        self.memory.add_region(
            AddrOpt::Fixed(PCIE_CONFIG_START),
            Arc::new(MemRegion::with_emulated(
                self.pci_bus.segment.clone(),
                MemRegionType::Reserved,
            )),
        )?;
        let pcie_mmio_64_start = self.config.pcie_mmio_64_start();
        self.pci_bus.assign_resources(&[
            (0x1000, 0x10000),
            (
                PCIE_MMIO_32_NON_PREFETCHABLE_START,
                PCIE_MMIO_32_NON_PREFETCHABLE_END,
            ),
            (
                PCIE_MMIO_32_PREFETCHABLE_START,
                PCIE_MMIO_32_PREFETCHABLE_END,
            ),
            (pcie_mmio_64_start, pcie_mmio_64_start + PCIE_MMIO_64_SIZE),
        ]);
        Ok(())
    }

    fn vcpu_loop(&self, vcpu: &mut <V as Vm>::Vcpu, id: u32) -> Result<bool, Error> {
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
                VmExit::ConvertMemory { gpa, size, private } => {
                    self.memory
                        .ram_bus()
                        .mark_private_memory(gpa, size, private)?;
                    VmEntry::None
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
            self.coco_init(id)?;
            if id == 0 {
                self.create_ram()?;
                for (port, dev) in self.io_devs.read().iter() {
                    self.memory.add_io_dev(Some(*port), dev.clone())?;
                }
                #[cfg(target_arch = "aarch64")]
                for (addr, dev) in self.mmio_devs.read().iter() {
                    self.memory.add_region(*addr, dev.clone())?;
                }
                self.add_pci_devs()?;
                let init_state = self.load_payload()?;
                self.init_boot_vcpu(&mut vcpu, &init_state)?;
                self.create_firmware_data(&init_state)?;
            }
            self.init_ap(id, &mut vcpu, &vcpus)?;
            self.coco_finalize(id, &vcpus)?;
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
                            V::stop_vcpu(vcpu_id as u32, handle)?;
                        }
                    }
                }
                Err(s) if s == new_state => {}
                Ok(s) | Err(s) => {
                    log::error!("unexpected state: {s}");
                }
            }

            self.sync_vcpus(&vcpus);

            if id == 0 {
                let devices = self.pci_bus.segment.devices.read();
                for (_, dev) in devices.iter() {
                    dev.dev.reset()?;
                }
                self.memory.reset()?;
            }

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

            self.reset_vcpu(id, &mut vcpu)?;
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
