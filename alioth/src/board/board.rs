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

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use libc::{MAP_PRIVATE, MAP_SHARED};
use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use snafu::{ResultExt, Snafu};

#[cfg(target_arch = "x86_64")]
use crate::arch::layout::PORT_PCI_ADDRESS;
use crate::arch::layout::{
    MEM_64_START, PCIE_CONFIG_START, PCIE_MMIO_32_NON_PREFETCHABLE_END,
    PCIE_MMIO_32_NON_PREFETCHABLE_START, PCIE_MMIO_32_PREFETCHABLE_END,
    PCIE_MMIO_32_PREFETCHABLE_START, RAM_32_SIZE,
};
#[cfg(target_arch = "x86_64")]
use crate::device::fw_cfg::FwCfg;
use crate::errors::{trace_error, DebugTrace};
use crate::hv::{Coco, Vcpu, Vm, VmEntry, VmExit};
#[cfg(target_arch = "x86_64")]
use crate::loader::xen;
use crate::loader::{firmware, linux, ExecType, InitState, Payload};
use crate::mem::emulated::Mmio;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{MemBackend, MemConfig, MemRegion, MemRegionType, Memory};
use crate::pci::bus::PciBus;
use crate::pci::Bdf;
#[cfg(target_os = "linux")]
use crate::vfio::container::Container;
#[cfg(target_os = "linux")]
use crate::vfio::iommu::Ioas;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::ArchBoard;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::ArchBoard;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Failed to access guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("Failed to load payload"), context(false))]
    Loader { source: Box<crate::loader::Error> },
    #[snafu(display("Failed to create VCPU-{id}"))]
    CreateVcpu {
        id: u32,
        source: Box<crate::hv::Error>,
    },
    #[snafu(display("Failed to run VCPU-{id}"))]
    RunVcpu {
        id: u32,
        source: Box<crate::hv::Error>,
    },
    #[snafu(display("Failed to stop VCPU-{id}"))]
    StopVcpu {
        id: u32,
        source: Box<crate::hv::Error>,
    },
    #[snafu(display("Failed to reset PCI {bdf}"))]
    ResetPci {
        bdf: Bdf,
        source: Box<crate::pci::Error>,
    },
    #[snafu(display("Cannot handle vmexit: {msg}"))]
    VmExit { msg: String },
    #[snafu(display("Failed to configure firmware"))]
    Firmware { error: std::io::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub const STATE_CREATED: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_SHUTDOWN: u8 = 2;
pub const STATE_REBOOT_PENDING: u8 = 3;

pub const PCIE_MMIO_64_SIZE: u64 = 1 << 40;

pub struct BoardConfig {
    pub mem: MemConfig,
    pub num_cpu: u32,
    pub coco: Option<Coco>,
}

impl BoardConfig {
    pub fn pcie_mmio_64_start(&self) -> u64 {
        (self.mem.size.saturating_sub(RAM_32_SIZE) + MEM_64_START).next_power_of_two()
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
    pub mmio_devs: RwLock<Vec<(u64, Arc<MemRegion>)>>,
    pub pci_bus: PciBus,
    #[cfg(target_arch = "x86_64")]
    pub fw_cfg: Mutex<Option<Arc<Mutex<FwCfg>>>>,
    #[cfg(target_os = "linux")]
    pub vfio_ioases: Mutex<HashMap<Box<str>, Arc<Ioas>>>,
    #[cfg(target_os = "linux")]
    pub vfio_containers: Mutex<HashMap<Box<str>, Arc<Container>>>,
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
            .add_io_dev(PORT_PCI_ADDRESS, self.pci_bus.io_bus.clone())?;
        self.memory.add_region(
            PCIE_CONFIG_START,
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
            let vm_exit = vcpu.run(vm_entry).context(error::RunVcpu { id })?;
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
                    self.memory.mark_private_memory(gpa, size, private)?;
                    VmEntry::None
                }
                VmExit::Unknown(msg) => break error::VmExit { msg }.fail(),
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
        let mut vcpu = self.vm.create_vcpu(id).context(error::CreateVcpu { id })?;
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
                    self.memory.add_io_dev(*port, dev.clone())?;
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
                            V::stop_vcpu(vcpu_id as u32, handle).context(error::StopVcpu { id })?;
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
                for (bdf, dev) in devices.iter() {
                    dev.dev.reset().context(error::ResetPci { bdf: *bdf })?;
                    dev.dev.config().reset();
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

    fn create_ram_pages(
        &self,
        size: u64,
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] name: &CStr,
    ) -> Result<ArcMemPages> {
        let mmap_flag = if self.config.mem.shared {
            Some(MAP_SHARED)
        } else {
            Some(MAP_PRIVATE)
        };
        let pages = match self.config.mem.backend {
            #[cfg(target_os = "linux")]
            MemBackend::Memfd => ArcMemPages::from_memfd(name, size as usize, None),
            MemBackend::Anonymous => ArcMemPages::from_anonymous(size as usize, None, mmap_flag),
        }?;
        #[cfg(target_os = "linux")]
        if self.config.mem.transparent_hugepage {
            pages.madvise_hugepage()?;
        }
        Ok(pages)
    }
}
