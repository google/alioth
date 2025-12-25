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
#[path = "board_aarch64.rs"]
mod aarch64;
#[cfg(target_arch = "x86_64")]
#[path = "board_x86_64.rs"]
mod x86_64;

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;

use libc::{MAP_PRIVATE, MAP_SHARED};
use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use serde::Deserialize;
use serde_aco::Help;
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
use crate::errors::{DebugTrace, trace_error};
use crate::hv::{Coco, Vcpu, Vm, VmEntry, VmExit};
#[cfg(target_arch = "x86_64")]
use crate::loader::xen;
use crate::loader::{Executable, InitState, Payload, linux};
use crate::mem::emulated::Mmio;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{MemBackend, MemConfig, MemRegion, MemRegionType, Memory};
use crate::pci::bus::PciBus;
#[cfg(target_os = "linux")]
use crate::vfio::container::Container;
#[cfg(target_os = "linux")]
use crate::vfio::iommu::Ioas;

#[cfg(target_arch = "aarch64")]
pub(crate) use self::aarch64::ArchBoard;
#[cfg(target_arch = "x86_64")]
pub(crate) use self::x86_64::ArchBoard;

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
    #[snafu(display("Invalid CPU topology"))]
    InvalidCpuTopology,
    #[snafu(display("Failed to create VCPU-{index}"))]
    CreateVcpu {
        index: u16,
        source: Box<crate::hv::Error>,
    },
    #[snafu(display("Failed to run VCPU-{index}"))]
    RunVcpu {
        index: u16,
        source: Box<crate::hv::Error>,
    },
    #[snafu(display("Failed to stop VCPU-{index}"))]
    StopVcpu {
        index: u16,
        source: Box<crate::hv::Error>,
    },
    #[snafu(display("Failed to reset PCI devices"))]
    ResetPci { source: Box<crate::pci::Error> },
    #[snafu(display("Failed to configure firmware"))]
    Firmware { error: std::io::Error },
    #[snafu(display("Missing payload"))]
    MissingPayload,
    #[snafu(display("Failed to notify the VMM thread"))]
    NotifyVmm,
    #[snafu(display("Another VCPU thread has signaled failure"))]
    PeerFailure,
    #[snafu(display("Unexpected state: {state:?}, want {want:?}"))]
    UnexpectedState { state: BoardState, want: BoardState },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Help)]
pub struct CpuTopology {
    #[serde(default)]
    /// Enable SMT (Hyperthreading).
    pub smt: bool,
    #[serde(default)]
    /// Number of cores per socket.
    pub cores: u16,
    #[serde(default)]
    /// Number of sockets.
    pub sockets: u8,
}

impl CpuTopology {
    pub fn encode(&self, index: u16) -> (u8, u16, u8) {
        let total_cores = self.cores * self.sockets as u16;
        let thread_id = index / total_cores;
        let core_id = index % total_cores % self.cores;
        let socket_id = index % total_cores / self.cores;
        (thread_id as u8, core_id, socket_id as u8)
    }
}

const fn default_cpu_count() -> u16 {
    1
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Help)]
pub struct CpuConfig {
    /// Number of VCPUs assigned to the guest. [default: 1]
    #[serde(default = "default_cpu_count")]
    pub count: u16,
    /// Architecture specific CPU topology.
    #[serde(default)]
    pub topology: CpuTopology,
}

impl CpuConfig {
    pub fn fixup(&mut self) -> Result<()> {
        if self.topology.sockets == 0 {
            self.topology.sockets = 1;
        }
        let vcpus_per_core = 1 + self.topology.smt as u16;
        if self.topology.cores == 0 {
            self.topology.cores = self.count / self.topology.sockets as u16 / vcpus_per_core;
        }
        let vcpus_per_socket = self.topology.cores * vcpus_per_core;
        let count = self.topology.sockets as u16 * vcpus_per_socket;
        if count != self.count {
            return error::InvalidCpuTopology.fail();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardState {
    Created,
    Running,
    Shutdown,
    RebootPending,
    Fatal,
}

#[derive(Debug)]
struct MpSync {
    state: BoardState,
    count: u16,
}

pub const PCIE_MMIO_64_SIZE: u64 = 1 << 40;

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct BoardConfig {
    pub mem: MemConfig,
    pub cpu: CpuConfig,
    pub coco: Option<Coco>,
}

impl BoardConfig {
    pub fn pcie_mmio_64_start(&self) -> u64 {
        (self.mem.size.saturating_sub(RAM_32_SIZE) + MEM_64_START).next_power_of_two()
    }

    pub fn config_fixup(&mut self) -> Result<()> {
        self.cpu.fixup()
    }
}

type VcpuGuard<'a> = RwLockReadGuard<'a, Vec<VcpuHandle>>;
type VcpuHandle = JoinHandle<Result<()>>;

pub struct Board<V>
where
    V: Vm,
{
    pub vm: V,
    pub memory: Memory,
    pub vcpus: Arc<RwLock<Vec<VcpuHandle>>>,
    pub arch: ArchBoard<V>,
    pub config: BoardConfig,
    pub payload: RwLock<Option<Payload>>,
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

    mp_sync: Mutex<MpSync>,
    cond_var: Condvar,
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn new(vm: V, memory: Memory, arch: ArchBoard<V>, config: BoardConfig) -> Self {
        Board {
            vm,
            memory,
            arch,
            config,
            payload: RwLock::new(None),
            vcpus: Arc::new(RwLock::new(Vec::new())),
            io_devs: RwLock::new(Vec::new()),
            #[cfg(target_arch = "aarch64")]
            mmio_devs: RwLock::new(Vec::new()),
            pci_bus: PciBus::new(),
            #[cfg(target_arch = "x86_64")]
            fw_cfg: Mutex::new(None),
            #[cfg(target_os = "linux")]
            vfio_ioases: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            vfio_containers: Mutex::new(HashMap::new()),

            mp_sync: Mutex::new(MpSync {
                state: BoardState::Created,
                count: 0,
            }),
            cond_var: Condvar::new(),
        }
    }

    pub fn boot(&self) -> Result<()> {
        let mut mp_sync = self.mp_sync.lock();
        if mp_sync.state == BoardState::Created {
            mp_sync.state = BoardState::Running;
        } else {
            return error::UnexpectedState {
                state: mp_sync.state,
                want: BoardState::Created,
            }
            .fail();
        }
        self.cond_var.notify_all();
        Ok(())
    }

    fn load_payload(&self) -> Result<InitState, Error> {
        let payload = self.payload.read();
        let Some(payload) = payload.as_ref() else {
            return error::MissingPayload.fail();
        };

        if let Some(fw) = payload.firmware.as_ref() {
            return self.setup_firmware(fw, payload);
        }

        let Some(exec) = &payload.executable else {
            return error::MissingPayload.fail();
        };
        let mem_regions = self.memory.mem_region_entries();
        let init_state = match exec {
            Executable::Linux(image) => linux::load(
                &self.memory.ram_bus(),
                &mem_regions,
                image.as_ref(),
                payload.cmdline.as_deref(),
                payload.initramfs.as_deref(),
            ),
            #[cfg(target_arch = "x86_64")]
            Executable::Pvh(image) => xen::load(
                &self.memory.ram_bus(),
                &mem_regions,
                image.as_ref(),
                payload.cmdline.as_deref(),
                payload.initramfs.as_deref(),
            ),
        }?;
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
        self.pci_bus.segment.assign_resources(&[
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

    fn vcpu_loop(&self, vcpu: &mut <V as Vm>::Vcpu, index: u16) -> Result<bool, Error> {
        let mut vm_entry = VmEntry::None;
        loop {
            let vm_exit = vcpu.run(vm_entry).context(error::RunVcpu { index })?;
            vm_entry = match vm_exit {
                #[cfg(target_arch = "x86_64")]
                VmExit::Io { port, write, size } => self.memory.handle_io(port, write, size)?,
                VmExit::Mmio { addr, write, size } => self.memory.handle_mmio(addr, write, size)?,
                VmExit::Shutdown => {
                    log::info!("VCPU-{index} requested shutdown");
                    break Ok(false);
                }
                VmExit::Reboot => {
                    break Ok(true);
                }
                VmExit::Interrupted => {
                    let mp_sync = self.mp_sync.lock();
                    match mp_sync.state {
                        BoardState::Shutdown => VmEntry::Shutdown,
                        BoardState::RebootPending => VmEntry::Reboot,
                        _ => VmEntry::None,
                    }
                }
                VmExit::ConvertMemory { gpa, size, private } => {
                    self.memory.mark_private_memory(gpa, size, private)?;
                    VmEntry::None
                }
            };
        }
    }

    fn sync_vcpus(&self, vcpus: &VcpuGuard) -> Result<()> {
        let mut mp_sync = self.mp_sync.lock();
        if mp_sync.state == BoardState::Fatal {
            return error::PeerFailure.fail();
        }

        mp_sync.count += 1;
        if mp_sync.count == vcpus.len() as u16 {
            mp_sync.count = 0;
            self.cond_var.notify_all();
        } else {
            self.cond_var.wait(&mut mp_sync)
        }

        if mp_sync.state == BoardState::Fatal {
            return error::PeerFailure.fail();
        }

        Ok(())
    }

    fn notify_vmm(&self, index: u16, event_tx: &Sender<u16>) -> Result<()> {
        if event_tx.send(index).is_err() {
            error::NotifyVmm.fail()
        } else {
            Ok(())
        }
    }

    fn run_vcpu_inner(&self, index: u16, event_tx: &Sender<u16>) -> Result<(), Error> {
        let mut vcpu = self.create_vcpu(index)?;
        self.notify_vmm(index, event_tx)?;
        self.init_vcpu(index, &mut vcpu)?;

        let mut mp_sync = self.mp_sync.lock();
        while mp_sync.state == BoardState::Created {
            self.cond_var.wait(&mut mp_sync);
        }
        if mp_sync.state != BoardState::Running {
            return Ok(());
        }
        drop(mp_sync);

        loop {
            let vcpus = self.vcpus.read();
            self.coco_init(index)?;
            if index == 0 {
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
            self.init_ap(index, &mut vcpu, &vcpus)?;
            self.coco_finalize(index, &vcpus)?;
            self.sync_vcpus(&vcpus)?;
            drop(vcpus);

            let maybe_reboot = self.vcpu_loop(&mut vcpu, index);

            let vcpus = self.vcpus.read();
            let mut mp_sync = self.mp_sync.lock();
            if mp_sync.state == BoardState::Running {
                mp_sync.state = if matches!(maybe_reboot, Ok(true)) {
                    BoardState::RebootPending
                } else {
                    BoardState::Shutdown
                };
                for (another, handle) in vcpus.iter().enumerate() {
                    if index == another as u16 {
                        continue;
                    }
                    log::info!("VCPU-{index}: stopping VCPU-{another}");
                    self.vm
                        .stop_vcpu(self.encode_cpu_identity(another as u16), handle)
                        .context(error::StopVcpu {
                            index: another as u16,
                        })?;
                }
            }
            drop(mp_sync);
            self.sync_vcpus(&vcpus)?;

            if index == 0 {
                self.pci_bus.segment.reset().context(error::ResetPci)?;
                self.memory.reset()?;
            }
            self.reset_vcpu(index, &mut vcpu)?;

            if let Err(e) = maybe_reboot {
                break Err(e);
            }

            let mut mp_sync = self.mp_sync.lock();
            if mp_sync.state == BoardState::Shutdown {
                break Ok(());
            }
            mp_sync.state = BoardState::Running;
        }
    }

    fn create_vcpu(&self, index: u16) -> Result<V::Vcpu> {
        let identity = self.encode_cpu_identity(index);
        let vcpu = self
            .vm
            .create_vcpu(index, identity)
            .context(error::CreateVcpu { index })?;
        Ok(vcpu)
    }

    pub fn run_vcpu(&self, index: u16, event_tx: Sender<u16>) -> Result<(), Error> {
        let ret = self.run_vcpu_inner(index, &event_tx);

        let _ = self.notify_vmm(index, &event_tx);

        if matches!(ret, Ok(_) | Err(Error::PeerFailure { .. })) {
            return Ok(());
        }

        log::warn!("VCPU-{index} reported error, unblocking other VCPUs...");
        let mut mp_sync = self.mp_sync.lock();
        mp_sync.state = BoardState::Fatal;
        if mp_sync.count > 0 {
            self.cond_var.notify_all();
        }
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

#[cfg(test)]
#[path = "board_test.rs"]
mod tests;
