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
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
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
use crate::errors::{DebugTrace, trace_error};
use crate::hv::{Coco, Vcpu, Vm, VmEntry, VmExit};
#[cfg(target_arch = "x86_64")]
use crate::loader::xen;
use crate::loader::{ExecType, InitState, Payload, firmware, linux};
use crate::mem::emulated::Mmio;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{MemBackend, MemConfig, MemRegion, MemRegionType, Memory};
use crate::pci::Bdf;
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
    #[snafu(display("Failed to configure firmware"))]
    Firmware { error: std::io::Error },
    #[snafu(display("Failed to notify the VMM thread"))]
    NotifyVmm,
    #[snafu(display("Another VCPU thread has signaled failure"))]
    PeerFailure,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoardState {
    Created,
    Running,
    Shutdown,
    RebootPending,
}

#[derive(Debug)]
struct MpSync {
    state: BoardState,
    fatal: bool,
    count: u32,
}

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
                fatal: false,
            }),
            cond_var: Condvar::new(),
        }
    }

    pub fn boot(&self) -> Result<()> {
        let vcpus = self.vcpus.read();
        let mut mp_sync = self.mp_sync.lock();
        mp_sync.state = BoardState::Running;
        for (_, boot_tx) in vcpus.iter() {
            boot_tx.send(()).unwrap();
        }
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
        if mp_sync.fatal {
            return error::PeerFailure.fail();
        }

        mp_sync.count += 1;
        if mp_sync.count == vcpus.len() as u32 {
            mp_sync.count = 0;
            self.cond_var.notify_all();
        } else {
            self.cond_var.wait(&mut mp_sync)
        }

        if mp_sync.fatal {
            return error::PeerFailure.fail();
        }

        Ok(())
    }

    fn run_vcpu_inner(
        &self,
        id: u32,
        vcpu: &mut V::Vcpu,
        boot_rx: &Receiver<()>,
    ) -> Result<(), Error> {
        self.init_vcpu(id, vcpu)?;
        boot_rx.recv().unwrap();
        if self.mp_sync.lock().state != BoardState::Running {
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
                self.init_boot_vcpu(vcpu, &init_state)?;
                self.create_firmware_data(&init_state)?;
            }
            self.init_ap(id, vcpu, &vcpus)?;
            self.coco_finalize(id, &vcpus)?;
            self.sync_vcpus(&vcpus)?;
            drop(vcpus);

            let maybe_reboot = self.vcpu_loop(vcpu, id);

            let vcpus = self.vcpus.read();
            let mut mp_sync = self.mp_sync.lock();
            if mp_sync.state == BoardState::Running {
                mp_sync.state = if matches!(maybe_reboot, Ok(true)) {
                    BoardState::RebootPending
                } else {
                    BoardState::Shutdown
                };
                for (vcpu_id, (handle, _)) in vcpus.iter().enumerate() {
                    if id != vcpu_id as u32 {
                        log::info!("VCPU-{id}: stopping VCPU-{vcpu_id}");
                        self.vm
                            .stop_vcpu(vcpu_id as u32, handle)
                            .context(error::StopVcpu { id })?;
                    }
                }
            }
            drop(mp_sync);
            self.sync_vcpus(&vcpus)?;

            if id == 0 {
                let devices = self.pci_bus.segment.devices.read();
                for (bdf, dev) in devices.iter() {
                    dev.dev.reset().context(error::ResetPci { bdf: *bdf })?;
                    dev.dev.config().reset();
                }
                self.memory.reset()?;
            }
            self.reset_vcpu(id, vcpu)?;

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

    fn create_vcpu(&self, id: u32, event_tx: &Sender<u32>) -> Result<V::Vcpu> {
        let vcpu = self.vm.create_vcpu(id).context(error::CreateVcpu { id })?;
        if event_tx.send(id).is_err() {
            error::NotifyVmm.fail()
        } else {
            Ok(vcpu)
        }
    }

    pub fn run_vcpu(
        &self,
        id: u32,
        event_tx: Sender<u32>,
        boot_rx: Receiver<()>,
    ) -> Result<(), Error> {
        let mut vcpu = self.create_vcpu(id, &event_tx)?;

        let ret = self.run_vcpu_inner(id, &mut vcpu, &boot_rx);
        event_tx.send(id).unwrap();

        if matches!(ret, Ok(_) | Err(Error::PeerFailure { .. })) {
            return Ok(());
        }

        log::warn!("VCPU-{id} reported error, unblocking other VCPUs...");
        let mut mp_sync = self.mp_sync.lock();
        mp_sync.fatal = true;
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
