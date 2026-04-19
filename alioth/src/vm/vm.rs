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

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use flume::{Receiver, Sender};
#[cfg(target_os = "linux")]
use parking_lot::Mutex;
use snafu::{ResultExt, Snafu};

#[cfg(target_arch = "aarch64")]
use crate::arch::layout::{PL011_START, PL031_START};
#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{PORT_CMOS_REG, PORT_COM1, PORT_FW_CFG_SELECTOR, PORT_FWDBG};
use crate::board::{Board, BoardConfig};
use crate::cpu::{Context, State, VcpuHandle, stop_vcpus, vcpu_thread};
use crate::device::clock::SystemClock;
#[cfg(target_arch = "x86_64")]
use crate::device::cmos::Cmos;
use crate::device::console::StdioConsole;
#[cfg(target_arch = "x86_64")]
use crate::device::fw_cfg::{FwCfg, FwCfgItemParam};
#[cfg(target_arch = "x86_64")]
use crate::device::fw_dbg::FwDbg;
#[cfg(target_arch = "aarch64")]
use crate::device::pl011::Pl011;
#[cfg(target_arch = "aarch64")]
use crate::device::pl031::Pl031;
#[cfg(target_arch = "x86_64")]
use crate::device::serial::Serial;
use crate::errors::{DebugTrace, trace_error};
use crate::hv::{Hypervisor, IoeventFdRegistry, Vm};
use crate::loader::Payload;
use crate::pci::pvpanic::PvPanic;
use crate::pci::{Bdf, Pci};
#[cfg(target_os = "linux")]
use crate::sys::vfio::VfioIommu;
#[cfg(target_os = "linux")]
use crate::vfio::cdev::Cdev;
#[cfg(target_os = "linux")]
use crate::vfio::container::{Container, UpdateContainerMapping};
#[cfg(target_os = "linux")]
use crate::vfio::group::{DevFd, Group};
#[cfg(target_os = "linux")]
use crate::vfio::iommu::{Ioas, Iommu, UpdateIommuIoas};
#[cfg(target_os = "linux")]
use crate::vfio::pci::VfioPciDev;
#[cfg(target_os = "linux")]
use crate::vfio::{CdevParam, ContainerParam, GroupParam, IoasParam};
use crate::virtio::dev::{DevParam, Virtio, VirtioDevice};
use crate::virtio::pci::VirtioPciDevice;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Failed to create VCPU-{index} thread"))]
    CreateVcpu { index: u16, error: std::io::Error },
    #[snafu(display("Failed to stop VCPUs"))]
    StopVcpus { source: Box<crate::cpu::Error> },
    #[snafu(display("VCPU-{index} thread exited unexpectedly"))]
    VcpuExit {
        index: u16,
        source: Box<crate::cpu::Error>,
    },
    #[snafu(display("Failed to create a console"))]
    CreateConsole { error: crate::device::Error },
    #[snafu(display("Failed to configure firmware"))]
    FwCfg { error: std::io::Error },
    #[snafu(display("Failed to create a VirtIO device"), context(false))]
    CreateVirtio { source: Box<crate::virtio::Error> },
    #[snafu(display("Guest memory is not backed by sharable file descriptors"))]
    MemNotSharedFd,
    #[cfg(target_os = "linux")]
    #[snafu(display("Failed to create a VFIO device"), context(false))]
    CreateVfio { source: Box<crate::vfio::Error> },
    #[snafu(display("Failed to configure guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("Failed to setup board"), context(false))]
    Board { source: Box<crate::board::Error> },
    #[cfg(target_os = "linux")]
    #[snafu(display("{name:?} already exists"))]
    AlreadyExists { name: Box<str> },
    #[cfg(target_os = "linux")]
    #[snafu(display("{name:?} does not exist"))]
    NotExist { name: Box<str> },
    #[snafu(display("Unexpected state: {state:?}, want {want:?}"))]
    UnexpectedState { state: State, want: State },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Machine<H>
where
    H: Hypervisor,
{
    ctx: Arc<Context<H::Vm>>,
    event_rx: Receiver<u16>,
    _event_tx: Sender<u16>,

    #[cfg(target_os = "linux")]
    iommu: Mutex<Option<Arc<Iommu>>>,
    #[cfg(target_os = "linux")]
    pub vfio_ioases: Mutex<HashMap<Box<str>, Arc<Ioas>>>,
    #[cfg(target_os = "linux")]
    pub vfio_containers: Mutex<HashMap<Box<str>, Arc<Container>>>,
}

pub type VirtioPciDev<H> = VirtioPciDevice<
    <<H as Hypervisor>::Vm as Vm>::MsiSender,
    <<<H as Hypervisor>::Vm as Vm>::IoeventFdRegistry as IoeventFdRegistry>::IoeventFd,
>;

impl<H> Machine<H>
where
    H: Hypervisor,
{
    pub fn new(hv: &H, config: BoardConfig) -> Result<Self> {
        let ctx = Arc::new(Context::new(Board::new(hv, config)?));

        let (event_tx, event_rx) = flume::unbounded();

        let mut vcpus = ctx.vcpus.write();
        for index in 0..ctx.board.config.cpu.count {
            let event_tx = event_tx.clone();
            let ctx = ctx.clone();
            let handle = thread::Builder::new()
                .name(format!("vcpu_{index}"))
                .spawn(move || vcpu_thread(index, ctx, event_tx))
                .context(error::CreateVcpu { index })?;
            if event_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                let err = std::io::ErrorKind::TimedOut.into();
                Err(err).context(error::CreateVcpu { index })?;
            }
            let handle = VcpuHandle { thread: handle };
            vcpus.push(handle);
        }
        drop(vcpus);

        ctx.board.arch_init()?;

        let vm = Machine {
            ctx,
            event_rx,
            _event_tx: event_tx,
            #[cfg(target_os = "linux")]
            iommu: Mutex::new(None),
            #[cfg(target_os = "linux")]
            vfio_ioases: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            vfio_containers: Mutex::new(HashMap::new()),
        };

        Ok(vm)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_com1(&self) -> Result<(), Error> {
        let io_apic = self.ctx.board.arch.io_apic.clone();
        let console = StdioConsole::new().context(error::CreateConsole)?;
        let com1 = Serial::new(PORT_COM1, io_apic, 4, console).context(error::CreateConsole)?;
        let mut io_devs = self.ctx.board.io_devs.write();
        io_devs.push((PORT_COM1, Arc::new(com1)));
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_cmos(&self) -> Result<(), Error> {
        let mut io_devs = self.ctx.board.io_devs.write();
        io_devs.push((PORT_CMOS_REG, Arc::new(Cmos::new(SystemClock))));
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_fw_dbg(&self) -> Result<(), Error> {
        let mut io_devs = self.ctx.board.io_devs.write();
        io_devs.push((PORT_FWDBG, Arc::new(FwDbg::new())));
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn add_pl011(&self) -> Result<(), Error> {
        let irq_line = self.ctx.board.vm.create_irq_sender(1)?;
        let console = StdioConsole::new().context(error::CreateConsole)?;
        let pl011_dev = Pl011::new(PL011_START, irq_line, console).context(error::CreateConsole)?;
        let mut mmio_devs = self.ctx.board.mmio_devs.write();
        mmio_devs.push((PL011_START, Arc::new(pl011_dev)));
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn add_pl031(&self) {
        let pl031_dev = Pl031::new(PL031_START, SystemClock);
        let mut mmio_devs = self.ctx.board.mmio_devs.write();
        mmio_devs.push((PL031_START, Arc::new(pl031_dev)));
    }

    pub fn add_pci_dev(&self, bdf: Option<Bdf>, dev: Arc<dyn Pci>) -> Result<(), Error> {
        let bdf = if let Some(bdf) = bdf {
            bdf
        } else {
            self.ctx.board.pci_bus.reserve(None).unwrap()
        };
        dev.config().get_header().set_bdf(bdf);
        log::info!("{bdf}: device: {}", dev.name());
        self.ctx.board.pci_bus.add(bdf, dev);
        Ok(())
    }

    pub fn add_pvpanic(&self) -> Result<(), Error> {
        let dev = PvPanic::new();
        let pci_dev = Arc::new(dev);
        self.add_pci_dev(None, pci_dev)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_fw_cfg(
        &self,
        params: impl Iterator<Item = FwCfgItemParam>,
    ) -> Result<Arc<Mutex<FwCfg>>, Error> {
        let items = params
            .map(|p| p.build())
            .collect::<Result<Vec<_>, _>>()
            .context(error::FwCfg)?;
        let fw_cfg = Arc::new(Mutex::new(
            FwCfg::new(self.ctx.board.memory.ram_bus(), items).context(error::FwCfg)?,
        ));
        let mut io_devs = self.ctx.board.io_devs.write();
        io_devs.push((PORT_FW_CFG_SELECTOR, fw_cfg.clone()));
        *self.ctx.board.fw_cfg.lock() = Some(fw_cfg.clone());
        Ok(fw_cfg)
    }

    pub fn add_virtio_dev<D, P>(
        &self,
        name: impl Into<Arc<str>>,
        param: P,
    ) -> Result<Arc<VirtioPciDev<H>>, Error>
    where
        P: DevParam<Device = D>,
        D: Virtio,
    {
        if param.needs_mem_shared_fd() && !self.ctx.board.config.mem.has_shared_fd() {
            return error::MemNotSharedFd.fail();
        }
        let name = name.into();
        let bdf = self.ctx.board.pci_bus.reserve(None).unwrap();
        let dev = param.build(name.clone())?;
        if let Some(callback) = dev.mem_update_callback() {
            self.ctx.board.memory.register_update_callback(callback)?;
        }
        if let Some(callback) = dev.mem_change_callback() {
            self.ctx.board.memory.register_change_callback(callback)?;
        }
        let registry = self.ctx.board.vm.create_ioeventfd_registry()?;
        let virtio_dev = VirtioDevice::new(
            name.clone(),
            dev,
            self.ctx.board.memory.ram_bus(),
            self.ctx.board.config.coco.is_some(),
        )?;
        let msi_sender = self.ctx.board.vm.create_msi_sender(
            #[cfg(target_arch = "aarch64")]
            u32::from(bdf.0),
        )?;
        let dev = VirtioPciDevice::new(virtio_dev, msi_sender, registry)?;
        let dev = Arc::new(dev);
        self.add_pci_dev(Some(bdf), dev.clone())?;
        Ok(dev)
    }

    pub fn add_payload(&self, payload: Payload) {
        *self.ctx.board.payload.write() = Some(payload)
    }
}

#[cfg(target_os = "linux")]
impl<H> Machine<H>
where
    H: Hypervisor,
{
    const DEFAULT_NAME: &str = "default";

    pub fn add_vfio_ioas(&self, param: IoasParam) -> Result<Arc<Ioas>, Error> {
        let mut ioases = self.vfio_ioases.lock();
        if ioases.contains_key(&param.name) {
            return error::AlreadyExists { name: param.name }.fail();
        }
        let maybe_iommu = &mut *self.iommu.lock();
        let iommu = if let Some(iommu) = maybe_iommu {
            iommu.clone()
        } else {
            let iommu_path = if let Some(dev_iommu) = &param.dev_iommu {
                dev_iommu
            } else {
                Path::new("/dev/iommu")
            };
            let iommu = Arc::new(Iommu::new(iommu_path)?);
            maybe_iommu.replace(iommu.clone());
            iommu
        };
        let ioas = Arc::new(Ioas::alloc_on(iommu)?);
        let update = Box::new(UpdateIommuIoas { ioas: ioas.clone() });
        self.ctx.board.memory.register_change_callback(update)?;
        ioases.insert(param.name, ioas.clone());
        Ok(ioas)
    }

    fn get_ioas(&self, name: Option<&str>) -> Result<Arc<Ioas>> {
        let ioas_name = name.unwrap_or(Self::DEFAULT_NAME);
        if let Some(ioas) = self.vfio_ioases.lock().get(ioas_name) {
            return Ok(ioas.clone());
        };
        if name.is_none() {
            self.add_vfio_ioas(IoasParam {
                name: Self::DEFAULT_NAME.into(),
                dev_iommu: None,
            })
        } else {
            error::NotExist { name: ioas_name }.fail()
        }
    }

    pub fn add_vfio_cdev(&self, name: Arc<str>, param: CdevParam) -> Result<(), Error> {
        let ioas = self.get_ioas(param.ioas.as_deref())?;

        let mut cdev = Cdev::new(&param.path)?;
        cdev.attach_iommu_ioas(ioas.clone())?;

        let bdf = self.ctx.board.pci_bus.reserve(None).unwrap();
        let msi_sender = self.ctx.board.vm.create_msi_sender(
            #[cfg(target_arch = "aarch64")]
            u32::from(bdf.0),
        )?;
        let dev = VfioPciDev::new(name.clone(), cdev, msi_sender)?;
        self.add_pci_dev(Some(bdf), Arc::new(dev))?;
        Ok(())
    }

    pub fn add_vfio_container(&self, param: ContainerParam) -> Result<Arc<Container>, Error> {
        let mut containers = self.vfio_containers.lock();
        if containers.contains_key(&param.name) {
            return error::AlreadyExists { name: param.name }.fail();
        }
        let vfio_path = if let Some(dev_vfio) = &param.dev_vfio {
            dev_vfio
        } else {
            Path::new("/dev/vfio/vfio")
        };
        let container = Arc::new(Container::new(vfio_path)?);
        let update = Box::new(UpdateContainerMapping {
            container: container.clone(),
        });
        self.ctx.board.memory.register_change_callback(update)?;
        containers.insert(param.name, container.clone());
        Ok(container)
    }

    fn get_container(&self, name: Option<&str>) -> Result<Arc<Container>> {
        let container_name = name.unwrap_or(Self::DEFAULT_NAME);
        if let Some(container) = self.vfio_containers.lock().get(container_name) {
            return Ok(container.clone());
        }
        if name.is_none() {
            self.add_vfio_container(ContainerParam {
                name: Self::DEFAULT_NAME.into(),
                dev_vfio: None,
            })
        } else {
            error::NotExist {
                name: container_name,
            }
            .fail()
        }
    }

    pub fn add_vfio_devs_in_group(&self, name: &str, param: GroupParam) -> Result<()> {
        let container = self.get_container(param.container.as_deref())?;
        let mut group = Group::new(&param.path)?;
        group.attach(container, VfioIommu::TYPE1_V2)?;

        let group = Arc::new(group);
        for device in param.devices {
            let devfd = DevFd::new(group.clone(), &device)?;
            let name = format!("{name}-{device}");
            self.add_vfio_devfd(name.into(), devfd)?;
        }

        Ok(())
    }

    fn add_vfio_devfd(&self, name: Arc<str>, devfd: DevFd) -> Result<()> {
        let bdf = self.ctx.board.pci_bus.reserve(None).unwrap();
        let msi_sender = self.ctx.board.vm.create_msi_sender(
            #[cfg(target_arch = "aarch64")]
            u32::from(bdf.0),
        )?;
        let dev = VfioPciDev::new(name.clone(), devfd, msi_sender)?;
        self.add_pci_dev(Some(bdf), Arc::new(dev))
    }
}

impl<H> Machine<H>
where
    H: Hypervisor,
{
    pub fn boot(&self) -> Result<()> {
        self.resume()
    }

    pub fn resume(&self) -> Result<()> {
        let mut sync = self.ctx.sync.lock();
        if !matches!(sync.state, State::Paused) {
            return error::UnexpectedState {
                state: sync.state,
                want: State::Paused,
            }
            .fail();
        }
        sync.state = State::Running;
        self.ctx.cond.notify_all();
        Ok(())
    }

    pub fn pause(&self) -> Result<()> {
        let vcpus = self.ctx.vcpus.read();
        let mut sync = self.ctx.sync.lock();
        if !matches!(sync.state, State::Running) {
            return error::UnexpectedState {
                state: sync.state,
                want: State::Running,
            }
            .fail();
        }
        sync.state = State::Paused;
        stop_vcpus(&self.ctx.board, None, &vcpus).context(error::StopVcpus)?;
        Ok(())
    }

    pub fn wait(&self) -> Result<()> {
        self.event_rx.recv().unwrap();
        let vcpus = self.ctx.vcpus.read();
        for _ in 1..vcpus.len() {
            self.event_rx.recv().unwrap();
        }
        drop(vcpus);
        let mut vcpus = self.ctx.vcpus.write();
        let mut ret = Ok(());
        for (index, handle) in vcpus.drain(..).enumerate() {
            let Ok(r) = handle.thread.join() else {
                log::error!("Cannot join VCPU-{index}");
                continue;
            };
            if ret.is_ok() {
                ret = r.context(error::VcpuExit {
                    index: index as u16,
                });
            }
        }
        ret
    }
}
