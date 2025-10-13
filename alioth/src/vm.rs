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
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "linux")]
use parking_lot::Mutex;
use snafu::{ResultExt, Snafu};

#[cfg(target_arch = "aarch64")]
use crate::arch::layout::{PL011_START, PL031_START};
#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{PORT_COM1, PORT_FW_CFG_SELECTOR};
use crate::board::{ArchBoard, Board, BoardConfig};
#[cfg(target_arch = "x86_64")]
use crate::device::fw_cfg::{FwCfg, FwCfgItemParam};
#[cfg(target_arch = "aarch64")]
use crate::device::pl011::Pl011;
#[cfg(target_arch = "aarch64")]
use crate::device::pl031::Pl031;
use crate::device::pvpanic::PvPanic;
#[cfg(target_arch = "x86_64")]
use crate::device::serial::Serial;
use crate::errors::{DebugTrace, trace_error};
#[cfg(target_os = "linux")]
use crate::hv::Kvm;
use crate::hv::{Hypervisor, IoeventFdRegistry, Vm, VmConfig};
use crate::loader::Payload;
use crate::mem::Memory;
#[cfg(target_arch = "aarch64")]
use crate::mem::{MemRegion, MemRegionType};
use crate::pci::{Bdf, PciDevice};
#[cfg(target_os = "linux")]
use crate::sys::vfio::VfioIommu;
#[cfg(target_os = "linux")]
use crate::vfio::cdev::Cdev;
#[cfg(target_os = "linux")]
use crate::vfio::container::{Container, UpdateContainerMapping};
#[cfg(target_os = "linux")]
use crate::vfio::group::{DevFd, Group};
#[cfg(target_os = "linux")]
use crate::vfio::iommu::UpdateIommuIoas;
#[cfg(target_os = "linux")]
use crate::vfio::iommu::{Ioas, Iommu};
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
    #[cfg(target_os = "linux")]
    #[snafu(display("Failed to create a VFIO device"), context(false))]
    CreateVfio { source: Box<crate::vfio::Error> },
    #[snafu(display("VCPU-{id} error"))]
    VcpuError {
        id: u32,
        source: Box<crate::board::Error>,
    },
    #[snafu(display("Failed to configure guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[cfg(target_os = "linux")]
    #[snafu(display("{name:?} already exists"))]
    AlreadyExists { name: Box<str> },
    #[cfg(target_os = "linux")]
    #[snafu(display("{name:?} does not exist"))]
    NotExist { name: Box<str> },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Machine<H>
where
    H: Hypervisor,
{
    board: Arc<Board<H::Vm>>,
    #[cfg(target_os = "linux")]
    iommu: Mutex<Option<Arc<Iommu>>>,
    event_rx: Receiver<u32>,
    _event_tx: Sender<u32>,
}

pub type VirtioPciDev<H> = VirtioPciDevice<
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

        let board = Arc::new(Board::new(vm, memory, arch, config));

        let (event_tx, event_rx) = mpsc::channel();

        let mut vcpus = board.vcpus.write();
        for vcpu_id in 0..board.config.num_cpu {
            let (boot_tx, boot_rx) = mpsc::channel();
            let event_tx = event_tx.clone();
            let board = board.clone();
            let handle = thread::Builder::new()
                .name(format!("vcpu_{vcpu_id}"))
                .spawn(move || board.run_vcpu(vcpu_id, event_tx, boot_rx))
                .context(error::VcpuThread { id: vcpu_id })?;
            if event_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                let err = std::io::ErrorKind::TimedOut.into();
                Err(err).context(error::VcpuThread { id: vcpu_id })?;
            }
            vcpus.push((handle, boot_tx));
        }
        drop(vcpus);

        board.arch_init()?;

        let machine = Machine {
            board,
            event_rx,
            _event_tx: event_tx,
            #[cfg(target_os = "linux")]
            iommu: Mutex::new(None),
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

    #[cfg(target_arch = "aarch64")]
    pub fn add_pl031(&self) {
        let pl031_dev = Pl031::new(PL031_START);
        self.board.mmio_devs.write().push((
            PL031_START,
            Arc::new(MemRegion::with_emulated(
                Arc::new(pl031_dev),
                MemRegionType::Hidden,
            )),
        ));
    }

    pub fn add_pci_dev(&self, bdf: Option<Bdf>, dev: PciDevice) -> Result<(), Error> {
        let name = dev.name.clone();
        let bdf = if let Some(bdf) = bdf {
            bdf
        } else {
            self.board.pci_bus.reserve(None, name.clone()).unwrap()
        };
        dev.dev.config().get_header().set_bdf(bdf);
        self.board.pci_bus.add(bdf, dev);
        log::info!("{bdf}: device: {name}");
        Ok(())
    }

    pub fn add_pvpanic(&self) -> Result<(), Error> {
        let dev = PvPanic::new();
        let pci_dev = PciDevice::new("pvpanic", Arc::new(dev));
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
            FwCfg::new(self.board.memory.ram_bus(), items).context(error::FwCfg)?,
        ));
        let mut io_devs = self.board.io_devs.write();
        io_devs.push((PORT_FW_CFG_SELECTOR, fw_cfg.clone()));
        *self.board.fw_cfg.lock() = Some(fw_cfg.clone());
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
        if param.needs_mem_shared_fd() && !self.board.config.mem.has_shared_fd() {
            return error::MemNotSharedFd.fail();
        }
        let name = name.into();
        let bdf = self.board.pci_bus.reserve(None, name.clone()).unwrap();
        let dev = param.build(name.clone())?;
        if let Some(callback) = dev.mem_update_callback() {
            self.board.memory.register_update_callback(callback)?;
        }
        if let Some(callback) = dev.mem_change_callback() {
            self.board.memory.register_change_callback(callback)?;
        }
        let registry = self.board.vm.create_ioeventfd_registry()?;
        let virtio_dev = VirtioDevice::new(
            name.clone(),
            dev,
            self.board.memory.ram_bus(),
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

    pub fn add_payload(&self, payload: Payload) {
        *self.board.payload.write() = Some(payload)
    }

    pub fn boot(&self) -> Result<(), Error> {
        self.board.boot()?;
        Ok(())
    }

    pub fn wait(&self) -> Result<()> {
        self.event_rx.recv().unwrap();
        let vcpus = self.board.vcpus.read();
        for _ in 1..vcpus.len() {
            self.event_rx.recv().unwrap();
        }
        drop(vcpus);
        let mut vcpus = self.board.vcpus.write();
        let mut ret = Ok(());
        for (id, (handle, _)) in vcpus.drain(..).enumerate() {
            let Ok(r) = handle.join() else {
                log::error!("Cannot join VCPU-{id}");
                continue;
            };
            if r.is_err() && ret.is_ok() {
                ret = r.context(error::Vcpu { id: id as u32 });
            }
        }
        ret
    }
}

#[cfg(target_os = "linux")]
impl Machine<Kvm> {
    const DEFAULT_NAME: &str = "default";

    pub fn add_vfio_ioas(&self, param: IoasParam) -> Result<Arc<Ioas>, Error> {
        let mut ioases = self.board.vfio_ioases.lock();
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
        self.board.memory.register_change_callback(update)?;
        ioases.insert(param.name, ioas.clone());
        Ok(ioas)
    }

    fn get_ioas(&self, name: Option<&str>) -> Result<Arc<Ioas>> {
        let ioas_name = name.unwrap_or(Self::DEFAULT_NAME);
        if let Some(ioas) = self.board.vfio_ioases.lock().get(ioas_name) {
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

        let bdf = self.board.pci_bus.reserve(None, name.clone()).unwrap();
        let msi_sender = self.board.vm.create_msi_sender(
            #[cfg(target_arch = "aarch64")]
            u32::from(bdf.0),
        )?;
        let dev = VfioPciDev::new(name.clone(), cdev, msi_sender)?;
        let pci_dev = PciDevice::new(name, Arc::new(dev));
        self.add_pci_dev(Some(bdf), pci_dev)?;
        Ok(())
    }

    pub fn add_vfio_container(&self, param: ContainerParam) -> Result<Arc<Container>, Error> {
        let mut containers = self.board.vfio_containers.lock();
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
        self.board.memory.register_change_callback(update)?;
        containers.insert(param.name, container.clone());
        Ok(container)
    }

    fn get_container(&self, name: Option<&str>) -> Result<Arc<Container>> {
        let container_name = name.unwrap_or(Self::DEFAULT_NAME);
        if let Some(container) = self.board.vfio_containers.lock().get(container_name) {
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
        let bdf = self.board.pci_bus.reserve(None, name.clone()).unwrap();
        let msi_sender = self.board.vm.create_msi_sender(
            #[cfg(target_arch = "aarch64")]
            u32::from(bdf.0),
        )?;
        let dev = VfioPciDev::new(name.clone(), devfd, msi_sender)?;
        let pci_dev = PciDevice::new(name, Arc::new(dev));
        self.add_pci_dev(Some(bdf), pci_dev)
    }
}
