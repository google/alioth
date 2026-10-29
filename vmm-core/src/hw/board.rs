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

use core::cell::UnsafeCell;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;

use thiserror::Error;
use zerocopy::AsBytes;

use crate::host::abi::{
    CORE_MSG_SHUTDOWN, CoreToIoEntry, GPR_RAX, GPR_RBX, GPR_RCX, GPR_RDX, IO_MSG_REQUEST_SHUTDOWN,
    IO_MSG_SERIAL_RX, IoToCoreEntry, RawVmEntry, SYNC_REG_GPRS, SYNC_REG_RIP_RFLAGS,
    SYNC_REG_SREGS, VcpuCommPage,
};
use crate::host::{
    self, PayloadKind, VcpuId, VmAction, VmEntry, VmExit, VmmCoreBridge, VmmHostCore,
};
use crate::loader::{self, ExecType, InitState, Payload, PayloadReader, linux, xen};
use crate::mem::mmio::Mmio;
use crate::mem::{self, AddrOpt, MemRegion, MemRegionType, Memory};
use crate::sync::{Condvar, Mutex, RwLock, RwLockReadGuard};
use crate::virtio;

#[path = "firmware/firmware.rs"]
pub mod firmware;
pub mod hw_x86_64;
pub use hw_x86_64::*;
pub mod insn_decode;
pub mod ioapic;
#[path = "pci/pci.rs"]
pub mod pci;
pub mod serial;

use firmware::acpi::bindings::AcpiTableRsdp;
use firmware::acpi::create_acpi;
use ioapic::IoApic;
use layout::{EBDA_START, IOAPIC_START, PCIE_CONFIG_START};
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

#[repr(transparent)]
pub struct VcpuCommSlot(UnsafeCell<VcpuCommPage>);

impl VcpuCommSlot {
    pub fn new() -> Self {
        Self(UnsafeCell::new(VcpuCommPage::default()))
    }
}

impl Default for VcpuCommSlot {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: Each `VcpuCommSlot` at index `id` is exclusively accessed by the runner of `vcpu_id == id`.
unsafe impl Send for VcpuCommSlot {}
unsafe impl Sync for VcpuCommSlot {}

type VcpuGuard<'a> = RwLockReadGuard<'a, Vec<(JoinHandle<Result<()>>, Sender<()>)>>;

pub struct Board {
    pub hv: Arc<dyn VmmHostCore>,
    pub bridge: Arc<dyn VmmCoreBridge>,
    pub memory: Memory,
    #[allow(clippy::type_complexity)]
    pub vcpus: Arc<RwLock<Vec<(JoinHandle<Result<()>>, Sender<()>)>>>,
    pub comm_pages: Box<[VcpuCommSlot]>,
    pub arch: ArchBoard,
    pub config: BoardConfig,
    pub state: AtomicU8,
    pub payload: RwLock<Option<Payload>>,
    pub mp_sync: Arc<(Mutex<u32>, Condvar)>,
    pub ioapic: Option<Arc<IoApic>>,
    pub io_devs: RwLock<Vec<(u16, Arc<dyn Mmio>)>>,
    pub com1: RwLock<Option<Arc<Serial>>>,
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
        let mut kernel_reader =
            PayloadReader::new(self.bridge.as_ref(), PayloadKind::Kernel, payload.kernel_size);
        let mut initramfs_reader = payload
            .initramfs_size
            .map(|sz| PayloadReader::new(self.bridge.as_ref(), PayloadKind::Initramfs, sz));
        let init_state = match payload.exec_type {
            ExecType::Linux => linux::load(
                &self.memory.ram_bus(),
                &mem_regions,
                &mut kernel_reader,
                payload.cmd_line.as_deref(),
                initramfs_reader.as_mut(),
            )?,
            ExecType::Pvh => xen::load(
                &self.memory.ram_bus(),
                &mem_regions,
                &mut kernel_reader,
                payload.cmd_line.as_deref(),
                initramfs_reader.as_mut(),
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

    /// Base pointer to the contiguous `[VcpuCommPage; num_cpu]` array in Wasm linear memory.
    pub fn comm_pages_ptr(&self) -> *mut VcpuCommPage {
        self.comm_pages.as_ptr() as *mut VcpuCommPage
    }

    /// Obtain exclusive mutable access to `vcpu_id`'s [`VcpuCommPage`].
    ///
    /// # Safety
    /// Caller must be the exclusive execution context for `vcpu_id`.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn comm_page_mut(&self, id: VcpuId) -> &mut VcpuCommPage {
        unsafe { &mut *self.comm_pages[id as usize].0.get() }
    }

    /// Handle one slow-path VM exit recorded in `comm`, populating `comm.entry` and `comm.dirty_regs`.
    pub fn handle_vcpu_exit(&self, id: VcpuId, comm: &mut VcpuCommPage) -> Result<VmAction, Error> {
        let vm_exit = comm.exit.to_exit()?;
        let insn_len = comm.exit.insn_len;
        let vm_entry = match vm_exit {
            VmExit::Io { port, write, size } => {
                let entry = self.memory.handle_io(port, write, size)?;
                if insn_len > 0 {
                    if let VmEntry::Io { data } = entry {
                        match size {
                            1 => {
                                comm.gprs[GPR_RAX] =
                                    (comm.gprs[GPR_RAX] & !0xff) | ((data as u64) & 0xff);
                            }
                            2 => {
                                comm.gprs[GPR_RAX] =
                                    (comm.gprs[GPR_RAX] & !0xffff) | ((data as u64) & 0xffff);
                            }
                            _ => {
                                comm.gprs[GPR_RAX] = data as u64;
                            }
                        }
                        comm.dirty_regs |= SYNC_REG_GPRS;
                    }
                    if !matches!(entry, VmEntry::Shutdown | VmEntry::Reboot) {
                        comm.rip = comm.rip.wrapping_add(insn_len as u64);
                        comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
                    }
                }
                entry
            }
            VmExit::Mmio { gpa, write, size } => self.memory.handle_mmio(gpa, write, size)?,
            VmExit::MmioFault {
                gpa,
                gva,
                is_write,
                insn_len,
                insn_bytes,
            } => insn_decode::emulate_mmio_fault(
                &self.memory,
                comm,
                gpa,
                gva,
                is_write,
                insn_len,
                &insn_bytes,
            )?,
            VmExit::Cpuid { func, index } => {
                let (eax, ebx, ecx, edx) = self.arch.lookup_cpuid(id, func, index);
                comm.gprs[GPR_RAX] = eax as u64;
                comm.gprs[GPR_RBX] = ebx as u64;
                comm.gprs[GPR_RCX] = ecx as u64;
                comm.gprs[GPR_RDX] = edx as u64;
                let step = if insn_len > 0 { insn_len as u64 } else { 2 };
                comm.rip = comm.rip.wrapping_add(step);
                comm.dirty_regs |= SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS;
                VmEntry::None
            }
            VmExit::MsrRead { msr } => {
                let val = if msr == msr::IA32_EFER {
                    comm.efer
                } else {
                    self.arch.read_msr(id, msr)
                };
                if insn_len > 0 {
                    comm.gprs[GPR_RAX] = (val as u32) as u64;
                    comm.gprs[GPR_RDX] = (val >> 32) & 0xffff_ffff;
                    comm.rip = comm.rip.wrapping_add(insn_len as u64);
                    comm.dirty_regs |= SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS;
                }
                VmEntry::Msr { data: val, error: 0 }
            }
            VmExit::MsrWrite { msr, val } => {
                if msr == msr::IA32_EFER {
                    comm.efer = val;
                    comm.dirty_regs |= SYNC_REG_SREGS;
                } else {
                    self.arch.write_msr(id, msr, val);
                }
                if insn_len > 0 {
                    comm.rip = comm.rip.wrapping_add(insn_len as u64);
                    comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
                }
                VmEntry::Msr { data: 0, error: 0 }
            }
            VmExit::Shutdown => {
                log::info!("vcpu {id} requested shutdown");
                comm.entry = RawVmEntry::from_entry(VmEntry::Shutdown);
                return Ok(VmAction::Shutdown);
            }
            VmExit::Reboot => {
                comm.entry = RawVmEntry::from_entry(VmEntry::Reboot);
                return Ok(VmAction::Reboot);
            }
            VmExit::Interrupted => {
                let state = self.state.load(Ordering::Acquire);
                match state {
                    STATE_SHUTDOWN => VmEntry::Shutdown,
                    STATE_REBOOT_PENDING => VmEntry::Reboot,
                    _ => VmEntry::None,
                }
            }
        };

        comm.entry = RawVmEntry::from_entry(vm_entry);
        Ok(VmAction::Continue)
    }

    fn vcpu_loop(&self, id: VcpuId) -> Result<bool, Error> {
        let comm = unsafe { self.comm_page_mut(id) };
        *comm = VcpuCommPage::default();
        loop {
            self.hv.vcpu_run(id, comm)?;
            match self.handle_vcpu_exit(id, comm)? {
                VmAction::Continue => {}
                VmAction::Shutdown => break Ok(false),
                VmAction::Reboot => break Ok(true),
            }
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
            drop(cvar.wait(count));
        }
    }

    pub fn notify_shutdown(&self) {
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_SHUTDOWN,
            ..Default::default()
        };
        let _ = self.bridge.send_io_cmd(&entry);
    }

    fn run_vcpu_inner(
        &self,
        id: VcpuId,
        event_tx: &Sender<u32>,
        boot_rx: &Receiver<()>,
    ) -> Result<(), Error> {
        self.init_vcpu(id)?;
        event_tx.send(id).unwrap();
        boot_rx.recv().unwrap();
        loop {
            let vcpus = self.vcpus.read();
            let setup_res = if id == 0 && self.state.load(Ordering::Acquire) == STATE_RUNNING {
                (|| -> Result<()> {
                    self.create_ram()?;
                    if let Some(ioapic) = &self.ioapic {
                        ioapic.reset();
                        self.memory.add_region(
                            AddrOpt::Fixed(IOAPIC_START as u64),
                            Arc::new(MemRegion::with_emulated(
                                ioapic.clone(),
                                MemRegionType::Reserved,
                            )),
                        )?;
                    }
                    for (port, dev) in self.io_devs.read().iter() {
                        self.memory.add_io_dev(Some(*port), dev.clone())?;
                    }
                    self.add_pci_devs()?;
                    let init_state = self.load_payload()?;
                    self.init_boot_vcpu(id, &init_state)?;
                    self.create_firmware_data(&init_state)?;
                    Ok(())
                })()
            } else {
                Ok(())
            };
            if setup_res.is_err() {
                self.state.store(STATE_SHUTDOWN, Ordering::Release);
            }
            self.sync_vcpus(&vcpus);
            drop(vcpus);
            setup_res?;
            if self.state.load(Ordering::Acquire) != STATE_RUNNING {
                return Ok(());
            }

            let reboot = self.vcpu_loop(id)?;

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
                            log::info!("vcpu{id} to kick {vcpu_id}");
                            let _ = self.hv.vcpu_kick(vcpu_id as u32);
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
            self.sync_vcpus(&vcpus);
        }
    }

    pub fn run_vcpu(
        &self,
        id: VcpuId,
        event_tx: Sender<u32>,
        boot_rx: Receiver<()>,
    ) -> Result<(), Error> {
        let ret = self.run_vcpu_inner(id, &event_tx, &boot_rx);
        self.state.store(STATE_SHUTDOWN, Ordering::Release);
        self.notify_shutdown();
        event_tx.send(id).unwrap();
        ret
    }

    pub fn run_serial_rx_loop(&self) -> Result<()> {
        let mut entry = IoToCoreEntry::default();
        loop {
            if self.state.load(Ordering::Acquire) == STATE_SHUTDOWN {
                break Ok(());
            }
            let got = self.bridge.recv_io_cmd(true, &mut entry)?;
            if !got {
                break Ok(());
            }
            match entry.msg_type {
                IO_MSG_SERIAL_RX => {
                    let len = (entry.queue_index as usize).min(entry.data.len());
                    if len > 0
                        && let Some(com1) = self.com1.read().as_ref()
                    {
                        com1.push_rx(&entry.data[..len]);
                    }
                }
                IO_MSG_REQUEST_SHUTDOWN => {
                    break Ok(());
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::host::abi::{
        GPR_RAX, GPR_RDI, GPR_RDX, IoToCoreEntry, RawSegReg, RawVmExit, ShmBootInfo,
        ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig, VcpuCommPage,
    };
    use crate::host::test::FakeHost;
    use crate::host::{HvResult, PayloadKind, VmAction, VmEntry, VmExit, VmmCoreBridge};
    use crate::hw::layout::IOAPIC_START;
    use crate::hw::msr::Efer;
    use crate::hw::reg::{Cr0, Cr4, Rflags};
    use crate::mem::{AddrOpt, MemRegion, MemRegionType};
    use crate::vm::Machine;

    use super::BoardConfig;

    struct DummyBridge;
    impl VmmCoreBridge for DummyBridge {
        fn boot_info(
            &self,
            _out_info: &mut ShmBootInfo,
            _out_devs: &mut [ShmVirtioDeviceSpec],
        ) -> HvResult<usize> {
            Ok(0)
        }
        fn read_payload(&self, _kind: PayloadKind, _offset: u64, _dst: &mut [u8]) -> HvResult<usize> {
            Ok(0)
        }
        fn configure_device_queues(&self, _dev: u32, _queues: &[ShmVirtioQueueConfig]) -> HvResult<()> {
            Ok(())
        }
        fn update_irq_route(&self, _dev: u32, _routing: &ShmDeviceMsixRouting) -> HvResult<()> {
            Ok(())
        }
        fn send_io_cmd(&self, _entry: &crate::host::abi::CoreToIoEntry) -> HvResult<()> {
            Ok(())
        }
        fn recv_io_cmd(&self, _blocking: bool, _out: &mut IoToCoreEntry) -> HvResult<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_handle_vcpu_exit_mmio_fault_ioapic_and_msrs() {
        let hv = Arc::new(FakeHost::default());
        let bridge = Arc::new(DummyBridge);
        let machine = Machine::new(
            hv,
            bridge,
            BoardConfig {
                mem_size: 16 << 20,
                num_cpu: 2,
            },
        )
        .unwrap();
        let board = &machine.board;
        let ioapic = board.ioapic.as_ref().unwrap().clone();
        board
            .memory
            .add_region(
                AddrOpt::Fixed(IOAPIC_START as u64),
                Arc::new(MemRegion::with_emulated(ioapic, MemRegionType::Reserved)),
            )
            .unwrap();

        let mut comm = VcpuCommPage {
            rip: 0x1000,
            rflags: Rflags::RESERVED_1.bits() as u64,
            cr0: (Cr0::PE | Cr0::PG).bits() as u64,
            cr4: Cr4::PAE.bits() as u64,
            efer: (Efer::LME | Efer::LMA).bits() as u64,
            cs: RawSegReg {
                base: 0,
                limit: 0xffff_ffff,
                access: 0xa09b,
                selector: 0x10,
                _pad: [0; 6],
            },
            ..Default::default()
        };

        // 1. Write IOREGSEL = 0x01 (IOAPICVER) via `mov byte [rdi], 0x01` (0xc6 0x07 0x01)
        let mut insn = [0u8; 15];
        insn[..3].copy_from_slice(&[0xc6, 0x07, 0x01]);
        comm.gprs[GPR_RDI] = IOAPIC_START as u64;
        comm.exit = RawVmExit::from_exit(VmExit::MmioFault {
            gpa: IOAPIC_START as u64,
            gva: None,
            is_write: true,
            insn_len: 3,
            insn_bytes: insn,
        });
        assert_eq!(board.handle_vcpu_exit(0, &mut comm).unwrap(), VmAction::Continue);
        assert_eq!(comm.rip, 0x1003);

        // 2. Read IOWIN (`0xfec0_0010`) via `mov eax, dword [rdi + 0x10]` (0x8b 0x47 0x10)
        let mut insn2 = [0u8; 15];
        insn2[..3].copy_from_slice(&[0x8b, 0x47, 0x10]);
        comm.exit = RawVmExit::from_exit(VmExit::MmioFault {
            gpa: (IOAPIC_START + 0x10) as u64,
            gva: None,
            is_write: false,
            insn_len: 3,
            insn_bytes: insn2,
        });
        assert_eq!(board.handle_vcpu_exit(0, &mut comm).unwrap(), VmAction::Continue);
        assert_eq!(comm.gprs[GPR_RAX], 0x0017_0020);
        assert_eq!(comm.rip, 0x1006);

        // 3. MSR write + read (`IA32_TSC_AUX` = 0xc000_0103) with raw Ring-0 `insn_len = 2`
        comm.exit = RawVmExit::from_exit(VmExit::MsrWrite {
            msr: 0xc000_0103,
            val: 0x0000_0002_0000_0007,
        });
        comm.exit.insn_len = 2;
        assert_eq!(board.handle_vcpu_exit(1, &mut comm).unwrap(), VmAction::Continue);
        assert_eq!(comm.rip, 0x1008);

        comm.exit = RawVmExit::from_exit(VmExit::MsrRead { msr: 0xc000_0103 });
        comm.exit.insn_len = 2;
        assert_eq!(board.handle_vcpu_exit(1, &mut comm).unwrap(), VmAction::Continue);
        assert_eq!(comm.gprs[GPR_RAX], 7);
        assert_eq!(comm.gprs[GPR_RDX], 2);
        assert_eq!(comm.rip, 0x100a);
        assert_eq!(
            comm.entry.to_entry(),
            VmEntry::Msr {
                data: 0x0000_0002_0000_0007,
                error: 0
            }
        );
    }
}
