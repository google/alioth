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

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt::{self, Display, Formatter};
use core::mem::size_of;
use core::sync::atomic::{AtomicU8, Ordering};

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
use crate::sync::RwLock;
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

#[derive(Debug)]
pub enum Error {
    Hv(host::Error),
    Memory(mem::Error),
    PciBus(pci::Error),
    Loader(loader::Error),
    Virtio(virtio::Error),
    AcpiTooLong,
    MemoryTooSmall,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hv(e) => write!(f, "hypervisor: {e}"),
            Self::Memory(e) => write!(f, "memory: {e}"),
            Self::PciBus(e) => write!(f, "PCI bus: {e}"),
            Self::Loader(e) => write!(f, "loader: {e}"),
            Self::Virtio(e) => write!(f, "virtio: {e}"),
            Self::AcpiTooLong => f.write_str("ACPI bytes exceed EBDA area"),
            Self::MemoryTooSmall => f.write_str("memory too small"),
        }
    }
}

impl core::error::Error for Error {}

impl From<host::Error> for Error {
    fn from(e: host::Error) -> Self {
        Self::Hv(e)
    }
}

impl From<mem::Error> for Error {
    fn from(e: mem::Error) -> Self {
        Self::Memory(e)
    }
}

impl From<pci::Error> for Error {
    fn from(e: pci::Error) -> Self {
        Self::PciBus(e)
    }
}

impl From<loader::Error> for Error {
    fn from(e: loader::Error) -> Self {
        Self::Loader(e)
    }
}

impl From<virtio::Error> for Error {
    fn from(e: virtio::Error) -> Self {
        Self::Virtio(e)
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub const STATE_CREATED: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_SHUTDOWN: u8 = 2;
pub const STATE_REBOOT_PENDING: u8 = 3;

/// Per-worker disjoint Wasm shadow stack size (64 KiB, 16-byte aligned).
pub const WORKER_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct StackAlign16(pub [u8; 16]);

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

pub struct Board {
    pub hv: Arc<dyn VmmHostCore>,
    pub bridge: Arc<dyn VmmCoreBridge>,
    pub memory: Memory,
    pub comm_pages: Box<[VcpuCommSlot]>,
    pub worker_stacks: Box<[StackAlign16]>,
    pub arch: ArchBoard,
    pub config: BoardConfig,
    pub state: AtomicU8,
    pub payload: RwLock<Option<Payload>>,
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

    /// Number of preallocated worker shadow stacks (`0..num_cpu` for vCPUs, `num_cpu` for bridge RX).
    pub fn num_worker_stacks(&self) -> u32 {
        (self.worker_stacks.len() / (WORKER_STACK_SIZE / size_of::<StackAlign16>())) as u32
    }

    /// 16-byte-aligned top address of worker shadow stack `slot` (`[base .. top]`).
    pub fn worker_stack_top(&self, slot: u32) -> Option<usize> {
        if slot >= self.num_worker_stacks() {
            return None;
        }
        let base = self.worker_stacks.as_ptr() as usize;
        Some(base + (slot as usize + 1) * WORKER_STACK_SIZE)
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

    /// Initialize Guest RAM, chipset/PCI devices, kernel payload, ACPI tables, and BSP/AP vCPUs.
    pub fn init_vm(&self) -> Result<()> {
        for id in 0..self.config.num_cpu {
            self.init_vcpu(id)?;
            let comm = unsafe { self.comm_page_mut(id) };
            *comm = VcpuCommPage::default();
        }
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
        if self.config.num_cpu > 0 {
            self.init_boot_vcpu(0, &init_state)?;
        }
        self.create_firmware_data(&init_state)?;
        self.state.store(STATE_RUNNING, Ordering::Release);
        Ok(())
    }

    /// Reset all emulated hardware, unmap Guest RAM/BARs, and re-initialize the VM for reboot.
    pub fn reset_vm(&self) -> Result<()> {
        self.state.store(STATE_CREATED, Ordering::Release);
        for dev in self.pci_devs.read().iter() {
            dev.dev.reset()?;
        }
        if let Some(com1) = self.com1.read().as_ref() {
            com1.reset();
        }
        self.arch.reset();
        self.memory.reset()?;
        self.init_vm()
    }

    pub fn kick_other_vcpus(&self, except: Option<VcpuId>) {
        for vcpu_id in 0..self.config.num_cpu {
            if Some(vcpu_id) != except {
                log::info!("kicking vcpu {vcpu_id}");
                let _ = self.hv.vcpu_kick(vcpu_id);
            }
        }
    }

    pub fn notify_shutdown(&self) {
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_SHUTDOWN,
            ..Default::default()
        };
        let _ = self.bridge.send_io_cmd(&entry);
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
            VmExit::Shutdown => VmEntry::Shutdown,
            VmExit::Reboot => VmEntry::Reboot,
            VmExit::Interrupted => match self.state.load(Ordering::Acquire) {
                STATE_SHUTDOWN => VmEntry::Shutdown,
                STATE_REBOOT_PENDING => VmEntry::Reboot,
                _ => VmEntry::None,
            },
        };

        comm.entry = RawVmEntry::from_entry(vm_entry);
        match vm_entry {
            VmEntry::Shutdown => {
                log::info!("vcpu {id} requested shutdown");
                Ok(VmAction::Shutdown)
            }
            VmEntry::Reboot => {
                log::info!("vcpu {id} requested reboot");
                Ok(VmAction::Reboot)
            }
            _ => Ok(VmAction::Continue),
        }
    }

    /// Host-driven vCPU exit entrypoint (`vmm_on_vcpu_exit`). Strictly non-blocking.
    pub fn on_vcpu_exit(&self, id: VcpuId) -> Result<VmAction> {
        if id >= self.config.num_cpu {
            return Err(Error::Hv(host::HvError::InvalidParam));
        }
        let comm = unsafe { self.comm_page_mut(id) };
        let action = self.handle_vcpu_exit(id, comm)?;
        match action {
            VmAction::Continue => match self.state.load(Ordering::Acquire) {
                STATE_SHUTDOWN => Ok(VmAction::Shutdown),
                STATE_REBOOT_PENDING => Ok(VmAction::Reboot),
                _ => Ok(VmAction::Continue),
            },
            VmAction::Shutdown => {
                if self.state.swap(STATE_SHUTDOWN, Ordering::AcqRel) != STATE_SHUTDOWN {
                    self.kick_other_vcpus(Some(id));
                    self.notify_shutdown();
                }
                Ok(VmAction::Shutdown)
            }
            VmAction::Reboot => {
                match self.state.compare_exchange(
                    STATE_RUNNING,
                    STATE_REBOOT_PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        self.kick_other_vcpus(Some(id));
                        Ok(VmAction::Reboot)
                    }
                    Err(STATE_SHUTDOWN) => Ok(VmAction::Shutdown),
                    Err(_) => Ok(VmAction::Reboot),
                }
            }
        }
    }

    /// Host-driven `vmm-io -> vmm-core` control channel drain (`vmm_on_bridge_rx`). Strictly non-blocking.
    pub fn on_bridge_rx(&self) -> Result<VmAction> {
        if self.state.load(Ordering::Acquire) == STATE_SHUTDOWN {
            return Ok(VmAction::Shutdown);
        }
        let mut entry = IoToCoreEntry::default();
        while self.bridge.recv_io_cmd(&mut entry)? {
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
                    if self.state.swap(STATE_SHUTDOWN, Ordering::AcqRel) != STATE_SHUTDOWN {
                        self.kick_other_vcpus(None);
                        self.notify_shutdown();
                    }
                    return Ok(VmAction::Shutdown);
                }
                _ => {}
            }
        }
        if self.state.load(Ordering::Acquire) == STATE_SHUTDOWN {
            Ok(VmAction::Shutdown)
        } else {
            Ok(VmAction::Continue)
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use crate::host::abi::{
        CORE_MSG_SHUTDOWN, CoreToIoEntry, GPR_RAX, GPR_RDI, GPR_RDX, IO_MSG_REQUEST_SHUTDOWN,
        IO_MSG_SERIAL_RX, IoToCoreEntry, RawSegReg, RawVmExit, ShmBootInfo, ShmDeviceMsixRouting,
        ShmVirtioDeviceSpec, ShmVirtioQueueConfig, VcpuCommPage,
    };
    use crate::host::test::FakeHost;
    use crate::host::{HvResult, PayloadKind, VmAction, VmEntry, VmExit, VmmCoreBridge};
    use crate::hw::layout::IOAPIC_START;
    use crate::hw::msr::Efer;
    use crate::hw::reg::{Cr0, Cr4, Rflags};
    use crate::mem::{AddrOpt, MemRegion, MemRegionType};
    use crate::sync::Mutex;
    use crate::vm::Machine;

    use super::BoardConfig;

    #[derive(Default)]
    struct DummyBridge {
        rx_queue: Mutex<VecDeque<IoToCoreEntry>>,
        tx_log: Mutex<Vec<CoreToIoEntry>>,
    }

    impl VmmCoreBridge for DummyBridge {
        fn boot_info(
            &self,
            _out_info: &mut ShmBootInfo,
            _out_devs: &mut [ShmVirtioDeviceSpec],
        ) -> HvResult<usize> {
            Ok(0)
        }
        fn read_payload(
            &self,
            _kind: PayloadKind,
            _offset: u64,
            _dst: &mut [u8],
        ) -> HvResult<usize> {
            Ok(0)
        }
        fn configure_device_queues(
            &self,
            _dev: u32,
            _queues: &[ShmVirtioQueueConfig],
        ) -> HvResult<()> {
            Ok(())
        }
        fn update_irq_route(&self, _dev: u32, _routing: &ShmDeviceMsixRouting) -> HvResult<()> {
            Ok(())
        }
        fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()> {
            self.tx_log.lock().push(*entry);
            Ok(())
        }
        fn recv_io_cmd(&self, out: &mut IoToCoreEntry) -> HvResult<bool> {
            if let Some(e) = self.rx_queue.lock().pop_front() {
                *out = e;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    #[test]
    fn test_handle_vcpu_exit_mmio_fault_ioapic_and_msrs() {
        let hv = Arc::new(FakeHost::default());
        let bridge = Arc::new(DummyBridge::default());
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
        assert_eq!(
            board.handle_vcpu_exit(0, &mut comm).unwrap(),
            VmAction::Continue
        );
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
        assert_eq!(
            board.handle_vcpu_exit(0, &mut comm).unwrap(),
            VmAction::Continue
        );
        assert_eq!(comm.gprs[GPR_RAX], 0x0017_0020);
        assert_eq!(comm.rip, 0x1006);

        // 3. MSR write + read (`IA32_TSC_AUX` = 0xc000_0103) with raw Ring-0 `insn_len = 2`
        comm.exit = RawVmExit::from_exit(VmExit::MsrWrite {
            msr: 0xc000_0103,
            val: 0x0000_0002_0000_0007,
        });
        comm.exit.insn_len = 2;
        assert_eq!(
            board.handle_vcpu_exit(1, &mut comm).unwrap(),
            VmAction::Continue
        );
        assert_eq!(comm.rip, 0x1008);

        comm.exit = RawVmExit::from_exit(VmExit::MsrRead { msr: 0xc000_0103 });
        comm.exit.insn_len = 2;
        assert_eq!(
            board.handle_vcpu_exit(1, &mut comm).unwrap(),
            VmAction::Continue
        );
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

    #[test]
    fn test_host_driven_init_bridge_rx_and_acpi_shutdown() {
        let hv = Arc::new(FakeHost::default());
        let bridge = Arc::new(DummyBridge::default());
        let machine = Machine::new(
            hv,
            bridge.clone(),
            BoardConfig {
                mem_size: 16 << 20,
                num_cpu: 2,
            },
        )
        .unwrap();
        machine.add_com1().unwrap();
        machine.init_vm().unwrap();
        let board = &machine.board;

        // Disjoint 16-byte aligned worker stacks for vcpu 0, vcpu 1, and bridge_rx (slot 2).
        let s0 = board.worker_stack_top(0).unwrap();
        let s1 = board.worker_stack_top(1).unwrap();
        let s2 = board.worker_stack_top(2).unwrap();
        assert_eq!(s0 & 15, 0);
        assert_eq!(s1 - s0, super::WORKER_STACK_SIZE);
        assert_eq!(s2 - s1, super::WORKER_STACK_SIZE);
        assert!(board.worker_stack_top(3).is_none());

        // Feed a serial RX byte via `on_bridge_rx` and read it back via `on_vcpu_exit` on port 0x3f8.
        let mut rx = IoToCoreEntry {
            msg_type: IO_MSG_SERIAL_RX,
            queue_index: 1,
            ..Default::default()
        };
        rx.data[0] = b'Z';
        bridge.rx_queue.lock().push_back(rx);
        assert_eq!(board.on_bridge_rx().unwrap(), VmAction::Continue);

        unsafe {
            let comm0 = board.comm_page_mut(0);
            comm0.exit = RawVmExit::from_exit(VmExit::Io {
                port: 0x3f8,
                write: None,
                size: 1,
            });
            comm0.exit.insn_len = 1;
        }
        assert_eq!(board.on_vcpu_exit(0).unwrap(), VmAction::Continue);
        assert_eq!(unsafe { board.comm_page_mut(0).gprs[GPR_RAX] } & 0xff, b'Z' as u64);

        // ACPI S5 sleep write (`outb 0x34, 0x600`) on vcpu 0 immediately returns `VmAction::Shutdown`,
        // sends `CORE_MSG_SHUTDOWN` to `vmm-io`, and causes peer vcpu 1's interrupted exit to return Shutdown.
        unsafe {
            board.comm_page_mut(0).exit = RawVmExit::from_exit(VmExit::Io {
                port: 0x600,
                write: Some(0x34),
                size: 1,
            });
        }
        assert_eq!(board.on_vcpu_exit(0).unwrap(), VmAction::Shutdown);
        assert!(
            bridge
                .tx_log
                .lock()
                .iter()
                .any(|e| e.msg_type == CORE_MSG_SHUTDOWN)
        );

        unsafe {
            board.comm_page_mut(1).exit = RawVmExit::from_exit(VmExit::Interrupted);
        }
        assert_eq!(board.on_vcpu_exit(1).unwrap(), VmAction::Shutdown);

        // Reset VM and verify `IO_MSG_REQUEST_SHUTDOWN` from `vmm-io` also triggers clean shutdown.
        board.reset_vm().unwrap();
        bridge.rx_queue.lock().push_back(IoToCoreEntry {
            msg_type: IO_MSG_REQUEST_SHUTDOWN,
            ..Default::default()
        });
        assert_eq!(board.on_bridge_rx().unwrap(), VmAction::Shutdown);
    }
}
