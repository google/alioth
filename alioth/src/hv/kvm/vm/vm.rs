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

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::thread::JoinHandleExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, SIGRTMIN, eventfd, write};
use parking_lot::{Mutex, RwLock};
use snafu::ResultExt;

#[cfg(target_arch = "x86_64")]
use crate::arch::sev::{SevPolicy, SnpPageType, SnpPolicy};
use crate::ffi;
use crate::hv::kvm::vcpu::{KvmRunBlock, KvmVcpu};
use crate::hv::kvm::{KvmError, kvm_error};
use crate::hv::{
    Error, IoeventFd, IoeventFdRegistry, IrqFd, IrqSender, MemMapOption, MsiSender, Result, Vm,
    VmMemory, error,
};
#[cfg(target_arch = "x86_64")]
use crate::sys::kvm::KVM_IRQCHIP_IOAPIC;
#[cfg(target_arch = "aarch64")]
use crate::sys::kvm::KvmMsiFlag;
use crate::sys::kvm::{
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KvmCap, KvmEncRegion, KvmIoEventFd,
    KvmIoEventFdFlag, KvmIrqRouting, KvmIrqRoutingEntry, KvmIrqRoutingIrqchip, KvmIrqRoutingMsi,
    KvmIrqfd, KvmIrqfdFlag, KvmMemFlag, KvmMemoryAttribute, KvmMemoryAttributes, KvmMsi,
    KvmUserspaceMemoryRegion, KvmUserspaceMemoryRegion2, kvm_check_extension, kvm_create_vcpu,
    kvm_ioeventfd, kvm_irqfd, kvm_memory_encrypt_reg_region, kvm_memory_encrypt_unreg_region,
    kvm_set_gsi_routing, kvm_set_memory_attributes, kvm_set_user_memory_region,
    kvm_set_user_memory_region2, kvm_signal_msi,
};

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::VmArch;

#[derive(Debug)]
pub(super) struct VmInner {
    pub(super) fd: OwnedFd,
    pub(super) memfd: Option<OwnedFd>,
    pub(super) ioeventfds: Mutex<HashMap<i32, KvmIoEventFd>>,
    pub(super) msi_table: RwLock<HashMap<u32, KvmMsiEntryData>>,
    pub(super) next_msi_gsi: AtomicU32,
    pub(super) pin_map: AtomicU32,
    #[cfg(target_arch = "x86_64")]
    pub(super) arch: VmArch,
}

impl VmInner {
    fn update_routing_table(&self, table: &HashMap<u32, KvmMsiEntryData>) -> Result<(), KvmError> {
        let mut entries = [KvmIrqRoutingEntry::default(); MAX_GSI_ROUTES];
        let mut index = 0;
        let pin_map = self.pin_map.load(Ordering::Acquire);
        #[cfg(target_arch = "x86_64")]
        let (irqchip, max_pin) = (KVM_IRQCHIP_IOAPIC, 24);
        #[cfg(target_arch = "aarch64")]
        let (irqchip, max_pin) = (0, 32);
        for pin in 0..max_pin {
            if pin_map & (1 << pin) == 0 {
                continue;
            }
            entries[index].gsi = pin;
            entries[index].type_ = KVM_IRQ_ROUTING_IRQCHIP;
            entries[index].routing.irqchip = KvmIrqRoutingIrqchip { irqchip, pin };
            index += 1;
        }
        for (gsi, entry) in table.iter() {
            if entry.masked {
                continue;
            }
            entries[index].gsi = *gsi;
            entries[index].type_ = KVM_IRQ_ROUTING_MSI;
            #[cfg(target_arch = "aarch64")]
            {
                entries[index].flags = KvmMsiFlag::VALID_DEVID;
            }
            entries[index].routing.msi = KvmIrqRoutingMsi {
                address_hi: entry.addr_hi,
                address_lo: entry.addr_lo,
                data: entry.data,
                #[cfg(target_arch = "aarch64")]
                devid: entry.devid,
                #[cfg(not(target_arch = "aarch64"))]
                devid: 0,
            };
            index += 1;
        }
        let irq_routing = KvmIrqRouting {
            nr: index as u32,
            _flags: 0,
            entries,
        };
        log::trace!("{self}: updating GSI routing table to {irq_routing:#x?}");
        unsafe { kvm_set_gsi_routing(&self.fd, &irq_routing) }.context(kvm_error::GsiRouting)?;
        Ok(())
    }

    pub fn check_extension(&self, id: KvmCap) -> Result<i32, Error> {
        let ret = unsafe { kvm_check_extension(&self.fd, id) };
        match ret {
            Ok(num) => Ok(num),
            Err(_) => error::Capability {
                cap: "KVM_CAP_CHECK_EXTENSION_VM",
            }
            .fail(),
        }
    }
}

impl Display for VmInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "kvm-{}", self.fd.as_raw_fd())
    }
}

pub struct KvmVm {
    pub(super) vm: Arc<VmInner>,
    pub(super) vcpu_mmap_size: usize,
    pub(super) memory_created: bool,
}

type MemSlots = (u32, HashMap<(u64, u64), u32>);

#[derive(Debug)]
pub struct KvmMemory {
    slots: Mutex<MemSlots>,
    vm: Arc<VmInner>,
}

impl KvmMemory {
    pub(super) fn new(vm: Arc<VmInner>) -> Self {
        KvmMemory {
            slots: Mutex::new((0, HashMap::new())),
            vm,
        }
    }

    fn unmap(&self, slot: u32, gpa: u64, size: u64) -> Result<()> {
        let flags = KvmMemFlag::empty();
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa,
            memory_size: 0,
            userspace_addr: 0,
            flags,
        };
        unsafe { kvm_set_user_memory_region(&self.vm.fd, &region) }
            .context(error::GuestUnmap { gpa, size })?;
        log::trace!(
            "{}: slot-{slot}: unmapped: {gpa:#018x}, size={size:#x}",
            self.vm
        );
        Ok(())
    }
}

impl VmMemory for KvmMemory {
    fn mem_map(&self, gpa: u64, size: u64, hva: usize, option: MemMapOption) -> Result<(), Error> {
        let mut flags = KvmMemFlag::empty();
        if !option.read || !option.exec {
            return kvm_error::MmapOption { option }.fail()?;
        }
        if !option.write {
            flags |= KvmMemFlag::READONLY;
        }
        if option.log_dirty {
            flags |= KvmMemFlag::LOG_DIRTY_PAGES;
        }
        let (slot_id, slots) = &mut *self.slots.lock();
        if let Some(memfd) = &self.vm.memfd {
            flags |= KvmMemFlag::GUEST_MEMFD;
            let region = KvmUserspaceMemoryRegion2 {
                slot: *slot_id,
                guest_phys_addr: gpa as _,
                memory_size: size as _,
                userspace_addr: hva as _,
                flags,
                guest_memfd: memfd.as_raw_fd() as _,
                guest_memfd_offset: gpa,
                ..Default::default()
            };
            unsafe { kvm_set_user_memory_region2(&self.vm.fd, &region) }
        } else {
            let region = KvmUserspaceMemoryRegion {
                slot: *slot_id,
                guest_phys_addr: gpa as _,
                memory_size: size as _,
                userspace_addr: hva as _,
                flags,
            };
            unsafe { kvm_set_user_memory_region(&self.vm.fd, &region) }
        }
        .context(error::GuestMap { hva, gpa, size })?;
        slots.insert((gpa, size), *slot_id);
        log::trace!(
            "{}: slot-{slot_id}: mapped: {gpa:#018x} -> {hva:#018x}, size = {size:#x}",
            self.vm
        );
        *slot_id += 1;
        Ok(())
    }

    fn unmap(&self, gpa: u64, size: u64) -> Result<(), Error> {
        let (_, slots) = &mut *self.slots.lock();
        let Some(slot) = slots.remove(&(gpa, size)) else {
            return Err(ErrorKind::NotFound.into()).context(error::GuestUnmap { gpa, size });
        };
        self.unmap(slot, gpa, size)
    }

    fn register_encrypted_range(&self, range: &[u8]) -> Result<()> {
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_reg_region(&self.vm.fd, &region) }
            .context(error::EncryptedRegion)?;
        Ok(())
    }

    fn deregister_encrypted_range(&self, range: &[u8]) -> Result<()> {
        let region = KvmEncRegion {
            addr: range.as_ptr() as u64,
            size: range.len() as u64,
        };
        unsafe { kvm_memory_encrypt_unreg_region(&self.vm.fd, &region) }
            .context(error::EncryptedRegion)?;
        Ok(())
    }

    fn mark_private_memory(&self, gpa: u64, size: u64, private: bool) -> Result<()> {
        let attr = KvmMemoryAttributes {
            address: gpa,
            size,
            attributes: if private {
                KvmMemoryAttribute::PRIVATE
            } else {
                KvmMemoryAttribute::empty()
            },
            flags: 0,
        };
        unsafe { kvm_set_memory_attributes(&self.vm.fd, &attr) }.context(error::EncryptedRegion)?;
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        let (slot_id, slots) = &mut *self.slots.lock();
        for ((gpa, size), slot) in slots.drain() {
            self.unmap(slot, gpa, size)?;
        }
        *slot_id = 0;
        Ok(())
    }
}

#[derive(Debug)]
pub struct KvmIrqSender {
    pin: u8,
    vm: Arc<VmInner>,
    event_fd: OwnedFd,
}

impl Drop for KvmIrqSender {
    fn drop(&mut self) {
        let pin_flag = 1 << (self.pin as u32);
        self.vm.pin_map.fetch_and(!pin_flag, Ordering::AcqRel);
        let request = KvmIrqfd {
            fd: self.event_fd.as_raw_fd() as u32,
            gsi: self.pin as u32,
            flags: KvmIrqfdFlag::DEASSIGN,
            ..Default::default()
        };
        if let Err(e) = unsafe { kvm_irqfd(&self.vm.fd, &request) } {
            log::error!(
                "{}: removing irqfd {:#x}: {e}",
                self.vm,
                self.event_fd.as_raw_fd(),
            )
        }
    }
}

impl IrqSender for KvmIrqSender {
    fn send(&self) -> Result<(), Error> {
        ffi!(unsafe { write(self.event_fd.as_raw_fd(), &1u64 as *const _ as _, 8) })
            .context(error::SendInterrupt)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) struct KvmMsiEntryData {
    addr_lo: u32,
    addr_hi: u32,
    data: u32,
    masked: bool,
    dirty: bool,
    #[cfg(target_arch = "aarch64")]
    devid: u32,
}

#[derive(Debug)]
pub struct KvmIrqFd {
    event_fd: OwnedFd,
    vm: Arc<VmInner>,
    gsi: u32,
}

impl Drop for KvmIrqFd {
    fn drop(&mut self) {
        let mut table = self.vm.msi_table.write();
        let Some(entry) = table.remove(&self.gsi) else {
            log::error!(
                "{}: cannot find gsi {:#x} in the gsi table",
                self.vm,
                self.gsi,
            );
            return;
        };
        if entry.masked {
            return;
        }
        if let Err(e) = self.deassign_irqfd() {
            log::error!(
                "{}: removing irqfd {:#x}: {e}",
                self.vm,
                self.event_fd.as_raw_fd(),
            )
        }
    }
}

impl AsFd for KvmIrqFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.event_fd.as_fd()
    }
}

impl KvmIrqFd {
    fn assign_irqfd(&self) -> Result<()> {
        let request = KvmIrqfd {
            fd: self.event_fd.as_raw_fd() as u32,
            gsi: self.gsi,
            ..Default::default()
        };
        unsafe { kvm_irqfd(&self.vm.fd, &request) }.context(error::IrqFd)?;
        log::debug!(
            "{}: assigned: gsi {:#x} -> irqfd {:#x}",
            self.vm,
            self.gsi,
            self.event_fd.as_raw_fd()
        );
        Ok(())
    }

    fn deassign_irqfd(&self) -> Result<()> {
        let request = KvmIrqfd {
            fd: self.event_fd.as_raw_fd() as u32,
            gsi: self.gsi,
            flags: KvmIrqfdFlag::DEASSIGN,
            ..Default::default()
        };
        unsafe { kvm_irqfd(&self.vm.fd, &request) }.context(error::IrqFd)?;
        log::debug!(
            "{}: de-assigned: gsi {:#x} -> irqfd {:#x}",
            self.vm,
            self.gsi,
            self.event_fd.as_raw_fd()
        );
        Ok(())
    }
}

macro_rules! impl_irqfd_method {
    ($field:ident, $get:ident, $set:ident) => {
        fn $get(&self) -> u32 {
            let table = self.vm.msi_table.read();
            let Some(entry) = table.get(&self.gsi) else {
                unreachable!("cannot find gsi {}", self.gsi);
            };
            entry.$field
        }
        fn $set(&self, val: u32) -> Result<()> {
            let mut table = self.vm.msi_table.write();
            let Some(entry) = table.get_mut(&self.gsi) else {
                unreachable!("cannot find gsi {}", self.gsi);
            };
            if entry.$field == val {
                return Ok(());
            }
            entry.$field = val;

            if !entry.masked {
                self.vm.update_routing_table(&table)?;
            } else {
                entry.dirty = true;
            }
            Ok(())
        }
    };
}

impl IrqFd for KvmIrqFd {
    impl_irqfd_method!(addr_lo, get_addr_lo, set_addr_lo);

    impl_irqfd_method!(addr_hi, get_addr_hi, set_addr_hi);

    impl_irqfd_method!(data, get_data, set_data);

    fn get_masked(&self) -> bool {
        let table = self.vm.msi_table.read();
        let Some(entry) = table.get(&self.gsi) else {
            unreachable!("{}: cannot find gsi {:#x}", self.vm, self.gsi);
        };
        entry.masked
    }

    fn set_masked(&self, val: bool) -> Result<bool> {
        let mut table = self.vm.msi_table.write();
        let Some(entry) = table.get_mut(&self.gsi) else {
            unreachable!("{}: cannot find gsi {:#x}", self.vm, self.gsi);
        };
        if entry.masked == val {
            return Ok(false);
        }
        entry.masked = val;
        if !val {
            if entry.dirty {
                self.vm.update_routing_table(&table)?;
            }
            self.assign_irqfd()?;
        } else {
            self.deassign_irqfd()?;
        }
        Ok(true)
    }
}

const MAX_GSI_ROUTES: usize = 256;

#[derive(Debug)]
pub struct KvmMsiSender {
    vm: Arc<VmInner>,
    #[cfg(target_arch = "aarch64")]
    devid: u32,
}

impl MsiSender for KvmMsiSender {
    type IrqFd = KvmIrqFd;

    fn send(&self, addr: u64, data: u32) -> Result<()> {
        let kvm_msi = KvmMsi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            #[cfg(target_arch = "aarch64")]
            devid: self.devid,
            #[cfg(target_arch = "aarch64")]
            flags: KvmMsiFlag::VALID_DEVID,
            ..Default::default()
        };
        unsafe { kvm_signal_msi(&self.vm.fd, &kvm_msi) }.context(error::SendInterrupt)?;
        Ok(())
    }

    fn create_irqfd(&self) -> Result<Self::IrqFd> {
        let event_fd = unsafe {
            OwnedFd::from_raw_fd(
                ffi!(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)).context(error::IrqFd)?,
            )
        };
        let mut table = self.vm.msi_table.write();
        let mut allocated_gsi = None;
        for _ in 0..(MAX_GSI_ROUTES - 24) {
            let gsi = self.vm.next_msi_gsi.fetch_add(1, Ordering::AcqRel)
                % (MAX_GSI_ROUTES as u32 - 24)
                + 24;
            let new_entry = KvmMsiEntryData {
                #[cfg(target_arch = "aarch64")]
                devid: self.devid,
                masked: true,
                ..Default::default()
            };
            if let Some(e) = table.insert(gsi, new_entry) {
                table.insert(gsi, e);
            } else {
                allocated_gsi = Some(gsi);
                break;
            }
        }
        let Some(gsi) = allocated_gsi else {
            return kvm_error::AllocateGsi.fail()?;
        };
        log::debug!(
            "{}: allocated: gsi {gsi:#x} -> irqfd {:#x}",
            self.vm,
            event_fd.as_raw_fd()
        );
        let entry = KvmIrqFd {
            vm: self.vm.clone(),
            event_fd,
            gsi,
        };
        Ok(entry)
    }
}

#[derive(Debug)]
pub struct KvmIoeventFd {
    fd: OwnedFd,
}

impl AsFd for KvmIoeventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl IoeventFd for KvmIoeventFd {}

#[derive(Debug)]
pub struct KvmIoeventFdRegistry {
    vm: Arc<VmInner>,
}

impl IoeventFdRegistry for KvmIoeventFdRegistry {
    type IoeventFd = KvmIoeventFd;

    fn create(&self) -> Result<Self::IoeventFd> {
        let fd =
            ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) }).context(error::IoeventFd)?;
        Ok(KvmIoeventFd {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn register(&self, fd: &Self::IoeventFd, gpa: u64, len: u8, data: Option<u64>) -> Result<()> {
        let mut request = KvmIoEventFd {
            addr: gpa,
            len: len as u32,
            fd: fd.as_fd().as_raw_fd(),
            ..Default::default()
        };
        if let Some(data) = data {
            request.datamatch = data;
            request.flags |= KvmIoEventFdFlag::DATA_MATCH;
        }
        unsafe { kvm_ioeventfd(&self.vm.fd, &request) }.context(error::IoeventFd)?;
        let mut fds = self.vm.ioeventfds.lock();
        fds.insert(request.fd, request);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn register_port(
        &self,
        _fd: &Self::IoeventFd,
        _port: u16,
        _len: u8,
        _data: Option<u64>,
    ) -> Result<()> {
        unimplemented!()
    }

    fn deregister(&self, fd: &Self::IoeventFd) -> Result<()> {
        let mut fds = self.vm.ioeventfds.lock();
        if let Some(mut request) = fds.remove(&fd.as_fd().as_raw_fd()) {
            request.flags |= KvmIoEventFdFlag::DEASSIGN;
            unsafe { kvm_ioeventfd(&self.vm.fd, &request) }.context(error::IoeventFd)?;
        }
        Ok(())
    }
}

impl Vm for KvmVm {
    #[cfg(target_arch = "aarch64")]
    type GicV2 = aarch64::KvmGicV2;
    #[cfg(target_arch = "aarch64")]
    type GicV2m = aarch64::KvmGicV2m;
    #[cfg(target_arch = "aarch64")]
    type GicV3 = aarch64::KvmGicV3;
    type IoeventFdRegistry = KvmIoeventFdRegistry;
    type IrqSender = KvmIrqSender;
    #[cfg(target_arch = "aarch64")]
    type Its = aarch64::KvmIts;
    type Memory = KvmMemory;
    type MsiSender = KvmMsiSender;
    type Vcpu = KvmVcpu;

    fn create_vcpu(&self, id: u32) -> Result<Self::Vcpu, Error> {
        let vcpu_fd = unsafe { kvm_create_vcpu(&self.vm.fd, id) }.context(error::CreateVcpu)?;
        let kvm_run = unsafe { KvmRunBlock::new(vcpu_fd, self.vcpu_mmap_size) }?;
        Ok(KvmVcpu {
            fd: unsafe { OwnedFd::from_raw_fd(vcpu_fd) },
            kvm_run,
            vm: self.vm.clone(),
            io_index: 0,
        })
    }

    fn stop_vcpu<T>(&self, _id: u32, handle: &JoinHandle<T>) -> Result<(), Error> {
        ffi!(unsafe { libc::pthread_kill(handle.as_pthread_t() as _, SIGRTMIN()) })
            .context(error::StopVcpu)?;
        Ok(())
    }

    fn create_vm_memory(&mut self) -> Result<Self::Memory, Error> {
        if self.memory_created {
            error::MemoryCreated.fail()
        } else {
            let kvm_memory = KvmMemory::new(self.vm.clone());
            self.memory_created = true;
            Ok(kvm_memory)
        }
    }

    fn create_irq_sender(&self, pin: u8) -> Result<Self::IrqSender, Error> {
        let pin_flag = 1 << pin;
        if self.vm.pin_map.fetch_or(pin_flag, Ordering::AcqRel) & pin_flag == pin_flag {
            return Err(std::io::ErrorKind::AlreadyExists.into()).context(error::CreateIrq { pin });
        }
        if self.vm.check_extension(KvmCap::IRQFD)? == 0 {
            return error::Capability {
                cap: "KVM_CAP_IRQFD",
            }
            .fail();
        }
        let event_fd = ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) })
            .context(error::CreateIrq { pin })?;
        let request = KvmIrqfd {
            fd: event_fd as u32,
            gsi: pin as u32,
            ..Default::default()
        };
        self.vm.update_routing_table(&self.vm.msi_table.read())?;
        unsafe { kvm_irqfd(&self.vm.fd, &request) }.context(error::CreateIrq { pin })?;
        Ok(KvmIrqSender {
            pin,
            vm: self.vm.clone(),
            event_fd: unsafe { OwnedFd::from_raw_fd(event_fd) },
        })
    }

    fn create_msi_sender(
        &self,
        #[cfg(target_arch = "aarch64")] devid: u32,
    ) -> Result<Self::MsiSender> {
        if self.vm.check_extension(KvmCap::SIGNAL_MSI)? == 0 {
            return error::Capability {
                cap: "KVM_CAP_SIGNAL_MSI",
            }
            .fail();
        }
        Ok(KvmMsiSender {
            vm: self.vm.clone(),
            #[cfg(target_arch = "aarch64")]
            devid,
        })
    }

    fn create_ioeventfd_registry(&self) -> Result<Self::IoeventFdRegistry> {
        Ok(KvmIoeventFdRegistry {
            vm: self.vm.clone(),
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_start(&self, policy: SevPolicy) -> Result<(), Error> {
        self.kvm_sev_launch_start(policy)
    }

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_update_data(&self, range: &mut [u8]) -> Result<(), Error> {
        self.kvm_sev_launch_update_data(range)
    }

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_update_vmsa(&self) -> Result<(), Error> {
        self.kvm_sev_launch_update_vmsa()
    }

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_measure(&self) -> Result<Vec<u8>, Error> {
        self.kvm_sev_launch_measure()
    }

    #[cfg(target_arch = "x86_64")]
    fn sev_launch_finish(&self) -> Result<(), Error> {
        self.kvm_sev_launch_finish()
    }

    #[cfg(target_arch = "x86_64")]
    fn snp_launch_start(&self, policy: SnpPolicy) -> Result<()> {
        self.kvm_snp_launch_start(policy)
    }

    #[cfg(target_arch = "x86_64")]
    fn snp_launch_update(&self, range: &mut [u8], gpa: u64, type_: SnpPageType) -> Result<()> {
        self.kvm_snp_launch_update(range, gpa, type_)
    }

    #[cfg(target_arch = "x86_64")]
    fn snp_launch_finish(&self) -> Result<()> {
        self.kvm_snp_launch_finish()
    }

    #[cfg(target_arch = "aarch64")]
    fn create_gic_v2(&self, distributor_base: u64, cpu_interface_base: u64) -> Result<Self::GicV2> {
        self.kvm_create_gic_v2(distributor_base, cpu_interface_base)
    }

    #[cfg(target_arch = "aarch64")]
    fn create_gic_v2m(&self, _base: u64) -> Result<Self::GicV2m> {
        Err(std::io::ErrorKind::Unsupported.into()).context(error::CreateDevice)
    }

    #[cfg(target_arch = "aarch64")]
    fn create_gic_v3(
        &self,
        distributor_base: u64,
        redistributor_base: u64,
        redistributor_count: u32,
    ) -> Result<Self::GicV3> {
        self.kvm_create_gic_v3(distributor_base, redistributor_base, redistributor_count)
    }

    #[cfg(target_arch = "aarch64")]
    fn create_its(&self, base: u64) -> Result<Self::Its> {
        self.kvm_create_its(base)
    }
}

#[cfg(test)]
mod test {
    use std::ptr::null_mut;

    use assert_matches::assert_matches;
    use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, mmap};

    use super::*;
    use crate::ffi;
    use crate::hv::kvm::KvmConfig;
    use crate::hv::{Hypervisor, Kvm, MemMapOption, VmConfig};

    #[test]
    #[cfg_attr(not(feature = "test-hv"), ignore)]
    fn test_mem_map() {
        let kvm = Kvm::new(KvmConfig::default()).unwrap();
        let vm_config = VmConfig { coco: None };
        let mut vm = kvm.create_vm(&vm_config).unwrap();
        let vm_memory = vm.create_vm_memory().unwrap();

        let prot = PROT_WRITE | PROT_READ | PROT_EXEC;
        let flag = MAP_ANONYMOUS | MAP_PRIVATE;
        let user_mem = ffi!(
            unsafe { mmap(null_mut(), 0x1000, prot, flag, -1, 0,) },
            MAP_FAILED
        )
        .unwrap();
        let option_no_write = MemMapOption {
            read: false,
            write: true,
            exec: true,
            log_dirty: true,
        };
        assert_matches!(
            vm_memory.mem_map(0x0, 0x1000, user_mem as usize, option_no_write),
            Err(Error::KvmErr { .. })
        );
        let option_no_exec = MemMapOption {
            read: false,
            write: true,
            exec: true,
            log_dirty: true,
        };
        assert_matches!(
            vm_memory.mem_map(0x0, 0x1000, user_mem as usize, option_no_exec),
            Err(Error::KvmErr { .. })
        );
        let option = MemMapOption {
            read: true,
            write: false,
            exec: true,
            log_dirty: true,
        };
        vm_memory
            .mem_map(0x0, 0x1000, user_mem as usize, option)
            .unwrap();
    }
}
