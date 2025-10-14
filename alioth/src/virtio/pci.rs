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

use std::io::ErrorKind;
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc::Sender;

use alioth_macros::Layout;
use parking_lot::{Mutex, RwLock};
use zerocopy::{FromZeros, Immutable, IntoBytes};

use crate::hv::{self, IoeventFd, IoeventFdRegistry, IrqFd, MsiSender};
use crate::mem::emulated::{Action, Mmio};
use crate::mem::{MemRange, MemRegion, MemRegionCallback, MemRegionEntry};
use crate::pci::cap::{
    MsixCap, MsixCapMmio, MsixCapOffset, MsixMsgCtrl, MsixTableEntry, MsixTableMmio,
    MsixTableMmioEntry, PciCap, PciCapHdr, PciCapId, PciCapList,
};
use crate::pci::config::{
    BAR_MEM32, BAR_MEM64, BAR_PREFETCHABLE, CommonHeader, DeviceHeader, EmulatedConfig, HeaderType,
    PciConfig, PciConfigArea,
};
use crate::pci::{self, Pci, PciBar};
use crate::sync::notifier::Notifier;
use crate::utils::{get_atomic_high32, get_atomic_low32, set_atomic_high32, set_atomic_low32};
use crate::virtio::dev::{Register, StartParam, VirtioDevice, WakeEvent};
use crate::virtio::queue::QueueReg;
use crate::virtio::{DevStatus, DeviceId, IrqSender, Result, error};
use crate::{impl_mmio_for_zerocopy, mem};

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

#[derive(Debug)]
struct VirtioPciMsixVector {
    config: AtomicU16,
    queues: Vec<AtomicU16>,
}

#[derive(Debug)]
pub struct PciIrqSender<S>
where
    S: MsiSender,
{
    msix_vector: VirtioPciMsixVector,
    msix_table: Arc<MsixTableMmio<S::IrqFd>>,
    msi_sender: S,
}

impl<S> PciIrqSender<S>
where
    S: MsiSender,
{
    fn send(&self, vector: u16) {
        let entries = self.msix_table.entries.read();
        let Some(entry) = entries.get(vector as usize) else {
            log::error!("invalid config vector: {vector:x}");
            return;
        };
        if entry.get_masked() {
            log::info!("{vector} is masked");
            return;
        }
        let data = entry.get_data();
        let addr = ((entry.get_addr_hi() as u64) << 32) | (entry.get_addr_lo() as u64);
        if let Err(e) = self.msi_sender.send(addr, data) {
            log::error!("send msi data = {data:#x} to {addr:#x}: {e}")
        } else {
            log::trace!("send msi data = {data:#x} to {addr:#x}: done")
        }
    }

    fn get_irqfd<F, T>(&self, vector: u16, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        let mut entries = self.msix_table.entries.write();
        let Some(entry) = entries.get_mut(vector as usize) else {
            return error::InvalidMsixVector { vector }.fail();
        };
        match &*entry {
            MsixTableMmioEntry::Entry(e) => {
                let irqfd = self.msi_sender.create_irqfd()?;
                irqfd.set_addr_hi(e.addr_hi)?;
                irqfd.set_addr_lo(e.addr_lo)?;
                irqfd.set_data(e.data)?;
                irqfd.set_masked(e.control.masked())?;
                let r = f(irqfd.as_fd())?;
                *entry = MsixTableMmioEntry::IrqFd(irqfd);
                Ok(r)
            }
            MsixTableMmioEntry::IrqFd(fd) => f(fd.as_fd()),
        }
    }
}

impl<S> IrqSender for PciIrqSender<S>
where
    S: MsiSender,
{
    fn config_irq(&self) {
        let vector = self.msix_vector.config.load(Ordering::Acquire);
        if vector != VIRTIO_MSI_NO_VECTOR {
            self.send(vector)
        }
    }

    fn queue_irq(&self, idx: u16) {
        let Some(vector) = self.msix_vector.queues.get(idx as usize) else {
            log::error!("invalid queue index: {idx}");
            return;
        };
        let vector = vector.load(Ordering::Acquire);
        if vector != VIRTIO_MSI_NO_VECTOR {
            self.send(vector);
        }
    }

    fn config_irqfd<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        self.get_irqfd(self.msix_vector.config.load(Ordering::Acquire), f)
    }

    fn queue_irqfd<F, T>(&self, idx: u16, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        let Some(vector) = self.msix_vector.queues.get(idx as usize) else {
            return error::InvalidQueueIndex { index: idx }.fail();
        };
        self.get_irqfd(vector.load(Ordering::Acquire), f)
    }
}

#[repr(C, align(4))]
#[derive(Layout)]
pub struct VirtioCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    config_msix_vector: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_driver_lo: u32,
    queue_driver_hi: u32,
    queue_device_lo: u32,
    queue_device_hi: u32,
    queue_notify_data: u16,
    queue_reset: u16,
}

#[derive(Layout)]
#[repr(C, align(4))]
pub struct VirtioPciRegister {
    common: VirtioCommonCfg,
    isr_status: u32,
    queue_notify: PhantomData<[u32]>,
}

#[derive(Debug)]
pub struct VirtioPciRegisterMmio<M, E>
where
    M: MsiSender,
    E: IoeventFd,
{
    name: Arc<str>,
    reg: Register,
    queues: Arc<[QueueReg]>,
    irq_sender: Arc<PciIrqSender<M>>,
    ioeventfds: Option<Arc<[E]>>,
    event_tx: Sender<WakeEvent<PciIrqSender<M>, E>>,
    notifier: Arc<Notifier>,
}

impl<M, E> VirtioPciRegisterMmio<M, E>
where
    M: MsiSender,
    E: IoeventFd,
{
    fn wake_up_dev(&self, event: WakeEvent<PciIrqSender<M>, E>) {
        let is_start = matches!(event, WakeEvent::Start { .. });
        if let Err(e) = self.event_tx.send(event) {
            log::error!("{}: failed to send event: {e}", self.name);
            return;
        }
        if is_start {
            return;
        }
        if let Err(e) = self.notifier.notify() {
            log::error!("{}: failed to wake up device: {e}", self.name);
        }
    }

    fn reset(&self) {
        let config_msix = &self.irq_sender.msix_vector.config;
        config_msix.store(VIRTIO_MSI_NO_VECTOR, Ordering::Release);
        for q_vector in self.irq_sender.msix_vector.queues.iter() {
            q_vector.store(VIRTIO_MSI_NO_VECTOR, Ordering::Release);
        }
        self.irq_sender.msix_table.reset();
        for q in self.queues.iter() {
            q.enabled.store(false, Ordering::Release);
        }
    }

    fn msix_change_allowed(&self, old: u16) -> bool {
        let entries = self.irq_sender.msix_table.entries.read();
        let Some(entry) = entries.get(old as usize) else {
            return true;
        };
        if let MsixTableMmioEntry::IrqFd(fd) = entry {
            log::error!(
                "{}: MSI-X vector {old:#x} was assigned to irqfd {:#x}",
                self.name,
                fd.as_fd().as_raw_fd(),
            );
            false
        } else {
            true
        }
    }
}

impl<M, E> Mmio for VirtioPciRegisterMmio<M, E>
where
    M: MsiSender,
    E: IoeventFd,
{
    fn size(&self) -> u64 {
        (size_of::<VirtioPciRegister>() + size_of::<u32>() * self.queues.len()) as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let reg = &self.reg;
        let ret = match (offset as usize, size as usize) {
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT => {
                reg.device_feature_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE => {
                let sel = reg.device_feature_sel.load(Ordering::Acquire);
                if let Some(feature) = reg.device_feature.get(sel as usize) {
                    *feature as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT => {
                reg.driver_feature_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE => {
                let sel = reg.driver_feature_sel.load(Ordering::Acquire);
                if let Some(feature) = reg.driver_feature.get(sel as usize) {
                    feature.load(Ordering::Acquire) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR => {
                self.irq_sender.msix_vector.config.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_NUM_QUEUES => self.queues.len() as u64,
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS => reg.status.load(Ordering::Acquire) as u64,
            VirtioCommonCfg::LAYOUT_CONFIG_GENERATION => {
                0 // TODO: support device config change at runtime
            }
            VirtioCommonCfg::LAYOUT_QUEUE_SELECT => reg.queue_sel.load(Ordering::Acquire) as u64,
            VirtioCommonCfg::LAYOUT_QUEUE_SIZE => {
                let q_sel = reg.queue_sel.load(Ordering::Acquire) as usize;
                if let Some(q) = self.queues.get(q_sel) {
                    q.size.load(Ordering::Acquire) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_MSIX_VECTOR => {
                let q_sel = reg.queue_sel.load(Ordering::Acquire) as usize;
                if let Some(msix_vector) = self.irq_sender.msix_vector.queues.get(q_sel) {
                    msix_vector.load(Ordering::Acquire) as u64
                } else {
                    VIRTIO_MSI_NO_VECTOR as u64
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_ENABLE => {
                let q_sel = reg.queue_sel.load(Ordering::Acquire) as usize;
                if let Some(q) = self.queues.get(q_sel) {
                    q.enabled.load(Ordering::Acquire) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_NOTIFY_OFF => {
                reg.queue_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_low32(&q.desc) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.desc) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.driver) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.driver) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.device) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    get_atomic_high32(&q.device) as u64
                } else {
                    0
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_NOTIFY_DATA => {
                todo!()
            }
            VirtioCommonCfg::LAYOUT_QUEUE_RESET => {
                todo!()
            }
            _ => {
                log::error!(
                    "{}: read invalid register: offset = {offset:#x}, size = {size}",
                    self.name
                );
                0
            }
        };
        Ok(ret)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let reg = &self.reg;
        match (offset as usize, size as usize) {
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT => {
                reg.device_feature_sel.store(val as u8, Ordering::Release);
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT => {
                reg.driver_feature_sel.store(val as u8, Ordering::Release);
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE => {
                let sel = reg.driver_feature_sel.load(Ordering::Acquire);
                if let Some(feature) = reg.driver_feature.get(sel as usize) {
                    feature.store(val as u32, Ordering::Release);
                } else if val != 0 {
                    log::error!("{}: unknown feature {val:#x} for sel {sel}", self.name);
                }
            }
            VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR => {
                let config_msix = &self.irq_sender.msix_vector.config;
                let old = config_msix.load(Ordering::Acquire);
                if self.msix_change_allowed(old) {
                    config_msix.store(val as u16, Ordering::Release);
                    log::trace!(
                        "{}: config MSI-X vector update: {old:#x} -> {val:#x}",
                        self.name
                    );
                } else {
                    log::error!(
                        "{}: cannot change config MSI-X vector from {old:#x} to {val:#x}",
                        self.name
                    )
                }
            }
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS => {
                let status = DevStatus::from_bits_truncate(val as u8);
                let old = reg.status.swap(status.bits(), Ordering::AcqRel);
                let old = DevStatus::from_bits_retain(old);
                if (old ^ status).contains(DevStatus::DRIVER_OK) {
                    let event = if status.contains(DevStatus::DRIVER_OK) {
                        let mut feature = 0;
                        for (i, v) in reg.driver_feature.iter().enumerate() {
                            feature |= (v.load(Ordering::Acquire) as u128) << (i << 5);
                        }
                        let param = StartParam {
                            feature,
                            irq_sender: self.irq_sender.clone(),
                            ioeventfds: self.ioeventfds.clone(),
                        };
                        WakeEvent::Start { param }
                    } else {
                        self.reset();
                        WakeEvent::Reset
                    };
                    self.wake_up_dev(event);
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_SELECT => {
                reg.queue_sel.store(val as u16, Ordering::Relaxed);
                if self.queues.get(val as usize).is_none() {
                    log::error!("{}: unknown queue index {val}", self.name)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_SIZE => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed) as usize;
                if let Some(q) = self.queues.get(q_sel) {
                    // TODO: validate queue size
                    q.size.store(val as u16, Ordering::Release);
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_MSIX_VECTOR => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed) as usize;
                if let Some(msix_vector) = self.irq_sender.msix_vector.queues.get(q_sel) {
                    let old = msix_vector.load(Ordering::Acquire);
                    if self.msix_change_allowed(old) {
                        msix_vector.store(val as u16, Ordering::Release);
                        log::trace!(
                            "{}: queue {q_sel} MSI-X vector update: {old:#x} -> {val:#x}",
                            self.name
                        );
                    } else {
                        log::error!(
                            "{}: cannot change queue {q_sel} MSI-X vector from {old:#x} to {val:#x}",
                            self.name
                        )
                    }
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_ENABLE => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    q.enabled.store(val != 0, Ordering::Release);
                };
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_low32(&q.desc, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DESC_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_high32(&q.desc, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_low32(&q.driver, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DRIVER_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_high32(&q.driver, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_LO => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_low32(&q.device, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_DEVICE_HI => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed);
                if let Some(q) = self.queues.get(q_sel as usize) {
                    set_atomic_high32(&q.device, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_RESET => {
                todo!()
            }
            (offset, _)
                if offset >= VirtioPciRegister::OFFSET_QUEUE_NOTIFY
                    && offset
                        < VirtioPciRegister::OFFSET_QUEUE_NOTIFY
                            + size_of::<u32>() * self.queues.len() =>
            {
                let q_index = (offset - VirtioPciRegister::OFFSET_QUEUE_NOTIFY) as u16 / 4;
                if self.ioeventfds.is_some() {
                    log::warn!("{}: notifying queue-{q_index} by vm exit!", self.name);
                }
                let event = WakeEvent::Notify { q_index };
                self.wake_up_dev(event)
            }
            _ => {
                log::error!(
                    "{}: write 0x{val:0width$x} to invalid register offset = {offset:#x}",
                    self.name,
                    width = 2 * size as usize
                );
            }
        }
        Ok(Action::None)
    }
}

#[derive(Debug)]
struct IoeventFdCallback<R>
where
    R: IoeventFdRegistry,
{
    registry: R,
    ioeventfds: Arc<[R::IoeventFd]>,
}

impl<R> MemRegionCallback for IoeventFdCallback<R>
where
    R: IoeventFdRegistry,
{
    fn mapped(&self, addr: u64) -> mem::Result<()> {
        for (q_index, fd) in self.ioeventfds.iter().enumerate() {
            let base_addr = addr + (12 << 10) + VirtioPciRegister::OFFSET_QUEUE_NOTIFY as u64;
            let notify_addr = base_addr + (q_index * size_of::<u32>()) as u64;
            self.registry.register(fd, notify_addr, 0, None)?;
            log::info!("q-{q_index} ioeventfd registered at {notify_addr:x}",)
        }
        Ok(())
    }

    fn unmapped(&self) -> mem::Result<()> {
        for fd in self.ioeventfds.iter() {
            self.registry.deregister(fd)?;
            log::info!("ioeventfd {fd:?} de-registered")
        }
        Ok(())
    }
}

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_DEVICE_ID_BASE: u16 = 0x1040;

fn get_class(id: DeviceId) -> (u8, u8) {
    match id {
        DeviceId::Net => (0x02, 0x00),
        DeviceId::FileSystem => (0x01, 0x80),
        DeviceId::Block => (0x01, 0x00),
        DeviceId::Socket => (0x02, 0x80),
        _ => (0xff, 0x00),
    }
}

#[repr(u8)]
pub enum VirtioPciCfg {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    Pci = 5,
    SharedMemory = 8,
    Vendor = 9,
}

#[repr(C, align(4))]
#[derive(Debug, Default, FromZeros, Immutable, IntoBytes)]
pub struct VirtioPciCap {
    header: PciCapHdr,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    id: u8,
    padding: [u8; 2],
    offset: u32,
    length: u32,
}
impl_mmio_for_zerocopy!(VirtioPciCap);

impl PciConfigArea for VirtioPciCap {
    fn reset(&self) {}
}

impl PciCap for VirtioPciCap {
    fn set_next(&mut self, val: u8) {
        self.header.next = val
    }
}

#[repr(C, align(4))]
#[derive(Debug, Default, FromZeros, Immutable, IntoBytes)]
pub struct VirtioPciCap64 {
    cap: VirtioPciCap,
    offset_hi: u32,
    length_hi: u32,
}
impl_mmio_for_zerocopy!(VirtioPciCap64);

impl PciConfigArea for VirtioPciCap64 {
    fn reset(&self) {}
}

impl PciCap for VirtioPciCap64 {
    fn set_next(&mut self, val: u8) {
        PciCap::set_next(&mut self.cap, val)
    }
}

#[repr(C, align(4))]
#[derive(Debug, Default, FromZeros, Immutable, IntoBytes)]
pub struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    multiplier: u32,
}
impl_mmio_for_zerocopy!(VirtioPciNotifyCap);

impl PciConfigArea for VirtioPciNotifyCap {
    fn reset(&self) {}
}

impl PciCap for VirtioPciNotifyCap {
    fn set_next(&mut self, val: u8) {
        self.cap.header.next = val;
    }
}

#[derive(Debug)]
pub struct VirtioPciDevice<M, E>
where
    M: MsiSender,
    E: IoeventFd,
{
    pub dev: VirtioDevice<PciIrqSender<M>, E>,
    pub config: EmulatedConfig,
    pub registers: Arc<VirtioPciRegisterMmio<M, E>>,
}

impl<M, E> VirtioPciDevice<M, E>
where
    M: MsiSender,
    E: IoeventFd,
{
    pub fn new<R>(
        dev: VirtioDevice<PciIrqSender<M>, E>,
        msi_sender: M,
        ioeventfd_reg: R,
    ) -> Result<Self>
    where
        R: IoeventFdRegistry<IoeventFd = E>,
    {
        let (class, subclass) = get_class(dev.id);
        let mut header = DeviceHeader {
            common: CommonHeader {
                vendor: VIRTIO_VENDOR_ID,
                device: VIRTIO_DEVICE_ID_BASE + dev.id as u16,
                revision: 0x1,
                header_type: HeaderType::Device as u8,
                class,
                subclass,
                ..Default::default()
            },
            subsystem: VIRTIO_DEVICE_ID_BASE + dev.id as u16,
            ..Default::default()
        };
        let device_config = dev.device_config.clone();
        let num_queues = dev.queue_regs.len();
        let table_entries = num_queues + 1;

        let msix_table_offset = 0;
        let msix_table_size = size_of::<MsixTableEntry>() * table_entries;

        let msix_pba_offset = 8 << 10;

        let virtio_register_offset = 12 << 10;
        let device_config_offset =
            virtio_register_offset + size_of::<VirtioPciRegister>() + size_of::<u32>() * num_queues;

        let msix_msg_ctrl = MsixMsgCtrl::new(table_entries as u16);

        let cap_msix = MsixCap {
            header: PciCapHdr {
                id: PciCapId::Msix as u8,
                ..Default::default()
            },
            control: msix_msg_ctrl,
            table_offset: MsixCapOffset(msix_table_offset as u32),
            pba_offset: MsixCapOffset(msix_pba_offset as u32),
        };
        let cap_common = VirtioPciCap {
            header: PciCapHdr {
                id: PciCapId::Vendor as u8,
                ..Default::default()
            },
            cap_len: size_of::<VirtioPciCap>() as u8,
            cfg_type: VirtioPciCfg::Common as u8,
            bar: 0,
            id: 0,
            offset: (virtio_register_offset + VirtioPciRegister::OFFSET_COMMON) as u32,
            length: size_of::<VirtioCommonCfg>() as u32,
            ..Default::default()
        };
        let cap_isr = VirtioPciCap {
            header: PciCapHdr {
                id: PciCapId::Vendor as u8,
                ..Default::default()
            },
            cap_len: size_of::<VirtioPciCap>() as u8,
            cfg_type: VirtioPciCfg::Isr as u8,
            bar: 0,
            id: 0,
            offset: (virtio_register_offset + VirtioPciRegister::OFFSET_ISR_STATUS) as u32,
            length: size_of::<u32>() as u32,
            ..Default::default()
        };
        let cap_notify = VirtioPciNotifyCap {
            cap: VirtioPciCap {
                header: PciCapHdr {
                    id: PciCapId::Vendor as u8,
                    ..Default::default()
                },
                cap_len: size_of::<VirtioPciNotifyCap>() as u8,
                cfg_type: VirtioPciCfg::Notify as u8,
                bar: 0,
                id: 0,
                offset: (virtio_register_offset + VirtioPciRegister::OFFSET_QUEUE_NOTIFY) as u32,
                length: (size_of::<u32>() * num_queues) as u32,
                ..Default::default()
            },
            multiplier: size_of::<u32>() as u32,
        };
        let cap_device_config = VirtioPciCap {
            header: PciCapHdr {
                id: PciCapId::Vendor as u8,
                ..Default::default()
            },
            cap_len: size_of::<VirtioPciCap>() as u8,
            cfg_type: VirtioPciCfg::Device as u8,
            bar: 0,
            id: 0,
            offset: device_config_offset as u32,
            length: device_config.size() as u32,
            ..Default::default()
        };
        let entries = RwLock::new(
            (0..table_entries)
                .map(|_| MsixTableMmioEntry::Entry(MsixTableEntry::default()))
                .collect(),
        );
        let msix_table = Arc::new(MsixTableMmio { entries });
        let bar0_size = 16 << 10;
        let mut bar0 = MemRegion {
            ranges: vec![],
            entries: vec![MemRegionEntry {
                size: bar0_size,
                type_: mem::MemRegionType::Hidden,
            }],
            callbacks: Mutex::new(vec![]),
        };

        let mut caps: Vec<Box<dyn PciCap>> = vec![
            Box::new(MsixCapMmio {
                cap: RwLock::new(cap_msix),
            }),
            Box::new(cap_common),
            Box::new(cap_isr),
            Box::new(cap_notify),
        ];
        if device_config.size() > 0 {
            caps.push(Box::new(cap_device_config));
        }
        if let Some(region) = &dev.shared_mem_regions {
            let mut offset = 0;
            for (index, entry) in region.entries.iter().enumerate() {
                let share_mem_cap = VirtioPciCap64 {
                    cap: VirtioPciCap {
                        header: PciCapHdr {
                            id: PciCapId::Vendor as u8,
                            ..Default::default()
                        },
                        cap_len: size_of::<VirtioPciCap64>() as u8,
                        cfg_type: VirtioPciCfg::SharedMemory as u8,
                        bar: 2,
                        id: index as u8,
                        offset: offset as u32,
                        length: entry.size as u32,
                        ..Default::default()
                    },
                    length_hi: (entry.size >> 32) as u32,
                    offset_hi: (offset >> 32) as u32,
                };
                caps.push(Box::new(share_mem_cap));
                offset += entry.size;
            }
        }

        let cap_list = PciCapList::try_from(caps)?;

        let msix_vector = VirtioPciMsixVector {
            config: AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            queues: (0..num_queues)
                .map(|_| AtomicU16::new(VIRTIO_MSI_NO_VECTOR))
                .collect(),
        };

        let maybe_ioeventfds = (0..num_queues)
            .map(|_| ioeventfd_reg.create())
            .collect::<Result<Arc<_>, _>>();
        let ioeventfds = match maybe_ioeventfds {
            Ok(fds) => Some(fds),
            Err(hv::Error::IoeventFd { error, .. }) if error.kind() == ErrorKind::Unsupported => {
                None
            }
            Err(e) => {
                log::warn!("{}: failed to create ioeventfds: {e:?}", dev.name);
                None
            }
        };

        let mut device_feature = [0u32; 4];
        for (i, v) in device_feature.iter_mut().enumerate() {
            *v = (dev.device_feature >> (i << 5)) as u32;
        }
        let registers = Arc::new(VirtioPciRegisterMmio {
            name: dev.name.clone(),
            reg: Register {
                device_feature,
                ..Default::default()
            },
            event_tx: dev.event_tx.clone(),
            notifier: dev.notifier.clone(),
            queues: dev.queue_regs.clone(),
            irq_sender: Arc::new(PciIrqSender {
                msix_vector,
                msix_table: msix_table.clone(),
                msi_sender,
            }),
            ioeventfds: ioeventfds.clone(),
        });
        bar0.ranges.push(MemRange::Emulated(msix_table));
        bar0.ranges
            .push(MemRange::Span((12 << 10) - msix_table_size as u64));
        bar0.ranges.push(MemRange::Emulated(registers.clone()));
        if let Some(ioeventfds) = ioeventfds {
            bar0.callbacks.lock().push(Box::new(IoeventFdCallback {
                registry: ioeventfd_reg,
                ioeventfds,
            }));
        }
        if device_config.size() > 0 {
            bar0.ranges.push(MemRange::Emulated(device_config))
        }
        let mut bars = [const { PciBar::Empty }; 6];
        let mut bar_masks = [0; 6];
        let bar0_mask = !(bar0_size - 1);
        bar_masks[0] = bar0_mask as u32;
        bars[0] = PciBar::Mem(Arc::new(bar0));
        header.bars[0] = BAR_MEM32;

        if let Some(region) = &dev.shared_mem_regions {
            let region_size = region.size();
            let bar2_mask = !(region_size.next_power_of_two() - 1);
            bar_masks[2] = bar2_mask as u32;
            let mut not_emulated = |r| !matches!(r, &MemRange::Emulated(_));
            let prefetchable = region.ranges.iter().all(&mut not_emulated);
            if prefetchable {
                bar_masks[3] = (bar2_mask >> 32) as u32;
                bars[2] = PciBar::Mem(region.clone());
                header.bars[2] = BAR_MEM64 | BAR_PREFETCHABLE;
            } else {
                assert!(region_size <= u32::MAX as u64);
                bars[2] = PciBar::Mem(region.clone());
                header.bars[2] = BAR_MEM32;
            }
        }

        let config = EmulatedConfig::new_device(header, bar_masks, bars, cap_list);

        Ok(VirtioPciDevice {
            dev,
            config,
            registers,
        })
    }
}

impl<M, E> Pci for VirtioPciDevice<M, E>
where
    M: MsiSender,
    E: IoeventFd,
{
    fn config(&self) -> &dyn PciConfig {
        &self.config
    }

    fn reset(&self) -> pci::Result<()> {
        self.registers.wake_up_dev(WakeEvent::Reset);
        self.registers.reset();
        self.registers.reg.status.store(0, Ordering::Release);
        Ok(())
    }
}
