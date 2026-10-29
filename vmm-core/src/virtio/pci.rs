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

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use derive_layout::Layout;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::host::abi::{
    CORE_MSG_VIRTIO_NOTIFY, CORE_MSG_VIRTIO_RESET, CORE_MSG_VIRTIO_START, CoreToIoEntry,
    MAX_QUEUES_PER_DEV, ShmDeviceMsixRouting, ShmMsiEntry, ShmVirtioQueueConfig,
};
use crate::host::{VirtioDeviceSpec, VmmCoreBridge};
use crate::hw::pci::cap::{
    MsixCap, MsixCapMmio, MsixCapOffset, MsixMsgCtrl, MsixTableEntry, MsixTableMmio, PciCap,
    PciCapHdr, PciCapId, PciCapList,
};
use crate::hw::pci::config::{
    BAR_MEM64, CommonHeader, DeviceHeader, EmulatedConfig, HeaderType, PciConfig,
};
use crate::hw::pci::{self, Pci, PciBar};
use crate::mem::mmio::Mmio;
use crate::mem::{MemRange, MemRegion, MemRegionEntry};
use crate::sync::{Mutex, RwLock};
use crate::utils::{
    get_atomic_high32, get_atomic_low32, get_high32, get_low32, set_atomic_high32, set_atomic_low32,
};
use crate::virtio::{DevStatus, DeviceId, QUEUE_SIZE_MAX, Queue, Register, Result, VirtioFeature};
use crate::{impl_mmio_for_zerocopy, mem};

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

#[derive(Debug)]
struct VirtioPciMsixVector {
    config: AtomicU16,
    queues: Vec<AtomicU16>,
}

pub struct PciIrqRouting {
    dev_id: u32,
    msix_vector: VirtioPciMsixVector,
    msix_entries: Arc<Vec<RwLock<MsixTableEntry>>>,
    bridge: Arc<dyn VmmCoreBridge>,
}

impl Debug for PciIrqRouting {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PciIrqRouting")
            .field("dev_id", &self.dev_id)
            .field("msix_vector", &self.msix_vector)
            .finish()
    }
}

impl PciIrqRouting {
    fn resolve_vector(&self, vector: u16) -> Option<(u64, u32)> {
        if vector == VIRTIO_MSI_NO_VECTOR {
            return None;
        }
        let entry = self.msix_entries.get(vector as usize)?.read();
        if entry.control.masked() {
            return None;
        }
        let addr = ((entry.addr_hi as u64) << 32) | (entry.addr_lo as u64);
        if addr == 0 {
            return None;
        }
        Some((addr, entry.data))
    }

    pub fn sync_to_host(&self) {
        let mut routing = ShmDeviceMsixRouting::default();
        let config_vec = self.msix_vector.config.load(Ordering::Acquire);
        if let Some((addr, data)) = self.resolve_vector(config_vec) {
            routing.config_msi = ShmMsiEntry {
                addr,
                data,
                enabled: 1,
            };
        }
        for (i, q) in self
            .msix_vector
            .queues
            .iter()
            .enumerate()
            .take(MAX_QUEUES_PER_DEV)
        {
            if let Some((addr, data)) = self.resolve_vector(q.load(Ordering::Acquire)) {
                routing.queue_msis[i] = ShmMsiEntry {
                    addr,
                    data,
                    enabled: 1,
                };
            }
        }
        if let Err(e) = self.bridge.update_irq_route(self.dev_id, &routing) {
            log::error!("dev {}: failed to update MSI-X routing: {e}", self.dev_id);
        }
    }
}

#[derive(Debug)]
pub struct VirtioDeviceConfigBytes {
    bytes: Vec<u8>,
}

impl Mmio for VirtioDeviceConfigBytes {
    fn size(&self) -> usize {
        self.bytes.len()
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let bytes = &self.bytes;
        let val = match size {
            1 => bytes.get(offset).map(|b| *b as u64),
            2 => bytes
                .get(offset..)
                .and_then(|s| u16::read_from_prefix(s).map(|w| w as u64)),
            4 => bytes
                .get(offset..)
                .and_then(|s| u32::read_from_prefix(s).map(|d| d as u64)),
            8 => bytes.get(offset..).and_then(u64::read_from_prefix),
            _ => None,
        };
        if let Some(val) = val {
            Ok(val)
        } else {
            log::error!(
                "VirtioDeviceConfigBytes: invalid read access, offset = {offset:#x}, size = {size}."
            );
            Ok(0)
        }
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        log::error!(
            "VirtioDeviceConfigBytes: write 0x{val:0width$x} to readonly offset 0x{offset:x}.",
            width = 2 * size as usize
        );
        Ok(())
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

pub struct VirtioPciRegisterMmio {
    name: Arc<String>,
    dev_id: u32,
    reg: Arc<Register>,
    queues: Arc<Vec<Queue>>,
    irq_routing: Arc<PciIrqRouting>,
    bridge: Arc<dyn VmmCoreBridge>,
}

impl Debug for VirtioPciRegisterMmio {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioPciRegisterMmio")
            .field("name", &self.name)
            .field("dev_id", &self.dev_id)
            .finish()
    }
}

impl VirtioPciRegisterMmio {
    fn start_dev(&self) {
        self.irq_routing.sync_to_host();
        let driver_features = self.reg.driver_feature.load(Ordering::Acquire);
        let mut raw_queues = [ShmVirtioQueueConfig::default(); MAX_QUEUES_PER_DEV];
        let nq = self.queues.len().min(MAX_QUEUES_PER_DEV);
        for (i, q) in self.queues.iter().take(nq).enumerate() {
            raw_queues[i] = ShmVirtioQueueConfig {
                size: q.size.load(Ordering::Acquire),
                enabled: u16::from(q.enabled.load(Ordering::Acquire)),
                _pad: 0,
                desc_gpa: q.desc.load(Ordering::Acquire),
                avail_gpa: q.driver.load(Ordering::Acquire),
                used_gpa: q.device.load(Ordering::Acquire),
            };
        }
        if let Err(e) = self
            .bridge
            .configure_device_queues(self.dev_id, &raw_queues[..nq])
        {
            log::error!("{}: configure_device_queues failed: {e}", self.name);
            return;
        }
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_VIRTIO_START,
            aux_u16: nq as u16,
            _pad: 0,
            dev: self.dev_id as u64,
            features: driver_features,
            data: [0; 40],
        };
        if let Err(e) = self.bridge.send_io_cmd(&entry) {
            log::error!("{}: virtio start send_io_cmd failed: {e}", self.name);
        }
    }

    fn notify_dev(&self, q_index: u16) {
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_VIRTIO_NOTIFY,
            aux_u16: q_index,
            _pad: 0,
            dev: self.dev_id as u64,
            features: 0,
            data: [0; 40],
        };
        if let Err(e) = self.bridge.send_io_cmd(&entry) {
            log::error!("{}: virtio notify({q_index}) failed: {e}", self.name);
        }
    }

    fn reset(&self) {
        let config_msix = &self.irq_routing.msix_vector.config;
        config_msix.store(VIRTIO_MSI_NO_VECTOR, Ordering::Release);
        for q_vector in self.irq_routing.msix_vector.queues.iter() {
            q_vector.store(VIRTIO_MSI_NO_VECTOR, Ordering::Release);
        }
        for q in self.queues.iter() {
            q.enabled.store(false, Ordering::Release);
        }
        self.irq_routing.sync_to_host();
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_VIRTIO_RESET,
            aux_u16: 0,
            _pad: 0,
            dev: self.dev_id as u64,
            features: 0,
            data: [0; 40],
        };
        if let Err(e) = self.bridge.send_io_cmd(&entry) {
            log::error!("{}: virtio reset failed: {e}", self.name);
        }
    }
}

impl Mmio for VirtioPciRegisterMmio {
    fn size(&self) -> usize {
        size_of::<VirtioPciRegister>() + size_of::<u32>() * self.queues.len()
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let reg = &*self.reg;
        let ret = match (offset, size as usize) {
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT => {
                reg.device_feature_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE => {
                if reg.device_feature_sel.load(Ordering::Acquire) > 0 {
                    get_high32(reg.device_feature) as u64
                } else {
                    get_low32(reg.device_feature) as u64
                }
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT => {
                reg.driver_feature_sel.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE => {
                if reg.driver_feature_sel.load(Ordering::Acquire) > 0 {
                    get_atomic_high32(&reg.driver_feature) as u64
                } else {
                    get_atomic_low32(&reg.driver_feature) as u64
                }
            }
            VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR => {
                self.irq_routing.msix_vector.config.load(Ordering::Acquire) as u64
            }
            VirtioCommonCfg::LAYOUT_NUM_QUEUES => self.queues.len() as u64,
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS => reg.status.load(Ordering::Acquire) as u64,
            VirtioCommonCfg::LAYOUT_CONFIG_GENERATION => 0,
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
                if let Some(msix_vector) = self.irq_routing.msix_vector.queues.get(q_sel) {
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

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let reg = &*self.reg;
        match (offset, size as usize) {
            VirtioCommonCfg::LAYOUT_DEVICE_FEATURE_SELECT => {
                reg.device_feature_sel.store(val as u8, Ordering::Release);
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE_SELECT => {
                reg.driver_feature_sel.store(val as u8, Ordering::Release);
            }
            VirtioCommonCfg::LAYOUT_DRIVER_FEATURE => {
                if reg.driver_feature_sel.load(Ordering::Relaxed) > 0 {
                    set_atomic_high32(&reg.driver_feature, val as u32)
                } else {
                    set_atomic_low32(&reg.driver_feature, val as u32)
                }
            }
            VirtioCommonCfg::LAYOUT_CONFIG_MSIX_VECTOR => {
                let config_msix = &self.irq_routing.msix_vector.config;
                let old = config_msix.swap(val as u16, Ordering::AcqRel);
                log::trace!(
                    "{}: config MSI-X vector update: {old:#x} -> {val:#x}",
                    self.name
                );
                self.irq_routing.sync_to_host();
            }
            VirtioCommonCfg::LAYOUT_DEVICE_STATUS => {
                let status = DevStatus::from_bits_truncate(val as u8);
                let old = reg.status.swap(status.bits(), Ordering::AcqRel);
                let old = DevStatus::from_bits_retain(old);
                if (old ^ status).contains(DevStatus::DRIVER_OK) {
                    if status.contains(DevStatus::DRIVER_OK) {
                        self.start_dev();
                    } else {
                        self.reset();
                    }
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
                    q.size.store(val as u16, Ordering::Release);
                }
            }
            VirtioCommonCfg::LAYOUT_QUEUE_MSIX_VECTOR => {
                let q_sel = reg.queue_sel.load(Ordering::Relaxed) as usize;
                if let Some(msix_vector) = self.irq_routing.msix_vector.queues.get(q_sel) {
                    let old = msix_vector.swap(val as u16, Ordering::AcqRel);
                    log::trace!(
                        "{}: queue {q_sel} MSI-X vector update: {old:#x} -> {val:#x}",
                        self.name
                    );
                    self.irq_routing.sync_to_host();
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
            (VirtioPciRegister::OFFSET_QUEUE_NOTIFY, _) => {
                self.notify_dev(val as u16);
            }
            _ => {
                log::error!(
                    "{}: write 0x{val:0width$x} to invalid register offset = {offset:#x}",
                    self.name,
                    width = 2 * size as usize
                );
            }
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
#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes)]
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

impl PciCap for VirtioPciCap {
    fn set_next(&mut self, val: u8) {
        self.header.next = val
    }
}

#[repr(C, align(4))]
#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes)]
pub struct VirtioPciCap64 {
    cap: VirtioPciCap,
    offset_hi: u32,
    length_hi: u32,
}
impl_mmio_for_zerocopy!(VirtioPciCap64);

impl PciCap for VirtioPciCap64 {
    fn set_next(&mut self, val: u8) {
        PciCap::set_next(&mut self.cap, val)
    }
}

#[repr(C, align(4))]
#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes)]
pub struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    multiplier: u32,
}
impl_mmio_for_zerocopy!(VirtioPciNotifyCap);

impl PciCap for VirtioPciNotifyCap {
    fn set_next(&mut self, val: u8) {
        self.cap.header.next = val;
    }
}

#[derive(Debug)]
pub struct VirtioPciDevice {
    pub name: Arc<String>,
    pub reg: Arc<Register>,
    pub config: Arc<EmulatedConfig>,
    pub registers: Arc<VirtioPciRegisterMmio>,
}

impl VirtioPciDevice {
    pub fn from_spec(spec: VirtioDeviceSpec, bridge: Arc<dyn VmmCoreBridge>) -> Result<Self> {
        let name = Arc::new(spec.name);
        let device_id = DeviceId::from_u16(spec.device_id);
        let (class, subclass) = get_class(device_id);
        let mut header = DeviceHeader {
            common: CommonHeader {
                vendor: VIRTIO_VENDOR_ID,
                device: VIRTIO_DEVICE_ID_BASE + device_id as u16,
                revision: 0x1,
                header_type: HeaderType::Device as u8,
                class,
                subclass,
                ..Default::default()
            },
            subsystem: VIRTIO_DEVICE_ID_BASE + device_id as u16,
            ..Default::default()
        };

        let device_config = Arc::new(VirtioDeviceConfigBytes {
            bytes: spec.config_bytes,
        });
        let num_queues = spec.num_queues as usize;
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
            multiplier: 0,
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
        let msix_entries: Arc<Vec<RwLock<MsixTableEntry>>> = Arc::new(
            (0..table_entries)
                .map(|_| RwLock::new(MsixTableEntry::default()))
                .collect(),
        );
        let mut bar0 = MemRegion {
            size: 16 << 10,
            ranges: vec![],
            entries: vec![MemRegionEntry {
                size: 16 << 10,
                type_: mem::MemRegionType::Hidden,
            }],
            callbacks: Mutex::new(vec![]),
        };

        let msix_vector = VirtioPciMsixVector {
            config: AtomicU16::new(VIRTIO_MSI_NO_VECTOR),
            queues: (0..num_queues)
                .map(|_| AtomicU16::new(VIRTIO_MSI_NO_VECTOR))
                .collect(),
        };

        let irq_routing = Arc::new(PciIrqRouting {
            dev_id: spec.dev,
            msix_vector,
            msix_entries: msix_entries.clone(),
            bridge: bridge.clone(),
        });

        let irq_routing_cap_cb = {
            let irq_routing = irq_routing.clone();
            Arc::new(move || irq_routing.sync_to_host())
        };
        let irq_routing_tbl_cb = {
            let irq_routing = irq_routing.clone();
            Arc::new(move || irq_routing.sync_to_host())
        };

        let mut caps: Vec<Box<dyn PciCap>> = vec![
            Box::new(MsixCapMmio {
                cap: RwLock::new(cap_msix),
                on_change: Some(irq_routing_cap_cb),
            }),
            Box::new(cap_common),
            Box::new(cap_isr),
            Box::new(cap_notify),
        ];
        if device_config.size() > 0 {
            caps.push(Box::new(cap_device_config));
        }

        let cap_list = PciCapList::try_from(caps)?;

        let reg = Arc::new(Register {
            device_feature: spec.device_features | VirtioFeature::SUPPORTED.bits(),
            ..Default::default()
        });
        let queues = Arc::new(
            (0..num_queues)
                .map(|_| Queue {
                    size: AtomicU16::new(QUEUE_SIZE_MAX),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        );

        let registers = Arc::new(VirtioPciRegisterMmio {
            name: name.clone(),
            dev_id: spec.dev,
            reg: reg.clone(),
            queues,
            irq_routing,
            bridge,
        });
        bar0.ranges.push(MemRange::Emulated(Arc::new(MsixTableMmio {
            entries: msix_entries,
            on_change: Some(irq_routing_tbl_cb),
        })));
        bar0.ranges
            .push(MemRange::Span((12 << 10) - msix_table_size));
        bar0.ranges.push(MemRange::Emulated(registers.clone()));
        if device_config.size() > 0 {
            bar0.ranges.push(MemRange::Emulated(device_config))
        }
        let mut bars = PciBar::empty_6();
        let mut bar_masks = [0; 6];
        let bar0_mask = !((bar0.size as u64).next_power_of_two() - 1);
        bar_masks[0] = bar0_mask as u32;
        bar_masks[1] = (bar0_mask >> 32) as u32;
        bars[0] = PciBar::Mem64(Arc::new(bar0));
        header.bars[0] = BAR_MEM64;

        let config = Arc::new(EmulatedConfig::new_device(
            header, bar_masks, bars, cap_list,
        ));

        Ok(VirtioPciDevice {
            name,
            reg,
            config,
            registers,
        })
    }
}

impl Pci for VirtioPciDevice {
    fn config(&self) -> Arc<dyn PciConfig> {
        self.config.clone()
    }
    fn reset(&self) -> pci::Result<()> {
        self.registers.reset();
        self.reg.status.store(0, Ordering::Release);
        Ok(())
    }
}
