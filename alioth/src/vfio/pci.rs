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

use std::fs::File;
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use libc::{PROT_READ, PROT_WRITE};
use parking_lot::{Mutex, RwLock};
use snafu::ResultExt;
use zerocopy::{transmute, FromBytes};

use crate::errors::boxed_debug_trace;
use crate::hv::{IrqFd, MsiSender};
use crate::mem::addressable::{Addressable, SlotBackend};
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{IoRegion, MemRange, MemRegion, MemRegionEntry, MemRegionType};
use crate::pci::cap::{
    MsixCap, MsixTableEntry, MsixTableMmio, MsixTableMmioEntry, PciCapHdr, PciCapId,
};
use crate::pci::config::{
    Command, CommonHeader, ConfigHeader, DeviceHeader, EmulatedHeader, HeaderData, HeaderType,
    PciConfig, Status, BAR_IO, BAR_MEM64,
};
use crate::pci::{self, Bdf, Pci, PciBar};
use crate::vfio::bindings::{
    VfioIrqSet, VfioIrqSetData, VfioIrqSetFlag, VfioPciIrq, VfioPciRegion, VfioRegionInfo,
    VfioRegionInfoFlag,
};
use crate::vfio::device::Device;
use crate::vfio::{error, Result};
use crate::{align_down, align_up, assign_bits, mask_bits, mem};

fn round_up_range(range: Range<usize>) -> Range<usize> {
    (align_down!(range.start, 12))..(align_up!(range.end, 12))
}

fn create_mapped_bar_pages(
    fd: &File,
    region_flags: VfioRegionInfoFlag,
    offset: i64,
    size: usize,
) -> Result<ArcMemPages> {
    let mut prot = 0;
    if region_flags.contains(VfioRegionInfoFlag::READ) {
        prot |= PROT_READ;
    }
    if region_flags.contains(VfioRegionInfoFlag::WRITE) {
        prot |= PROT_WRITE;
    }
    let mapped_pages = ArcMemPages::from_file(fd.try_clone()?, offset, size, prot)?;
    Ok(mapped_pages)
}

fn create_splitted_bar_region<I, M, D>(
    dev: Arc<VfioDev<D>>,
    region_info: &VfioRegionInfo,
    table_range: Range<usize>,
    pba_range: Range<usize>,
    msix_table: Arc<MsixTableMmio<I>>,
    msi_sender: Arc<M>,
) -> Result<MemRegion>
where
    I: IrqFd,
    M: MsiSender<IrqFd = I>,
    D: Device,
{
    let table_pages = round_up_range(table_range.clone());
    let pba_pages = round_up_range(pba_range.clone());
    let (excluded_page1, excluded_page2) = if table_pages.clone().eq(0..0) {
        (0..0, pba_pages)
    } else if pba_pages.clone().eq(0..0) {
        (0..0, table_pages)
    } else if table_pages.start <= pba_pages.start && table_pages.end >= pba_pages.start {
        (0..0, table_pages.start..pba_pages.end)
    } else if pba_pages.start <= table_pages.start && pba_pages.end >= table_pages.start {
        (0..0, pba_pages.start..table_pages.end)
    } else if table_pages.end < pba_pages.start {
        (table_pages, pba_pages)
    } else {
        (pba_pages, table_pages)
    };
    let mut region = MemRegion {
        callbacks: Mutex::new(vec![]),
        entries: vec![MemRegionEntry {
            size: region_info.size,
            type_: MemRegionType::Hidden,
        }],
        ranges: vec![],
    };
    if excluded_page1.start > 0 {
        region.ranges.push(MemRange::DevMem(create_mapped_bar_pages(
            dev.dev.fd(),
            region_info.flags,
            region_info.offset as i64,
            excluded_page1.start,
        )?));
    }
    if excluded_page1.end - excluded_page1.start > 0 {
        region.ranges.push(MemRange::Emulated(Arc::new(MsixBarMmio {
            table: msix_table.clone(),
            table_range: table_range.clone(),
            msi_sender: msi_sender.clone(),
            pba: Arc::new([]),
            pba_range: pba_range.clone(),
            cdev: dev.clone(),
            cdev_offset: region_info.offset,
            region_start: excluded_page1.start,
            region_size: excluded_page1.end - excluded_page1.start,
        })));
    }
    if excluded_page2.start - excluded_page1.end > 0 {
        region.ranges.push(MemRange::DevMem(create_mapped_bar_pages(
            dev.dev.fd(),
            region_info.flags,
            region_info.offset as i64 + excluded_page1.end as i64,
            excluded_page2.start - excluded_page1.end,
        )?));
    }
    if excluded_page2.end - excluded_page2.start > 0 {
        region.ranges.push(MemRange::Emulated(Arc::new(MsixBarMmio {
            table: msix_table,
            table_range,
            msi_sender,
            pba: Arc::new([]),
            pba_range,
            cdev: dev.clone(),
            cdev_offset: region_info.offset,
            region_start: excluded_page2.start,
            region_size: excluded_page2.end - excluded_page2.start,
        })));
    }
    if excluded_page2.end < region_info.size as usize {
        region.ranges.push(MemRange::DevMem(create_mapped_bar_pages(
            dev.dev.fd(),
            region_info.flags,
            region_info.offset as i64 + excluded_page2.end as i64,
            region_info.size as usize - excluded_page2.end,
        )?));
    }
    Ok(region)
}

fn create_mappable_bar_region<I, M, D>(
    cdev: Arc<VfioDev<D>>,
    index: u32,
    region_info: &VfioRegionInfo,
    msix_cap: Option<&MsixCap>,
    msix_table: Arc<MsixTableMmio<I>>,
    msi_sender: Arc<M>,
) -> Result<MemRegion>
where
    I: IrqFd,
    M: MsiSender<IrqFd = I>,
    D: Device,
{
    let (msix_table_offset, msix_pba_offset, msix_control) = if let Some(msix_cap) = msix_cap {
        (msix_cap.table_offset, msix_cap.pba_offset, msix_cap.control)
    } else {
        return create_splitted_bar_region(cdev, region_info, 0..0, 0..0, msix_table, msi_sender);
    };
    let num_msix_entries = msix_control.table_len() as usize + 1;
    let table_offset = msix_table_offset.0 as usize & !0b111;
    let pba_offset = msix_pba_offset.0 as usize & !0b111;
    let table_range = table_offset..(table_offset + size_of::<MsixTableEntry>() * num_msix_entries);
    let pba_range = pba_offset..(pba_offset + (align_up!(num_msix_entries, 6) >> 3));

    if msix_table_offset.bar() == index && msix_pba_offset.bar() == index {
        create_splitted_bar_region(
            cdev,
            region_info,
            table_range,
            pba_range,
            msix_table,
            msi_sender,
        )
    } else if msix_table_offset.bar() == index {
        create_splitted_bar_region(cdev, region_info, table_range, 0..0, msix_table, msi_sender)
    } else if msix_pba_offset.bar() == index {
        create_splitted_bar_region(cdev, region_info, 0..0, pba_range, msix_table, msi_sender)
    } else {
        create_splitted_bar_region(cdev, region_info, 0..0, 0..0, msix_table, msi_sender)
    }
}

#[derive(Debug)]
struct MaskedCap {
    size: usize,
}

impl SlotBackend for MaskedCap {
    fn size(&self) -> u64 {
        self.size as u64
    }
}

#[derive(Debug)]
struct VfioDev<D> {
    name: Arc<str>,
    dev: D,
}

#[derive(Debug)]
pub struct ExtraConfig<D> {
    msix_msg_ctrl_hi: AtomicU8,
    msix_msg_ctrl_offset: usize,
    masked_caps: Addressable<MaskedCap>,

    dev: Arc<VfioDev<D>>,
    offset: u64,
    size: usize,
}

impl<D> ExtraConfig<D>
where
    D: Device,
{
    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let name = &self.dev.name;
        let mut masks = [0; 8];
        let vals = val.to_ne_bytes();
        for index in 0..(size as usize) {
            let pos = offset + index;
            if pos == self.msix_msg_ctrl_offset + 1 {
                let mut msix_msg_ctrl_hi = self.msix_msg_ctrl_hi.load(Ordering::Acquire);
                const MASKED: u8 = 1 << 6;
                const ENABLED: u8 = 1 << 7;
                assign_bits!(msix_msg_ctrl_hi, vals[index], MASKED | ENABLED);
                // TODO trigger mask / enable interrupt
                self.msix_msg_ctrl_hi
                    .store(msix_msg_ctrl_hi, Ordering::Release);
                log::trace!("{name}: msix_msg_ctrl_hi -> {msix_msg_ctrl_hi:#x?}",);
                masks[index] = 0xff;
            } else if pos == self.msix_msg_ctrl_offset
                || self.masked_caps.search(pos as u64).is_some()
            {
                masks[index] = 0xff;
            }
        }
        let mask = u64::from_ne_bytes(masks);
        log::trace!(
            "{name}: write config: val=0x{val:0width$x}, offset={offset:#05x}, size={size}, mask=0x{mask:0width$x}",
            width = 2 * size as usize
        );
        if mask.trailing_ones() == (size << 3) as u32 {
            return Ok(());
        }
        let cdev = &self.dev.dev;
        let masked_val = if mask == 0 {
            val
        } else {
            let real_val = cdev.read(self.offset + offset as u64, size)?;
            mask_bits!(val, real_val, mask)
        };
        cdev.write(self.offset + offset as u64, size, masked_val)
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let mut emulated_bytes = [0; 8];
        let mut masks = [0; 8];
        for index in 0..(size as usize) {
            let pos = offset + index;
            if pos == self.msix_msg_ctrl_offset + 1 {
                emulated_bytes[index] = self.msix_msg_ctrl_hi.load(Ordering::Acquire);
                masks[index] = 0xff;
            } else if let Some((start, _)) = self.masked_caps.search(pos as u64) {
                if pos != start as usize + PciCapHdr::OFFSET_NEXT {
                    emulated_bytes[index] = 0;
                    masks[index] = 0xff;
                }
            }
        }
        let mask = u64::from_ne_bytes(masks);
        let emulated_val = u64::from_ne_bytes(emulated_bytes);
        let ret = if mask.trailing_ones() == (size << 3) as u32 {
            emulated_val
        } else {
            let real_val = self.dev.dev.read(self.offset + offset as u64, size)?;
            mask_bits!(real_val, emulated_val, mask)
        };
        log::trace!(
            "{}: read config: offset={offset:#05x}, size={size}, mask=0x{mask:0width$x}, emulated_val=0x{emulated_val:0width$x}, ret=0x{ret:0width$x}",
            self.dev.name,
            width = 2 * size as usize
        );
        Ok(ret)
    }
}

#[derive(Debug)]
pub struct PciPthConfig<D> {
    header: EmulatedHeader,
    extra: ExtraConfig<D>,
}

impl<D> Mmio for PciPthConfig<D>
where
    D: Device,
{
    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        if offset < self.header.size() {
            Mmio::read(&self.header, offset, size)
        } else {
            self.extra.read(offset as usize, size)
        }
    }

    fn size(&self) -> u64 {
        self.extra.size as u64
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        if offset < self.header.size() {
            Mmio::write(&self.header, offset, size, val)
        } else {
            self.extra.write(offset as usize, size, val)?;
            Ok(Action::None)
        }
    }
}

impl<D> PciConfig for PciPthConfig<D>
where
    D: Device,
{
    fn get_header(&self) -> &EmulatedHeader {
        &self.header
    }

    fn reset(&self) {
        self.header.reset();
        self.extra.msix_msg_ctrl_hi.store(0, Ordering::Release)
    }
}

#[derive(Debug)]
pub struct PthBarRegion<D> {
    cdev: Arc<VfioDev<D>>,
    size: usize,
    offset: u64,
}

impl<D> Mmio for PthBarRegion<D>
where
    D: Device,
{
    fn size(&self) -> u64 {
        self.size as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        log::trace!(
            "{}: emulated read at {offset:#x}, size={size}",
            self.cdev.name
        );
        self.cdev.dev.read(self.offset + offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        log::trace!(
            "{}: emulated write at {offset:#x}, val={val:#x}, size={size}",
            self.cdev.name
        );
        self.cdev.dev.write(self.offset + offset, size, val)?;
        Ok(Action::None)
    }
}

#[derive(Debug)]
pub struct VfioPciDev<M, D>
where
    M: MsiSender,
{
    config: Arc<PciPthConfig<D>>,
    msix_table: Arc<MsixTableMmio<M::IrqFd>>,
}

impl<M, D> Pci for VfioPciDev<M, D>
where
    D: Device,
    M: MsiSender,
{
    fn config(&self) -> Arc<dyn PciConfig> {
        self.config.clone()
    }

    fn reset(&self) -> pci::Result<()> {
        let ret = VfioPciDev::reset(self);
        ret.map_err(boxed_debug_trace).context(pci::error::Reset)?;
        Ok(())
    }
}

impl<M, D> VfioPciDev<M, D>
where
    M: MsiSender,
    D: Device,
{
    pub fn new(name: Arc<str>, dev: D, msi_sender: M) -> Result<VfioPciDev<M, D>> {
        let cdev = Arc::new(VfioDev { dev, name });

        let region_config = cdev.dev.get_region_info(VfioPciRegion::CONFIG.raw())?;

        let pci_command = Command::MEM | Command::BUS_MASTER | Command::INTX_DISABLE;
        cdev.dev.write(
            region_config.offset + CommonHeader::OFFSET_COMMAND as u64,
            CommonHeader::SIZE_COMMAND as u8,
            pci_command.bits() as _,
        )?;
        let mut buf: [u8; 4096] = transmute!([0u32; 1024]);
        cdev.dev.fd().read_at(&mut buf, region_config.offset)?;

        let (mut dev_header, _) = DeviceHeader::read_from_prefix(&buf).unwrap();
        if dev_header.common.header_type != HeaderType::Device as u8 {
            return error::NotSupportedHeader {
                ty: dev_header.common.header_type,
            }
            .fail();
        }
        dev_header.intx_pin = 0;
        dev_header.common.command = Command::empty();

        let mut msix_cap = None;
        let mut msix_msg_ctrl_offset = 0;
        let mut masked_caps = Addressable::new();

        if dev_header.common.status.contains(Status::CAP) {
            let mut cap_offset = dev_header.capability_pointer as usize;
            while cap_offset != 0 {
                let (cap_header, _) = PciCapHdr::ref_from_prefix(&buf[cap_offset..]).unwrap();
                if cap_header.id == PciCapId::Msix as u8 {
                    if let Ok((c, _)) = MsixCap::read_from_prefix(&buf[cap_offset..]) {
                        msix_cap = Some(c)
                    }
                    msix_msg_ctrl_offset = cap_offset + MsixCap::OFFSET_CONTROL;
                } else if cap_header.id == PciCapId::Msi as u8 {
                    log::trace!("{}: hiding MSI cap at {cap_offset:#x}", cdev.name);
                    masked_caps.add(cap_offset as u64, MaskedCap { size: 0x20 })?;
                }
                cap_offset = cap_header.next as usize;
            }
        }
        let config_header = ConfigHeader::Device(dev_header);

        cdev.dev.reset()?;
        let msix_info = cdev.dev.get_irq_info(VfioPciIrq::MSIX.raw())?;
        let msix_entries = RwLock::new(
            (0..msix_info.count)
                .map(|_| MsixTableMmioEntry::Entry(MsixTableEntry::default()))
                .collect(),
        );

        let msix_table = Arc::new(MsixTableMmio {
            entries: msix_entries,
        });
        let msi_sender = Arc::new(msi_sender);

        let mut bars = [const { PciBar::Empty }; 6];
        let mut bar_masks = [0u32; 6];

        let bar_vals = config_header.bars();

        for index in VfioPciRegion::BAR0.raw()..=VfioPciRegion::BAR5.raw() {
            let region_info = cdev.dev.get_region_info(index)?;
            if region_info.size == 0 {
                continue;
            }
            let region = if region_info.flags.contains(VfioRegionInfoFlag::MMAP) {
                create_mappable_bar_region(
                    cdev.clone(),
                    index,
                    &region_info,
                    msix_cap.as_ref(),
                    msix_table.clone(),
                    msi_sender.clone(),
                )?
            } else {
                MemRegion::with_emulated(
                    Arc::new(PthBarRegion {
                        cdev: cdev.clone(),
                        size: region_info.size as usize,
                        offset: region_info.offset,
                    }),
                    MemRegionType::Hidden,
                )
            };
            let index = index as usize;
            let bar_val = bar_vals[index];
            let region_mask = !(region_info.size.next_power_of_two() - 1);
            bar_masks[index] = region_mask as u32;
            if bar_val & BAR_IO == BAR_IO {
                let MemRange::Emulated(range) = &region.ranges[0] else {
                    unreachable!()
                };
                bars[index] = PciBar::Io(Arc::new(IoRegion {
                    range: range.clone(),
                    callbacks: Mutex::new(vec![]),
                }))
            } else if bar_val & BAR_MEM64 == BAR_MEM64 {
                bar_masks[index + 1] = (region_mask >> 32) as u32;
                bars[index] = PciBar::Mem(Arc::new(region));
            } else {
                bars[index] = PciBar::Mem(Arc::new(region));
            }
        }

        Ok(VfioPciDev {
            config: Arc::new(PciPthConfig {
                header: EmulatedHeader {
                    data: Arc::new(RwLock::new(HeaderData {
                        header: config_header,
                        bar_masks,
                        bdf: Bdf(0),
                    })),
                    bars,
                },
                extra: ExtraConfig {
                    msix_msg_ctrl_hi: AtomicU8::new(0),
                    msix_msg_ctrl_offset,
                    masked_caps,
                    dev: cdev,
                    offset: region_config.offset,
                    size: region_config.size as usize,
                },
            }),
            msix_table,
        })
    }

    fn reset(&self) -> Result<()> {
        let disable_msix = VfioIrqSet {
            argsz: size_of::<VfioIrqSet<0>>() as u32,
            flags: VfioIrqSetFlag::DATA_NONE | VfioIrqSetFlag::ACTION_TRIGGER,
            index: VfioPciIrq::MSIX.raw(),
            start: 0,
            count: 0,
            data: VfioIrqSetData { eventfds: [] },
        };
        self.config.extra.dev.dev.set_irqs(&disable_msix)?;

        self.msix_table.reset();
        self.config.extra.dev.dev.reset()
    }
}

#[derive(Debug)]
struct MsixBarMmio<M, D>
where
    M: MsiSender,
{
    table: Arc<MsixTableMmio<M::IrqFd>>,
    msi_sender: Arc<M>,
    table_range: Range<usize>,
    #[allow(dead_code)]
    pba: Arc<[AtomicU64]>, // TODO
    pba_range: Range<usize>,
    cdev: Arc<VfioDev<D>>,
    cdev_offset: u64,
    region_start: usize,
    region_size: usize,
}

impl<M, D> MsixBarMmio<M, D>
where
    M: MsiSender,
    D: Device,
{
    fn disable_all_irqs(&self) -> Result<()> {
        let vfio_irq_disable_all = VfioIrqSet {
            argsz: size_of::<VfioIrqSet<0>>() as u32,
            flags: VfioIrqSetFlag::DATA_NONE | VfioIrqSetFlag::ACTION_TRIGGER,
            index: VfioPciIrq::MSIX.raw(),
            start: 0,
            count: 0,
            data: VfioIrqSetData { eventfds: [] },
        };
        self.cdev.dev.set_irqs(&vfio_irq_disable_all)
    }

    fn enable_irqfd(&self, index: usize) -> Result<()> {
        let mut entries = self.table.entries.write();
        let Some(entry) = entries.get_mut(index) else {
            log::error!(
                "{}: MSIX-X index {index} is out of range ({})",
                self.cdev.name,
                entries.len()
            );
            return Ok(());
        };
        let MsixTableMmioEntry::Entry(e) = &*entry else {
            return Ok(());
        };
        if e.control.masked() {
            return Ok(());
        }

        log::debug!("{}: enabling irqfd for MSI-X {index}", self.cdev.name);
        let irqfd = self.msi_sender.create_irqfd()?;
        irqfd.set_addr_hi(e.addr_hi)?;
        irqfd.set_addr_lo(e.addr_lo)?;
        irqfd.set_data(e.data)?;
        irqfd.set_masked(false)?;
        *entry = MsixTableMmioEntry::IrqFd(irqfd);

        // If a device IRQ has flag NORESIZE, it must be disabled before a new
        // subindex can be enabled.
        // However if this IRQ has been disabled, VFIO returns error if we try
        // to call disable_all_irqs(). This happens when the guest enables a
        // subindex for the first time.
        // As long as the following set_irqs() succeeds, we can safely ignore
        // the error here.
        let _ = self.disable_all_irqs();

        let mut eventfds = [-1; 2048];
        let mut count = 0;
        for (index, (entry, fd)) in std::iter::zip(entries.iter(), &mut eventfds).enumerate() {
            let MsixTableMmioEntry::IrqFd(irqfd) = entry else {
                continue;
            };
            count = index + 1;
            *fd = irqfd.as_fd().as_raw_fd();
        }
        let vfio_irq_set_eventfd = VfioIrqSet {
            argsz: (size_of::<VfioIrqSet<0>>() + size_of::<i32>() * count) as u32,
            flags: VfioIrqSetFlag::DATA_EVENTFD | VfioIrqSetFlag::ACTION_TRIGGER,
            index: VfioPciIrq::MSIX.raw(),
            start: 0,
            count: count as u32,
            data: VfioIrqSetData { eventfds },
        };
        self.cdev.dev.set_irqs(&vfio_irq_set_eventfd)
    }
}

impl<M, D> Mmio for MsixBarMmio<M, D>
where
    M: MsiSender,
    D: Device,
{
    fn size(&self) -> u64 {
        self.region_size as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let offset = self.region_start + offset as usize;
        let name = &self.cdev.name;
        if offset < self.table_range.end && offset + size as usize > self.table_range.start {
            let offset = offset - self.table_range.start;
            self.table.read(offset as u64, size)
        } else if self.pba_range.contains(&offset) {
            log::error!("{name}: reading pba at {offset:#x}, size={size}: unimplemented",);
            Ok(0)
        } else {
            log::trace!("{name}: emulated BAR read at {offset:#x}, size={size}",);
            self.cdev.dev.read(self.cdev_offset + offset as u64, size)
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let offset = self.region_start + offset as usize;
        let name = &self.cdev.name;
        if offset < self.table_range.end && offset + size as usize > self.table_range.start {
            let offset = offset - self.table_range.start;
            if self.table.write_val(offset as u64, size, val)? {
                self.enable_irqfd(offset / size_of::<MsixTableEntry>())
                    .map_err(boxed_debug_trace)
                    .context(mem::error::Mmio)?;
            }
        } else if self.pba_range.contains(&offset) {
            log::error!(
                "{name}: writing pba at {offset:#x}, size={size}, val={val:#x}: unimplemented",
            );
        } else {
            log::trace!("{name}: emulated BAR write at {offset:#x}, size={size}, val={val:#x}",);
            self.cdev
                .dev
                .write(self.cdev_offset + offset as u64, size, val)?;
        }
        Ok(Action::None)
    }
}
