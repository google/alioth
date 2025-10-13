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

use std::cmp::min;
use std::fs::File;
use std::iter::zip;
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use alioth_macros::Layout;
use libc::{PROT_READ, PROT_WRITE};
use parking_lot::{Mutex, RwLock};
use zerocopy::{FromBytes, Immutable, IntoBytes, transmute};

use crate::errors::BoxTrace;
use crate::hv::{IrqFd, MsiSender};
use crate::mem::emulated::{Action, Mmio, MmioBus};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{IoRegion, MemRange, MemRegion, MemRegionEntry, MemRegionType};
use crate::pci::cap::{
    MsiCapHdr, MsiMsgCtrl, MsixCap, MsixCapMmio, MsixTableEntry, MsixTableMmio, MsixTableMmioEntry,
    NullCap, PciCapHdr, PciCapId,
};
use crate::pci::config::{
    BAR_IO, BAR_MEM64, Command, CommonHeader, ConfigHeader, DeviceHeader, EmulatedHeader,
    HeaderData, HeaderType, PciConfig, PciConfigArea, Status,
};
use crate::pci::{self, Bdf, Pci, PciBar};
use crate::sys::vfio::{
    VfioIrqSet, VfioIrqSetData, VfioIrqSetFlag, VfioPciIrq, VfioPciRegion, VfioRegionInfo,
    VfioRegionInfoFlag,
};
use crate::vfio::device::Device;
use crate::vfio::{Result, error};
use crate::{align_down, align_up, impl_mmio_for_zerocopy, mem};

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
struct VfioDev<D> {
    name: Arc<str>,
    dev: D,
}

#[derive(Debug)]
struct PthConfigArea<D> {
    offset: u64, // offset to dev
    size: u64,
    dev: Arc<VfioDev<D>>,
}

impl<D> Mmio for PthConfigArea<D>
where
    D: Device,
{
    fn size(&self) -> u64 {
        self.size
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        self.dev.dev.read(self.offset + offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        self.dev.dev.write(self.offset + offset, size, val)?;
        Ok(Action::None)
    }
}

impl<D> PciConfigArea for PthConfigArea<D>
where
    D: Device,
{
    fn reset(&self) {}
}

#[derive(Debug)]
pub struct PciPthConfig<D> {
    header: EmulatedHeader,
    extra: MmioBus<Box<dyn PciConfigArea>>,
    dev: Arc<VfioDev<D>>,
}

impl<D> Mmio for PciPthConfig<D>
where
    D: Device,
{
    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        if offset < self.header.size() {
            Mmio::read(&self.header, offset, size)
        } else {
            self.extra.read(offset, size)
        }
    }

    fn size(&self) -> u64 {
        4096
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        if offset < self.header.size() {
            Mmio::write(&self.header, offset, size, val)
        } else {
            self.extra.write(offset, size, val)
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
        for (_, area) in self.extra.inner.iter() {
            area.reset();
        }
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
    config: PciPthConfig<D>,
    msix_table: Arc<MsixTableMmio<M::IrqFd>>,
}

impl<M, D> Pci for VfioPciDev<M, D>
where
    D: Device,
    M: MsiSender,
{
    fn config(&self) -> &dyn PciConfig {
        &self.config
    }

    fn reset(&self) -> pci::Result<()> {
        let ret = VfioPciDev::reset(self);
        ret.box_trace(pci::error::Reset)?;
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

        let msi_sender = Arc::new(msi_sender);

        let region_config = cdev.dev.get_region_info(VfioPciRegion::CONFIG.raw())?;

        let pci_command = Command::IO | Command::MEM | Command::BUS_MASTER | Command::INTX_DISABLE;
        cdev.dev.write(
            region_config.offset + CommonHeader::OFFSET_COMMAND as u64,
            CommonHeader::SIZE_COMMAND as u8,
            pci_command.bits() as _,
        )?;
        let mut buf: [u8; 4096] = transmute!([0u32; 1024]);
        cdev.dev.fd().read_at(&mut buf, region_config.offset)?;

        let (mut dev_header, _) = DeviceHeader::read_from_prefix(&buf).unwrap();
        dev_header.common.header_type &= !(1 << 7);
        if dev_header.common.header_type != HeaderType::Device as u8 {
            return error::NotSupportedHeader {
                ty: dev_header.common.header_type,
            }
            .fail();
        }
        dev_header.intx_pin = 0;
        dev_header.common.command = Command::empty();

        let mut masked_caps: Vec<(u64, Box<dyn PciConfigArea>)> = vec![];
        let mut msix_info = None;
        let mut msi_info = None;

        if dev_header.common.status.contains(Status::CAP) {
            let mut cap_offset = dev_header.capability_pointer as usize;
            while cap_offset != 0 {
                let Some(cap_buf) = buf.get(cap_offset..) else {
                    log::error!("{}: invalid cap offset: {cap_offset:#x}", cdev.name);
                    break;
                };
                let (cap_header, _) = PciCapHdr::ref_from_prefix(cap_buf).unwrap();
                if cap_header.id == PciCapId::Msix as u8 {
                    let Ok((mut c, _)) = MsixCap::read_from_prefix(cap_buf) else {
                        log::error!(
                            "{}: MSIX capability is at an invalid offset: {cap_offset:#x}",
                            cdev.name
                        );
                        continue;
                    };
                    c.control.set_enabled(false);
                    c.control.set_masked(false);
                    msix_info = Some((cap_offset, c.clone()));
                } else if cap_header.id == PciCapId::Msi as u8 {
                    let Ok((mut c, _)) = MsiCapHdr::read_from_prefix(cap_buf) else {
                        log::error!(
                            "{}: MSI capability is at an invalid offset: {cap_offset:#x}",
                            cdev.name
                        );
                        continue;
                    };
                    log::info!("{}: MSI cap header: {c:#x?}", cdev.name);
                    c.control.set_enable(false);
                    c.control.set_ext_msg_data_cap(true);
                    let multi_msg_cap = min(5, c.control.multi_msg_cap());
                    c.control.set_multi_msg_cap(multi_msg_cap);
                    msi_info = Some((cap_offset, c));
                }
                cap_offset = cap_header.next as usize;
            }
        }

        let mut msix_cap = None;
        if let Some((offset, cap)) = msix_info {
            msix_cap = Some(cap.clone());
            let msix_cap_mmio = MsixCapMmio {
                cap: RwLock::new(cap),
            };
            masked_caps.push((offset as u64, Box::new(msix_cap_mmio)));
            if let Some((offset, hdr)) = msi_info {
                let null_cap = NullCap {
                    size: hdr.control.cap_size(),
                    next: hdr.header.next,
                };
                masked_caps.push((offset as u64, Box::new(null_cap)));
            }
        } else if let Some((offset, hdr)) = msi_info {
            let count = 1 << hdr.control.multi_msg_cap();
            let irqfds = (0..count)
                .map(|_| msi_sender.create_irqfd())
                .collect::<Result<Box<_>, _>>()?;

            let mut eventfds = [-1; 32];
            for (fd, irqfd) in zip(&mut eventfds, &irqfds) {
                *fd = irqfd.as_fd().as_raw_fd();
            }
            let set_eventfd = VfioIrqSet {
                argsz: (size_of::<VfioIrqSet<0>>() + size_of::<i32>() * count) as u32,
                flags: VfioIrqSetFlag::DATA_EVENTFD | VfioIrqSetFlag::ACTION_TRIGGER,
                index: VfioPciIrq::MSI.raw(),
                start: 0,
                count: count as u32,
                data: VfioIrqSetData { eventfds },
            };
            cdev.dev.set_irqs(&set_eventfd)?;

            let msi_cap_mmio = MsiCapMmio::<M, D> {
                cap: RwLock::new((hdr, MsiCapBody { data: [0; 4] })),
                dev: cdev.clone(),
                irqfds,
            };
            masked_caps.push((offset as u64, Box::new(msi_cap_mmio)));
        }

        let mut extra_areas: MmioBus<Box<dyn PciConfigArea>> = MmioBus::new();
        masked_caps.sort_by_key(|(offset, _)| *offset);
        let mut area_end = 0x40;
        for (offset, cap) in masked_caps {
            if area_end < offset {
                extra_areas.add(
                    area_end,
                    Box::new(PthConfigArea {
                        offset: region_config.offset + area_end,
                        size: offset - area_end,
                        dev: cdev.clone(),
                    }),
                )?;
            }
            area_end = offset + Mmio::size(&*cap);
            extra_areas.add(offset, cap)?;
        }
        if area_end < region_config.size {
            extra_areas.add(
                area_end,
                Box::new(PthConfigArea {
                    offset: region_config.offset + area_end,
                    size: region_config.size - area_end,
                    dev: cdev.clone(),
                }),
            )?;
        }

        let config_header = ConfigHeader::Device(dev_header);

        cdev.dev.reset()?;

        let msix_count = match &msix_cap {
            Some(cap) => cap.control.table_len() + 1,
            None => 0,
        };
        let msix_entries = RwLock::new(
            (0..msix_count)
                .map(|_| MsixTableMmioEntry::Entry(MsixTableEntry::default()))
                .collect(),
        );

        let msix_table = Arc::new(MsixTableMmio {
            entries: msix_entries,
        });

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
            config: PciPthConfig {
                header: EmulatedHeader {
                    data: Arc::new(RwLock::new(HeaderData {
                        header: config_header,
                        bar_masks,
                        bdf: Bdf(0),
                    })),
                    bars,
                },
                extra: extra_areas,
                dev: cdev,
            },
            msix_table,
        })
    }

    fn reset(&self) -> Result<()> {
        let is_irqfd = |e| matches!(e, &MsixTableMmioEntry::IrqFd(_));
        if self.msix_table.entries.read().iter().any(is_irqfd) {
            let dev = &self.config.dev;
            if let Err(e) = dev.dev.disable_all_irqs(VfioPciIrq::MSIX) {
                log::error!("{}: failed to disable MSIX IRQs: {e:?}", dev.name)
            }
        }

        self.msix_table.reset();
        self.config.dev.dev.reset()
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
        let _ = self.cdev.dev.disable_all_irqs(VfioPciIrq::MSIX);

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
                    .box_trace(mem::error::Mmio)?;
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

#[derive(Debug, Default, Clone, FromBytes, Immutable, IntoBytes, Layout)]
#[repr(C)]
struct MsiCapBody {
    data: [u32; 4],
}
impl_mmio_for_zerocopy!(MsiCapBody);

#[derive(Debug)]
struct MsiCapMmio<M, D>
where
    M: MsiSender,
{
    cap: RwLock<(MsiCapHdr, MsiCapBody)>,
    dev: Arc<VfioDev<D>>,
    irqfds: Box<[M::IrqFd]>,
}

impl<M, D> MsiCapMmio<M, D>
where
    M: MsiSender,
    D: Device,
{
    fn update_msi(&self) -> Result<()> {
        let (hdr, body) = &*self.cap.read();
        let ctrl = &hdr.control;
        let data = &body.data;
        let msg_mask = if ctrl.ext_msg_data() {
            u32::MAX
        } else {
            0xffff
        };
        let (addr, msg) = if ctrl.addr_64_cap() {
            (
                ((data[1] as u64) << 32) | data[0] as u64,
                data[2] & msg_mask,
            )
        } else {
            (data[0] as u64, data[1] & msg_mask)
        };
        let mask = match (ctrl.addr_64_cap(), ctrl.per_vector_masking_cap()) {
            (true, true) => data[3],
            (false, true) => data[2],
            (_, false) => 0,
        };
        let count = 1 << ctrl.multi_msg();
        for (index, irqfd) in self.irqfds.iter().enumerate() {
            irqfd.set_masked(true)?;
            if !ctrl.enable() || index >= count || mask & (1 << index) > 0 {
                continue;
            }
            let msg = msg | index as u32;
            irqfd.set_addr_hi((addr >> 32) as u32)?;
            irqfd.set_addr_lo(addr as u32)?;
            irqfd.set_data(msg)?;
            irqfd.set_masked(false)?;
        }
        Ok(())
    }
}

impl<M, D> Mmio for MsiCapMmio<M, D>
where
    D: Device,
    M: MsiSender,
{
    fn size(&self) -> u64 {
        let (hdr, _) = &*self.cap.read();
        hdr.control.cap_size() as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let (hdr, body) = &*self.cap.read();
        let ctrl = hdr.control;
        match offset {
            0..4 => hdr.read(offset, size),
            0x10 if ctrl.per_vector_masking_cap() && !ctrl.addr_64_cap() => Ok(0),
            0x14 if ctrl.per_vector_masking_cap() && ctrl.addr_64_cap() => Ok(0),
            _ => body.read(offset - size_of_val(hdr) as u64, size),
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let mut need_update = false;
        let mut cap = self.cap.write();
        let (hdr, body) = &mut *cap;
        match (offset as usize, size) {
            (0x2, 2) => {
                let ctrl = &mut hdr.control;
                let new_ctrl = MsiMsgCtrl(val as u16);
                if !ctrl.enable() || !new_ctrl.enable() {
                    let multi_msg = min(ctrl.multi_msg_cap(), new_ctrl.multi_msg());
                    ctrl.set_multi_msg(multi_msg);
                }
                need_update = ctrl.enable() != new_ctrl.enable()
                    || (new_ctrl.enable() && ctrl.ext_msg_data() != new_ctrl.ext_msg_data());
                ctrl.set_ext_msg_data(new_ctrl.ext_msg_data());
                ctrl.set_enable(new_ctrl.enable());
            }
            (0x4 | 0x8 | 0xc | 0x10, 2 | 4) => {
                let data_offset = (offset as usize - size_of_val(hdr)) >> 2;
                let reg = &mut body.data[data_offset];
                need_update = hdr.control.enable() && *reg != val as u32;
                *reg = val as u32;
            }
            _ => log::error!(
                "{}: write 0x{val:0width$x} to invalid offset 0x{offset:x}.",
                self.dev.name,
                width = 2 * size as usize
            ),
        }
        drop(cap);
        if need_update {
            self.update_msi().box_trace(mem::error::Mmio)?;
        }
        Ok(Action::None)
    }
}

impl<M, D> PciConfigArea for MsiCapMmio<M, D>
where
    D: Device,
    M: MsiSender,
{
    fn reset(&self) {
        {
            let (hdr, _) = &mut *self.cap.write();
            hdr.control.set_enable(false);
        }
        if let Err(e) = self.update_msi() {
            log::error!("{}: failed to reset: {e:?}", self.dev.name);
        }
    }
}
