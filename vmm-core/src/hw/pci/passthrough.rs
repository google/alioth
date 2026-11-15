// Copyright 2026 Google LLC
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

//! Host-agnostic PCI endpoint passthrough device (`PassthroughPciDev`) built
//! exclusively on [`VmmHostCore`].
//!
//! - Virtualizes the Type-0 PCI header (`BAR0..BAR5`, `Command`, `Status`) so guest
//!   BAR sizing/relocation updates Stage-2 NPT without touching physical BARs.
//! - Tracks `Command::BUS_MASTER` and propagates DMA master enable/disable to the
//!   physical function.
//! - Sanitizes the capability list: passes through VirtIO vendor capabilities
//!   (`0x09`) verbatim *except* `VIRTIO_PCI_CAP_PCI_CFG` (`cfg_type == 5`),
//!   virtualizes MSI-X (`0x11`) via `MsixCapMmio` + `MsixTableMmio`, and exposes
//!   PCIe (`0x10`) FLR reset.
//! - Partitions MMIO BARs on 4 KiB boundaries: pages disjoint from MSI-X Table &
//!   PBA use `MemRange::DevMem` (zero VM-exits on VirtIO doorbells/registers),
//!   while pages overlapping MSI-X Table or PBA trap to `MsixTableMmio` / emulated
//!   PBA / `pci_bar_io`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::host::{HvError, PciBarKind, PciDevId, VmmHostCore};
use crate::hw::pci::cap::{
    MsixCap, MsixCapMmio, MsixCapOffset, MsixMsgCtrl, MsixTableEntry, MsixTableMmio, PciCap,
    PciCapHdr, PciCapId, PciCapList,
};
use crate::hw::pci::config::{
    BAR_IO, BAR_MEM32, BAR_MEM64, BAR_PREFETCHABLE, Command, CommonHeader, ConfigHeader,
    DeviceHeader, EmulatedConfig, EmulatedHeader, HeaderType, PciConfig, Status,
};
use crate::hw::pci::{self, Bdf, Pci, PciBar, PciDevice};
use crate::mem::mapped::ArcMemPages;
use crate::mem::mmio::Mmio;
use crate::mem::{self, IoRegion, MemRange, MemRegion, MemRegionEntry, MemRegionType};
use crate::sync::{Mutex, RwLock};

const PCI_CAP_ID_EXP: u8 = 0x10;
const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;
const PCIE_DEVCTL_OFFSET: usize = 0x08;
const PCIE_DEVCTL_BCR_FLR: u16 = 1 << 15;

// Host PCI_COMMAND bits kept enabled while attached (`MEM | IO | INTX_DISABLE`).
const HOST_CMD_BASE: u32 = 0x0001 | 0x0002 | 0x0400;
const HOST_CMD_BUS_MASTER: u32 = 0x0004;

struct AttachedPciGuard {
    host_bdf: u16,
    dev_id: PciDevId,
    hv: Arc<dyn VmmHostCore>,
}

impl Debug for AttachedPciGuard {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachedPciGuard")
            .field("host_bdf", &Bdf(self.host_bdf))
            .field("dev_id", &self.dev_id)
            .finish()
    }
}

impl Drop for AttachedPciGuard {
    fn drop(&mut self) {
        let _ = self.hv.pci_detach(self.dev_id);
    }
}

#[derive(Debug)]
struct RawReadOnlyPciCap {
    bytes: Vec<u8>,
}

impl Mmio for RawReadOnlyPciCap {
    fn size(&self) -> usize {
        self.bytes.len()
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let mut out = 0u64;
        let n = (size as usize).min(8);
        for i in 0..n {
            if let Some(&b) = self.bytes.get(offset + i) {
                out |= (b as u64) << (i * 8);
            }
        }
        Ok(out)
    }

    fn write(&self, _offset: usize, _size: u8, _val: u64) -> mem::Result<()> {
        Ok(())
    }
}

impl PciCap for RawReadOnlyPciCap {
    fn set_next(&mut self, val: u8) {
        if self.bytes.len() >= 2 {
            self.bytes[1] = val;
        }
    }
}

struct PcieEndpointCapMmio {
    bytes: RwLock<Vec<u8>>,
    on_flr: Arc<dyn Fn() + Send + Sync>,
}

impl Debug for PcieEndpointCapMmio {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcieEndpointCapMmio")
            .field("len", &self.bytes.read().len())
            .finish()
    }
}

impl Mmio for PcieEndpointCapMmio {
    fn size(&self) -> usize {
        self.bytes.read().len()
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let bytes = self.bytes.read();
        let mut out = 0u64;
        let n = (size as usize).min(8);
        for i in 0..n {
            if let Some(&b) = bytes.get(offset + i) {
                out |= (b as u64) << (i * 8);
            }
        }
        Ok(out)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        if offset == PCIE_DEVCTL_OFFSET && size == 2 && ((val as u16) & PCIE_DEVCTL_BCR_FLR) != 0 {
            (self.on_flr)();
        }
        Ok(())
    }
}

impl PciCap for PcieEndpointCapMmio {
    fn set_next(&mut self, val: u8) {
        let mut bytes = self.bytes.write();
        if bytes.len() >= 2 {
            bytes[1] = val;
        }
    }
}

struct PassthroughMsixState {
    guard: Arc<AttachedPciGuard>,
    cap: Arc<RwLock<MsixCap>>,
    entries: Arc<Vec<RwLock<MsixTableEntry>>>,
    last_routes: Mutex<Vec<Option<(u64, u32)>>>,
}

impl Debug for PassthroughMsixState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassthroughMsixState")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl PassthroughMsixState {
    fn sync_to_host(&self) {
        let ctrl = self.cap.read().control;
        let globally_active = ctrl.enabled() && !ctrl.masked();
        let mut last = self.last_routes.lock();
        for (idx, entry_lock) in self.entries.iter().enumerate() {
            let desired = if globally_active {
                let e = entry_lock.read();
                let addr = ((e.addr_hi as u64) << 32) | (e.addr_lo as u64);
                if !e.control.masked() && addr != 0 {
                    Some((addr, e.data))
                } else {
                    None
                }
            } else {
                None
            };
            if last[idx] != desired {
                if let Err(err) =
                    self.guard
                        .hv
                        .pci_configure_msix(self.guard.dev_id, idx as u16, desired)
                {
                    log::error!(
                        "{}: pci_configure_msix(entry={idx}, {desired:x?}) failed: {err}",
                        Bdf(self.guard.host_bdf)
                    );
                } else {
                    last[idx] = desired;
                }
            }
        }
    }

    fn reset_state(&self) {
        {
            let mut cap = self.cap.write();
            cap.control.set_enabled(false);
            cap.control.set_masked(false);
        }
        for entry in self.entries.iter() {
            *entry.write() = MsixTableEntry::default();
        }
        let mut last = self.last_routes.lock();
        for (idx, slot) in last.iter_mut().enumerate() {
            if slot.take().is_some() {
                let _ = self
                    .guard
                    .hv
                    .pci_configure_msix(self.guard.dev_id, idx as u16, None);
            }
        }
    }
}

#[derive(Debug)]
struct TrappedBarRegionMmio {
    guard: Arc<AttachedPciGuard>,
    bar_idx: u8,
    base_offset: usize,
    region_size: usize,
    msix_table: Option<(usize, usize, MsixTableMmio)>,
    msix_pba: Option<(usize, usize)>,
}

impl Mmio for TrappedBarRegionMmio {
    fn size(&self) -> usize {
        self.region_size
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let abs = self.base_offset + offset;
        let end = abs + (size as usize);
        if let Some((t_start, t_end, ref tbl)) = self.msix_table
            && abs < t_end
            && end > t_start
        {
            if abs >= t_start && end <= t_end {
                return tbl.read(abs - t_start, size);
            }
            return Ok(0);
        }
        if let Some((p_start, p_end)) = self.msix_pba
            && abs < p_end
            && end > p_start
        {
            return Ok(0);
        }
        Ok(self
            .guard
            .hv
            .pci_bar_io(self.guard.dev_id, self.bar_idx, abs as u64, size, None)?)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let abs = self.base_offset + offset;
        let end = abs + (size as usize);
        if let Some((t_start, t_end, ref tbl)) = self.msix_table
            && abs < t_end
            && end > t_start
        {
            if abs >= t_start && end <= t_end {
                return tbl.write(abs - t_start, size, val);
            }
            return Ok(());
        }
        if let Some((p_start, p_end)) = self.msix_pba
            && abs < p_end
            && end > p_start
        {
            return Ok(());
        }
        self.guard.hv.pci_bar_io(
            self.guard.dev_id,
            self.bar_idx,
            abs as u64,
            size,
            Some(val),
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct PassthroughPciConfig {
    inner: EmulatedConfig,
    guard: Arc<AttachedPciGuard>,
    bus_master_enabled: AtomicBool,
}

impl PassthroughPciConfig {
    fn sync_bus_master(&self) {
        let want_bm = {
            let hdr = self.inner.header.data.read();
            match &hdr.header {
                ConfigHeader::Device(d) => d.common.command.contains(Command::BUS_MASTER),
            }
        };
        let prev = self.bus_master_enabled.swap(want_bm, Ordering::AcqRel);
        if prev != want_bm {
            let phys_cmd = HOST_CMD_BASE | if want_bm { HOST_CMD_BUS_MASTER } else { 0 };
            if let Err(err) = self
                .guard
                .hv
                .pci_write_config(self.guard.dev_id, 0x04, 2, phys_cmd)
            {
                log::error!(
                    "{}: failed updating host BUS_MASTER={want_bm}: {err}",
                    Bdf(self.guard.host_bdf)
                );
            }
        }
    }
}

impl Mmio for PassthroughPciConfig {
    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        self.inner.read(offset, size)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let res = self.inner.write(offset, size, val);
        if offset <= 0x04 && offset + (size as usize) > 0x04 {
            self.sync_bus_master();
        }
        res
    }

    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl PciConfig for PassthroughPciConfig {
    fn get_header(&self) -> &EmulatedHeader {
        self.inner.get_header()
    }
}

#[derive(Debug)]
pub struct PassthroughPciDev {
    guard: Arc<AttachedPciGuard>,
    config: Arc<PassthroughPciConfig>,
    msix: Option<Arc<PassthroughMsixState>>,
}

struct ParsedMsixInfo {
    table_bar: u8,
    table_offset: usize,
    table_size: usize,
    pba_bar: u8,
    pba_offset: usize,
    pba_size: usize,
    tbl_mmio: MsixTableMmio,
    state: Arc<PassthroughMsixState>,
}

fn read_cfg_bytes(
    hv: &dyn VmmHostCore,
    dev_id: PciDevId,
    start: u16,
    len: usize,
) -> Result<Vec<u8>, HvError> {
    let mut out = Vec::with_capacity(len);
    let mut pos = 0usize;
    while pos + 4 <= len && ((start as usize + pos) & 3) == 0 {
        let d = hv.pci_read_config(dev_id, start + pos as u16, 4)?;
        out.extend_from_slice(&d.to_le_bytes());
        pos += 4;
    }
    while pos < len {
        let b = hv.pci_read_config(dev_id, start + pos as u16, 1)? as u8;
        out.push(b);
        pos += 1;
    }
    Ok(out)
}

impl PassthroughPciDev {
    pub fn new(host_bdf: u16, hv: Arc<dyn VmmHostCore>) -> pci::Result<PciDevice> {
        let dev_id = hv.pci_attach(host_bdf).map_err(mem::Error::Hv)?;
        let guard = Arc::new(AttachedPciGuard {
            host_bdf,
            dev_id,
            hv: hv.clone(),
        });

        let id_dword = hv.pci_read_config(dev_id, 0x00, 4).map_err(mem::Error::Hv)?;
        let vendor = (id_dword & 0xffff) as u16;
        let device = (id_dword >> 16) as u16;
        if vendor == 0 || vendor == 0xffff {
            return Err(pci::Error::Memory(mem::Error::Hv(HvError::InvalidParam)));
        }

        let cmd_sts = hv.pci_read_config(dev_id, 0x04, 4).map_err(mem::Error::Hv)?;
        let phys_status = (cmd_sts >> 16) as u16;
        let rev_class = hv.pci_read_config(dev_id, 0x08, 4).map_err(mem::Error::Hv)?;
        let subsys = hv.pci_read_config(dev_id, 0x2c, 4).map_err(mem::Error::Hv)?;

        // Ensure physical MEM | IO | INTX_DISABLE are enabled while BUS_MASTER starts disabled.
        hv.pci_write_config(dev_id, 0x04, 2, HOST_CMD_BASE)
            .map_err(mem::Error::Hv)?;

        let mut header = DeviceHeader {
            common: CommonHeader {
                vendor,
                device,
                command: Command::empty(),
                status: Status::empty(),
                revision: (rev_class & 0xff) as u8,
                prog_if: ((rev_class >> 8) & 0xff) as u8,
                subclass: ((rev_class >> 16) & 0xff) as u8,
                class: ((rev_class >> 24) & 0xff) as u8,
                header_type: HeaderType::Device as u8,
                ..Default::default()
            },
            subsystem_vendor: (subsys & 0xffff) as u16,
            subsystem: (subsys >> 16) as u16,
            intx_line: 0,
            intx_pin: 0,
            ..Default::default()
        };

        let mut caps: Vec<Box<dyn PciCap>> = Vec::new();
        let mut parsed_msix: Option<ParsedMsixInfo> = None;
        let mut pcie_cap_pos_and_bytes: Option<Vec<u8>> = None;

        if (phys_status & Status::CAP.bits()) != 0 {
            let mut pos =
                (hv.pci_read_config(dev_id, 0x34, 1).map_err(mem::Error::Hv)? as u8) & !0x3;
            let mut visited: u64 = 0;

            for _ in 0..48 {
                if pos < 0x40 {
                    break;
                }
                let slot_bit = ((pos - 0x40) >> 2) as u32;
                if slot_bit < 64 {
                    if (visited & (1u64 << slot_bit)) != 0 {
                        break;
                    }
                    visited |= 1u64 << slot_bit;
                }

                let cap_hdr =
                    hv.pci_read_config(dev_id, pos as u16, 2).map_err(mem::Error::Hv)? as u16;
                let cap_id = (cap_hdr & 0xff) as u8;
                let next = ((cap_hdr >> 8) as u8) & !0x3;

                if cap_id == PciCapId::Vendor as u8 {
                    let cap_len = hv
                        .pci_read_config(dev_id, pos as u16 + 2, 1)
                        .map_err(mem::Error::Hv)? as u8;
                    let cfg_type = hv
                        .pci_read_config(dev_id, pos as u16 + 3, 1)
                        .map_err(mem::Error::Hv)? as u8;
                    // Strip `VIRTIO_PCI_CAP_PCI_CFG` (`cfg_type == 5`) so a malicious guest
                    // cannot use the config-space window backdoor to bypass trapped MSI-X pages.
                    if cfg_type != VIRTIO_PCI_CAP_PCI_CFG
                        && cap_len >= 4
                        && (pos as usize) + (cap_len as usize) <= 256
                    {
                        let bytes = read_cfg_bytes(hv.as_ref(), dev_id, pos as u16, cap_len as usize)
                            .map_err(mem::Error::Hv)?;
                        caps.push(Box::new(RawReadOnlyPciCap { bytes }));
                    }
                } else if cap_id == PciCapId::Msix as u8 && parsed_msix.is_none() {
                    let msg_ctrl = hv
                        .pci_read_config(dev_id, pos as u16 + 2, 2)
                        .map_err(mem::Error::Hv)? as u16;
                    let raw_table = hv
                        .pci_read_config(dev_id, pos as u16 + 4, 4)
                        .map_err(mem::Error::Hv)?;
                    let raw_pba = hv
                        .pci_read_config(dev_id, pos as u16 + 8, 4)
                        .map_err(mem::Error::Hv)?;

                    let table_entries = ((msg_ctrl & 0x07ff) as usize) + 1;
                    let table_bar = (raw_table & 0x7) as u8;
                    let table_offset = (raw_table & !0x7) as usize;
                    let table_size = table_entries * size_of::<MsixTableEntry>();

                    let pba_bar = (raw_pba & 0x7) as u8;
                    let pba_offset = (raw_pba & !0x7) as usize;
                    let pba_size = table_entries.div_ceil(64) * 8;

                    let cap_lock = Arc::new(RwLock::new(MsixCap {
                        header: PciCapHdr {
                            id: PciCapId::Msix as u8,
                            next: 0,
                        },
                        control: MsixMsgCtrl(((table_entries as u16) - 1) & 0x07ff),
                        table_offset: MsixCapOffset(raw_table),
                        pba_offset: MsixCapOffset(raw_pba),
                    }));
                    let entries: Arc<Vec<RwLock<MsixTableEntry>>> = Arc::new(
                        (0..table_entries)
                            .map(|_| RwLock::new(MsixTableEntry::default()))
                            .collect(),
                    );
                    let msix_state = Arc::new(PassthroughMsixState {
                        guard: guard.clone(),
                        cap: cap_lock.clone(),
                        entries: entries.clone(),
                        last_routes: Mutex::new(vec![None; table_entries]),
                    });
                    let cap_cb = {
                        let st = msix_state.clone();
                        Arc::new(move || st.sync_to_host())
                    };
                    let tbl_cb = {
                        let st = msix_state.clone();
                        Arc::new(move || st.sync_to_host())
                    };
                    let tbl_mmio = MsixTableMmio {
                        entries,
                        on_change: Some(tbl_cb),
                    };
                    caps.push(Box::new(MsixCapMmio {
                        cap: RwLock::new(cap_lock.read().clone()),
                        on_change: None,
                    }));
                    // Replace the placeholder above so `MsixCapMmio` and `PassthroughMsixState`
                    // share the exact same `RwLock<MsixCap>` instance:
                    caps.pop();
                    caps.push(Box::new(SharedMsixCapMmio {
                        cap: cap_lock,
                        on_change: cap_cb,
                    }));

                    parsed_msix = Some(ParsedMsixInfo {
                        table_bar,
                        table_offset,
                        table_size,
                        pba_bar,
                        pba_offset,
                        pba_size,
                        tbl_mmio,
                        state: msix_state,
                    });
                } else if cap_id == PCI_CAP_ID_EXP && pcie_cap_pos_and_bytes.is_none() {
                    let max_rem = (256usize).saturating_sub(pos as usize).min(0x3c);
                    if max_rem >= 0x10 {
                        let bytes = read_cfg_bytes(hv.as_ref(), dev_id, pos as u16, max_rem)
                            .map_err(mem::Error::Hv)?;
                        pcie_cap_pos_and_bytes = Some(bytes);
                    }
                }

                pos = next;
            }
        }

        let msix_state_opt = parsed_msix.as_ref().map(|m| m.state.clone());

        if let Some(pcie_bytes) = pcie_cap_pos_and_bytes {
            let guard_flr = guard.clone();
            let msix_flr = msix_state_opt.clone();
            caps.push(Box::new(PcieEndpointCapMmio {
                bytes: RwLock::new(pcie_bytes),
                on_flr: Arc::new(move || {
                    if let Some(ref m) = msix_flr {
                        m.reset_state();
                    }
                    let _ = guard_flr.hv.pci_reset(guard_flr.dev_id);
                }),
            }));
        }

        let cap_list = PciCapList::try_from(caps)?;

        let mut bars = PciBar::empty_6();
        let mut bar_masks = [0u32; 6];
        let mut bar_idx = 0u8;

        while bar_idx < 6 {
            let info = hv
                .pci_bar_info(dev_id, bar_idx)
                .map_err(mem::Error::Hv)?;
            match info.kind {
                PciBarKind::Empty => {
                    bar_idx += 1;
                }
                PciBarKind::Io => {
                    let io_size = (info.size as usize).max(4).next_power_of_two();
                    let io_mmio = Arc::new(TrappedBarRegionMmio {
                        guard: guard.clone(),
                        bar_idx,
                        base_offset: 0,
                        region_size: io_size,
                        msix_table: None,
                        msix_pba: None,
                    });
                    bars[bar_idx as usize] = PciBar::Io(Arc::new(IoRegion::new(io_mmio)));
                    bar_masks[bar_idx as usize] = !((io_size as u32) - 1);
                    header.bars[bar_idx as usize] = BAR_IO;
                    bar_idx += 1;
                }
                PciBarKind::Mem32 | PciBarKind::Mem64 => {
                    let is_64 = info.kind == PciBarKind::Mem64;
                    if is_64 && bar_idx >= 5 {
                        return Err(pci::Error::InvalidBar(bar_idx as usize));
                    }
                    let raw_size = (info.size as usize).max(4096).next_power_of_two();
                    let bar_msix_tbl = parsed_msix
                        .as_ref()
                        .filter(|m| m.table_bar == bar_idx)
                        .map(|m| {
                            (
                                m.table_offset,
                                m.table_offset + m.table_size,
                                m.tbl_mmio.clone(),
                            )
                        });
                    let bar_msix_pba = parsed_msix
                        .as_ref()
                        .filter(|m| m.pba_bar == bar_idx)
                        .map(|m| (m.pba_offset, m.pba_offset + m.pba_size));

                    let mut ranges: Vec<MemRange> = Vec::new();
                    if let Some(mem_obj_id) = info.mem_obj
                        && info.size >= 4096
                        && (info.size & 0xfff) == 0
                        && (info.size as usize) == raw_size
                    {
                        let borrowed =
                            ArcMemPages::from_borrowed(hv.clone(), mem_obj_id, raw_size);
                        let mut run_start: Option<usize> = None;

                        let mut page_off = 0usize;
                        while page_off < raw_size {
                            let page_end = page_off + 4096;
                            let overlaps_tbl = bar_msix_tbl
                                .as_ref()
                                .is_some_and(|(s, e, _)| page_off < *e && page_end > *s);
                            let overlaps_pba = bar_msix_pba
                                .as_ref()
                                .is_some_and(|(s, e)| page_off < *e && page_end > *s);

                            if overlaps_tbl || overlaps_pba {
                                if let Some(rs) = run_start.take() {
                                    ranges.push(MemRange::DevMem(
                                        borrowed.subslice(rs, page_off - rs)?,
                                    ));
                                }
                                ranges.push(MemRange::Emulated(Arc::new(TrappedBarRegionMmio {
                                    guard: guard.clone(),
                                    bar_idx,
                                    base_offset: page_off,
                                    region_size: 4096,
                                    msix_table: bar_msix_tbl.clone(),
                                    msix_pba: bar_msix_pba,
                                })));
                            } else if run_start.is_none() {
                                run_start = Some(page_off);
                            }
                            page_off = page_end;
                        }
                        if let Some(rs) = run_start.take() {
                            ranges.push(MemRange::DevMem(
                                borrowed.subslice(rs, raw_size - rs)?,
                            ));
                        }
                    } else {
                        ranges.push(MemRange::Emulated(Arc::new(TrappedBarRegionMmio {
                            guard: guard.clone(),
                            bar_idx,
                            base_offset: 0,
                            region_size: raw_size,
                            msix_table: bar_msix_tbl,
                            msix_pba: bar_msix_pba,
                        })));
                    }

                    let region = Arc::new(MemRegion {
                        size: raw_size,
                        ranges,
                        entries: vec![MemRegionEntry {
                            size: raw_size,
                            type_: MemRegionType::Hidden,
                        }],
                        callbacks: Mutex::new(vec![]),
                    });

                    let full_mask = !((raw_size as u64) - 1);
                    bar_masks[bar_idx as usize] = full_mask as u32;
                    let mut flags = if is_64 { BAR_MEM64 } else { BAR_MEM32 };
                    if info.prefetchable {
                        flags |= BAR_PREFETCHABLE;
                    }
                    header.bars[bar_idx as usize] = flags;
                    if is_64 {
                        bar_masks[bar_idx as usize + 1] = (full_mask >> 32) as u32;
                        bars[bar_idx as usize] = PciBar::Mem64(region);
                        bar_idx += 2;
                    } else {
                        bars[bar_idx as usize] = PciBar::Mem32(region);
                        bar_idx += 1;
                    }
                }
            }
        }

        let emulated = EmulatedConfig::new_device(header, bar_masks, bars, cap_list);
        let config = Arc::new(PassthroughPciConfig {
            inner: emulated,
            guard: guard.clone(),
            bus_master_enabled: AtomicBool::new(false),
        });

        let dev = Arc::new(Self {
            guard,
            config,
            msix: msix_state_opt,
        });
        let name: Arc<String> = Arc::new(format!("pci-passthrough-{}", Bdf(host_bdf)));
        Ok(PciDevice::new(name, dev))
    }
}

struct SharedMsixCapMmio {
    cap: Arc<RwLock<MsixCap>>,
    on_change: Arc<dyn Fn() + Send + Sync>,
}

impl Debug for SharedMsixCapMmio {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedMsixCapMmio")
            .field("cap", &self.cap)
            .finish()
    }
}

impl Mmio for SharedMsixCapMmio {
    fn size(&self) -> usize {
        size_of::<MsixCap>()
    }

    fn read(&self, offset: usize, size: u8) -> Result<u64, mem::Error> {
        let cap = self.cap.read();
        Mmio::read(&*cap, offset, size)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> Result<(), mem::Error> {
        if offset == 2 && size == 2 {
            {
                let mut cap = self.cap.write();
                let ctrl = MsixMsgCtrl(val as u16);
                cap.control.set_enabled(ctrl.enabled());
                cap.control.set_masked(ctrl.masked());
            }
            (self.on_change)();
        }
        Ok(())
    }
}

impl PciCap for SharedMsixCapMmio {
    fn set_next(&mut self, val: u8) {
        self.cap.write().header.next = val;
    }
}

impl Pci for PassthroughPciDev {
    fn config(&self) -> Arc<dyn PciConfig> {
        self.config.clone()
    }

    fn reset(&self) -> pci::Result<()> {
        self.config
            .bus_master_enabled
            .store(false, Ordering::Release);
        if let Some(ref msix) = self.msix {
            msix.reset_state();
        }
        self.guard
            .hv
            .pci_reset(self.guard.dev_id)
            .map_err(|_| pci::Error::ResetFailed)?;
        let _ = self
            .guard
            .hv
            .pci_write_config(self.guard.dev_id, 0x04, 2, HOST_CMD_BASE);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use super::*;
    use crate::host::abi::RawCpuid;
    use crate::host::{
        DoorbellSpec, HostCaps, HvResult, IoSpace, MemObjId, MemProt, PciBarInfo, RegId, RegVal,
        VcpuId, VmEntry,
    };
    use crate::mem::{AddrOpt, Memory};

    struct MockPassthroughHost {
        cfg: Mutex<[u8; 256]>,
        gpa_mappings: Mutex<BTreeMap<u64, (u64, MemObjId, u64, MemProt)>>,
        msix_routes: Mutex<BTreeMap<u16, Option<(u64, u32)>>>,
        bar_io_log: Mutex<Vec<(u8, u64, u8, Option<u64>)>>,
        reset_count: Mutex<u32>,
        detached: AtomicBool,
    }

    impl MockPassthroughHost {
        fn new() -> Arc<Self> {
            let mut cfg = [0u8; 256];
            // Vendor 0x1af4, Device 0x1041 (VirtIO Net)
            cfg[0x00..0x02].copy_from_slice(&0x1af4u16.to_le_bytes());
            cfg[0x02..0x04].copy_from_slice(&0x1041u16.to_le_bytes());
            // Status: CAP (0x0010)
            cfg[0x06..0x08].copy_from_slice(&0x0010u16.to_le_bytes());
            // Class 0x02_00_00, rev 1
            cfg[0x08] = 1;
            cfg[0x0a] = 0x00;
            cfg[0x0b] = 0x02;
            // Cap pointer -> 0x40
            cfg[0x34] = 0x40;

            // Cap 1 @ 0x40: MSI-X (0x11), next = 0x50, 3 vectors (ctrl = 2),
            // Table @ BAR0 + 0x0000, PBA @ BAR0 + 0x2000
            cfg[0x40] = 0x11;
            cfg[0x41] = 0x50;
            cfg[0x42..0x44].copy_from_slice(&2u16.to_le_bytes());
            cfg[0x44..0x48].copy_from_slice(&0x0000u32.to_le_bytes());
            cfg[0x48..0x4c].copy_from_slice(&0x2000u32.to_le_bytes());

            // Cap 2 @ 0x50: VirtIO CommonCfg (cfg_type = 1), next = 0x60, len = 16, BAR0 + 0x3000
            cfg[0x50] = 0x09;
            cfg[0x51] = 0x60;
            cfg[0x52] = 16;
            cfg[0x53] = 1;
            cfg[0x54] = 0;
            cfg[0x58..0x5c].copy_from_slice(&0x3000u32.to_le_bytes());
            cfg[0x5c..0x60].copy_from_slice(&0x0038u32.to_le_bytes());

            // Cap 3 @ 0x60: VirtIO PCI_CFG backdoor (cfg_type = 5), next = 0x00, len = 20 -> MUST BE STRIPPED!
            cfg[0x60] = 0x09;
            cfg[0x61] = 0x00;
            cfg[0x62] = 20;
            cfg[0x63] = 5;

            Arc::new(Self {
                cfg: Mutex::new(cfg),
                gpa_mappings: Mutex::new(BTreeMap::new()),
                msix_routes: Mutex::new(BTreeMap::new()),
                bar_io_log: Mutex::new(Vec::new()),
                reset_count: Mutex::new(0),
                detached: AtomicBool::new(false),
            })
        }
    }

    impl VmmHostCore for MockPassthroughHost {
        fn caps(&self) -> HostCaps {
            HostCaps::empty()
        }
        fn supported_cpuids(&self, _dst: &mut [RawCpuid]) -> HvResult<usize> {
            Ok(0)
        }
        fn vcpu_configure(&self, _vcpu: VcpuId, _cpuids: &[RawCpuid]) -> HvResult<()> {
            Ok(())
        }
        fn vcpu_get_regs(&self, _vcpu: VcpuId, _ids: &[RegId], _out: &mut [RegVal]) -> HvResult<()> {
            Ok(())
        }
        fn vcpu_set_regs(&self, _vcpu: VcpuId, _regs: &[(RegId, RegVal)]) -> HvResult<()> {
            Ok(())
        }
        fn vcpu_kick(&self, _vcpu: VcpuId) -> HvResult<()> {
            Ok(())
        }
        fn mem_alloc(&self, _size: u64) -> HvResult<MemObjId> {
            Ok(1)
        }
        fn mem_free(&self, _obj: MemObjId) -> HvResult<()> {
            panic!("borrowed BAR MemObjId must never be freed via mem_free!");
        }
        fn mem_read(&self, _obj: MemObjId, _offset: u64, _dst: &mut [u8]) -> HvResult<()> {
            Err(HvError::Unsupported)
        }
        fn mem_write(&self, _obj: MemObjId, _offset: u64, _src: &[u8]) -> HvResult<()> {
            Err(HvError::Unsupported)
        }
        fn gpa_map(
            &self,
            gpa: u64,
            size: u64,
            obj: MemObjId,
            offset: u64,
            prot: MemProt,
        ) -> HvResult<()> {
            self.gpa_mappings
                .lock()
                .insert(gpa, (size, obj, offset, prot));
            Ok(())
        }
        fn gpa_unmap(&self, gpa: u64, _size: u64) -> HvResult<()> {
            self.gpa_mappings.lock().remove(&gpa);
            Ok(())
        }
        fn inject_msi(&self, _addr: u64, _data: u32) -> HvResult<()> {
            Ok(())
        }
        fn set_gsi_level(&self, _gsi: u32, _active: bool) -> HvResult<()> {
            Ok(())
        }
        fn register_doorbell(&self, _spec: DoorbellSpec) -> HvResult<()> {
            Ok(())
        }
        fn unregister_doorbell(&self, _space: IoSpace, _addr: u64, _size: u8) -> HvResult<()> {
            Ok(())
        }
        fn pci_attach(&self, host_bdf: u16) -> HvResult<PciDevId> {
            assert_eq!(host_bdf, 0x0018);
            Ok(7)
        }
        fn pci_detach(&self, dev: PciDevId) -> HvResult<()> {
            assert_eq!(dev, 7);
            self.detached.store(true, Ordering::Release);
            Ok(())
        }
        fn pci_reset(&self, dev: PciDevId) -> HvResult<()> {
            assert_eq!(dev, 7);
            *self.reset_count.lock() += 1;
            Ok(())
        }
        fn pci_read_config(&self, dev: PciDevId, offset: u16, size: u8) -> HvResult<u32> {
            assert_eq!(dev, 7);
            let cfg = self.cfg.lock();
            let o = offset as usize;
            let val = match size {
                1 => cfg[o] as u32,
                2 => u16::from_le_bytes(cfg[o..o + 2].try_into().unwrap()) as u32,
                4 => u32::from_le_bytes(cfg[o..o + 4].try_into().unwrap()),
                _ => return Err(HvError::InvalidParam),
            };
            Ok(val)
        }
        fn pci_write_config(
            &self,
            dev: PciDevId,
            offset: u16,
            size: u8,
            val: u32,
        ) -> HvResult<()> {
            assert_eq!(dev, 7);
            let mut cfg = self.cfg.lock();
            let o = offset as usize;
            match size {
                1 => cfg[o] = val as u8,
                2 => cfg[o..o + 2].copy_from_slice(&(val as u16).to_le_bytes()),
                4 => cfg[o..o + 4].copy_from_slice(&val.to_le_bytes()),
                _ => return Err(HvError::InvalidParam),
            }
            Ok(())
        }
        fn pci_bar_info(&self, dev: PciDevId, bar_idx: u8) -> HvResult<PciBarInfo> {
            assert_eq!(dev, 7);
            if bar_idx == 0 {
                Ok(PciBarInfo {
                    kind: PciBarKind::Mem64,
                    prefetchable: false,
                    size: 0x4000,
                    mem_obj: Some(99),
                })
            } else {
                Ok(PciBarInfo::default())
            }
        }
        fn pci_bar_io(
            &self,
            dev: PciDevId,
            bar_idx: u8,
            offset: u64,
            size: u8,
            write: Option<u64>,
        ) -> HvResult<u64> {
            assert_eq!(dev, 7);
            self.bar_io_log.lock().push((bar_idx, offset, size, write));
            Ok(0xdead_beef)
        }
        fn pci_configure_msix(
            &self,
            dev: PciDevId,
            entry_idx: u16,
            guest_msi: Option<(u64, u32)>,
        ) -> HvResult<()> {
            assert_eq!(dev, 7);
            self.msix_routes.lock().insert(entry_idx, guest_msi);
            Ok(())
        }
    }

    #[test]
    fn test_passthrough_pci_dev_cap_filtering_bar_carving_and_msix() {
        let host = MockPassthroughHost::new();
        let hv: Arc<dyn VmmHostCore> = host.clone();
        let memory = Memory::new(hv.clone());

        let pci_dev = PassthroughPciDev::new(0x0018, hv).unwrap();
        let cfg = pci_dev.dev.config();

        // 1. Verify capability filtering: MSI-X (0x11) + CommonCfg (0x09, type 1) present,
        //    while PCI_CFG backdoor (type 5) was stripped (`next == 0` on second cap).
        let cap0_ptr = cfg.read(0x34, 1).unwrap() as usize;
        assert_eq!(cap0_ptr, 0x40);
        assert_eq!(cfg.read(cap0_ptr, 1).unwrap(), 0x11);
        let cap1_ptr = cfg.read(cap0_ptr + 1, 1).unwrap() as usize;
        assert!(cap1_ptr >= 0x4c);
        assert_eq!(cfg.read(cap1_ptr, 1).unwrap(), 0x09);
        assert_eq!(cfg.read(cap1_ptr + 3, 1).unwrap(), 1);
        assert_eq!(cfg.read(cap1_ptr + 1, 1).unwrap(), 0); // End of chain: type 5 stripped!

        // 2. Map BAR0 (16 KiB) into Memory and verify 4 KiB carving:
        //    - [0x0000..0x1000): Emulated (MSI-X Table)
        //    - [0x1000..0x2000): DevMem (Stage-2 NPT mapped, obj=99, off=0x1000)
        //    - [0x2000..0x3000): Emulated (MSI-X PBA)
        //    - [0x3000..0x4000): DevMem (Stage-2 NPT mapped, obj=99, off=0x3000 — VirtIO regs!)
        let PciBar::Mem64(bar0_region) = &cfg.get_header().bars[0] else {
            panic!("expected Mem64 BAR0");
        };
        let bar_gpa = memory
            .add_region(AddrOpt::Above4G, bar0_region.clone())
            .unwrap();
        cfg.get_header().set_command(Command::MEM);

        {
            let maps = host.gpa_mappings.lock();
            assert_eq!(maps.len(), 2);
            assert_eq!(
                maps.get(&(bar_gpa + 0x1000)),
                Some(&(0x1000, 99, 0x1000, MemProt::READ | MemProt::WRITE))
            );
            assert_eq!(
                maps.get(&(bar_gpa + 0x3000)),
                Some(&(0x1000, 99, 0x3000, MemProt::READ | MemProt::WRITE))
            );
        }
        // DevMem MUST NOT appear in Guest RamBus!
        assert!(memory.ram_bus().read::<u32>(bar_gpa + 0x3000).is_err());

        // 3. Program MSI-X entry 1 in BAR0 + 0x0010 and enable MsixCapMmio:
        memory
            .handle_mmio(bar_gpa + 0x10, Some(0xfee0_1000), 4)
            .unwrap();
        memory.handle_mmio(bar_gpa + 0x14, Some(0), 4).unwrap();
        memory.handle_mmio(bar_gpa + 0x18, Some(0x45), 4).unwrap();
        memory.handle_mmio(bar_gpa + 0x1c, Some(0), 4).unwrap(); // Unmask entry 1

        // Still not globally enabled until MsixMsgCtrl bit 15 is set:
        assert!(host.msix_routes.lock().is_empty());
        cfg.write(cap0_ptr + 2, 2, 0x8000).unwrap();
        assert_eq!(
            host.msix_routes.lock().get(&1),
            Some(&Some((0xfee0_1000, 0x45)))
        );

        // Non-MSI-X bytes on shared page 0x0000..0x1000 forward to `pci_bar_io`:
        let read_entry = memory.handle_mmio(bar_gpa + 0x0800, None, 4).unwrap();
        assert_eq!(read_entry, VmEntry::Mmio { data: 0xdead_beef });
        assert_eq!(host.bar_io_log.lock().len(), 1);

        // 4. Toggle Command::BUS_MASTER and verify physical PCI_COMMAND propagation:
        let _ = cfg.write(0x04, 2, (Command::MEM | Command::BUS_MASTER).bits() as u64);
        let phys_cmd = u16::from_le_bytes(host.cfg.lock()[0x04..0x06].try_into().unwrap());
        assert_ne!(phys_cmd & (HOST_CMD_BUS_MASTER as u16), 0);

        // 5. Reset and drop:
        pci_dev.dev.reset().unwrap();
        assert_eq!(host.msix_routes.lock().get(&1), Some(&None));
        assert_eq!(*host.reset_count.lock(), 1);

        memory.remove_region(bar_gpa).unwrap();
        drop(cfg);
        drop(pci_dev);
        assert!(host.detached.load(Ordering::Acquire));
    }
}
