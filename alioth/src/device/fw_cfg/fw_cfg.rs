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

#[cfg(target_arch = "x86_64")]
pub mod acpi;

use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read, Result, Seek, SeekFrom};
#[cfg(target_arch = "x86_64")]
use std::mem::size_of;
use std::mem::size_of_val;
use std::os::unix::fs::FileExt;
#[cfg(target_arch = "x86_64")]
use std::path::Path;
use std::sync::Arc;

use alioth_macros::Layout;
use bitfield::bitfield;
use parking_lot::Mutex;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_aco::Help;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[cfg(target_arch = "x86_64")]
use crate::arch::layout::{
    PORT_FW_CFG_DATA, PORT_FW_CFG_DMA_HI, PORT_FW_CFG_DMA_LO, PORT_FW_CFG_SELECTOR,
};
#[cfg(target_arch = "x86_64")]
use crate::firmware::acpi::AcpiTable;
#[cfg(target_arch = "x86_64")]
use crate::loader::linux::bootparams::{
    BootE820Entry, BootParams, E820_ACPI, E820_PMEM, E820_RAM, E820_RESERVED,
};
use crate::mem;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::RamBus;
#[cfg(target_arch = "x86_64")]
use crate::mem::{MemRegionEntry, MemRegionType};
use crate::utils::endian::{Bu16, Bu32, Bu64, Lu32};

#[cfg(target_arch = "x86_64")]
use self::acpi::create_acpi_loader;

pub const SELECTOR_WR: u16 = 1 << 14;

pub const FW_CFG_SIGNATURE: u16 = 0x00;
pub const FW_CFG_ID: u16 = 0x01;
pub const FW_CFG_UUID: u16 = 0x02;
pub const FW_CFG_RAM_SIZE: u16 = 0x03;
pub const FW_CFG_NOGRAPHIC: u16 = 0x04;
pub const FW_CFG_NB_CPUS: u16 = 0x05;
pub const FW_CFG_MACHINE_ID: u16 = 0x06;
pub const FW_CFG_KERNEL_ADDR: u16 = 0x07;
pub const FW_CFG_KERNEL_SIZE: u16 = 0x08;
pub const FW_CFG_KERNEL_CMDLINE: u16 = 0x09;
pub const FW_CFG_INITRD_ADDR: u16 = 0x0a;
pub const FW_CFG_INITRD_SIZE: u16 = 0x0b;
pub const FW_CFG_BOOT_DEVICE: u16 = 0x0c;
pub const FW_CFG_NUMA: u16 = 0x0d;
pub const FW_CFG_BOOT_MENU: u16 = 0x0e;
pub const FW_CFG_MAX_CPUS: u16 = 0x0f;
pub const FW_CFG_KERNEL_ENTRY: u16 = 0x10;
pub const FW_CFG_KERNEL_DATA: u16 = 0x11;
pub const FW_CFG_INITRD_DATA: u16 = 0x12;
pub const FW_CFG_CMDLINE_ADDR: u16 = 0x13;
pub const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
pub const FW_CFG_CMDLINE_DATA: u16 = 0x15;
pub const FW_CFG_SETUP_ADDR: u16 = 0x16;
pub const FW_CFG_SETUP_SIZE: u16 = 0x17;
pub const FW_CFG_SETUP_DATA: u16 = 0x18;
pub const FW_CFG_FILE_DIR: u16 = 0x19;
pub const FW_CFG_KNOWN_ITEMS: usize = 0x20;

pub const FW_CFG_FILE_FIRST: u16 = 0x20;
pub const FW_CFG_DMA_SIGNATURE: [u8; 8] = *b"QEMU CFG";
pub const FW_CFG_FEATURE: [u8; 4] = [0b11, 0, 0, 0];

pub const FILE_NAME_SIZE: usize = 56;

fn create_file_name(name: &str) -> [u8; FILE_NAME_SIZE] {
    let mut c_name = [0u8; FILE_NAME_SIZE];
    let c_len = std::cmp::min(FILE_NAME_SIZE - 1, name.len());
    c_name[0..c_len].copy_from_slice(&name.as_bytes()[0..c_len]);
    c_name
}

#[derive(Debug)]
pub enum FwCfgContent {
    Bytes(Vec<u8>),
    Slice(&'static [u8]),
    File(u64, File),
    Lu32(Lu32),
}

struct FwCfgContentAccess<'a> {
    content: &'a FwCfgContent,
    offset: u32,
}

impl Read for FwCfgContentAccess<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.content {
            FwCfgContent::File(offset, f) => {
                Seek::seek(&mut (&*f), SeekFrom::Start(offset + self.offset as u64))?;
                Read::read(&mut (&*f), buf)
            }
            FwCfgContent::Bytes(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Slice(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Lu32(n) => match n.as_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
        }
    }
}

impl Default for FwCfgContent {
    fn default() -> Self {
        FwCfgContent::Slice(&[])
    }
}

impl FwCfgContent {
    fn size(&self) -> Result<u32> {
        let ret = match self {
            FwCfgContent::Bytes(v) => v.len(),
            FwCfgContent::File(offset, f) => (f.metadata()?.len() - offset) as usize,
            FwCfgContent::Slice(s) => s.len(),
            FwCfgContent::Lu32(n) => size_of_val(n),
        };
        u32::try_from(ret).map_err(|_| std::io::ErrorKind::InvalidInput.into())
    }

    fn access(&self, offset: u32) -> FwCfgContentAccess<'_> {
        FwCfgContentAccess {
            content: self,
            offset,
        }
    }

    fn read(&self, offset: u32) -> Option<u8> {
        match self {
            FwCfgContent::Bytes(b) => b.get(offset as usize).copied(),
            FwCfgContent::Slice(s) => s.get(offset as usize).copied(),
            FwCfgContent::File(o, f) => {
                let mut buf = [0u8];
                match f.read_exact_at(&mut buf, o + offset as u64) {
                    Ok(_) => Some(buf[0]),
                    Err(e) => {
                        log::error!("fw_cfg: reading {f:?}: {e:?}");
                        None
                    }
                }
            }
            FwCfgContent::Lu32(n) => n.as_bytes().get(offset as usize).copied(),
        }
    }
}

#[derive(Debug, Default)]
pub struct FwCfgItem {
    pub name: String,
    pub content: FwCfgContent,
}

/// https://www.qemu.org/docs/master/specs/fw_cfg.html
#[derive(Debug)]
pub struct FwCfg {
    selector: u16,
    data_offset: u32,
    dma_address: u64,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
    memory: Arc<RamBus>,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, Layout)]
struct FwCfgDmaAccess {
    control: Bu32,
    length: Bu32,
    address: Bu64,
}

bitfield! {
    struct AccessControl(u32);
    impl Debug;
    error, set_error: 0;
    read, _: 1;
    skip, _: 2;
    select, _ : 3;
    write, _ :4;
    selector, _: 31, 16;
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
struct FwCfgFilesHeader {
    count: Bu32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
struct FwCfgFile {
    size: Bu32,
    select: Bu16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

impl FwCfg {
    pub fn new(memory: Arc<RamBus>, items: Vec<FwCfgItem>) -> Result<Self> {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_DMA_SIGNATURE);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count: 0.into() }.as_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        let mut dev = Self {
            selector: 0,
            data_offset: 0,
            dma_address: 0,
            memory,
            items: vec![],
            known_items,
        };
        for item in items {
            dev.add_item(item)?;
        }
        Ok(dev)
    }

    fn get_file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let header = FwCfgFilesHeader {
            count: (self.items.len() as u32).into(),
        };
        self.get_file_dir_mut()[0..4].copy_from_slice(header.as_bytes());
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn add_e820(&mut self, mem_regions: &[(u64, MemRegionEntry)]) -> Result<()> {
        let mut bytes = vec![];
        for (addr, region) in mem_regions.iter() {
            let type_ = match region.type_ {
                MemRegionType::Ram => E820_RAM,
                MemRegionType::Reserved => E820_RESERVED,
                MemRegionType::Acpi => E820_ACPI,
                MemRegionType::Pmem => E820_PMEM,
                MemRegionType::Hidden => continue,
            };
            let entry = BootE820Entry {
                addr: *addr,
                size: region.size,
                type_,
            };
            bytes.extend_from_slice(entry.as_bytes());
        }
        let item = FwCfgItem {
            name: "etc/e820".to_owned(),
            content: FwCfgContent::Bytes(bytes),
        };
        self.add_item(item)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn add_acpi(&mut self, acpi_table: AcpiTable) -> Result<()> {
        let [table_loader, acpi_rsdp, apci_tables] = create_acpi_loader(acpi_table);
        self.add_item(table_loader)?;
        self.add_item(acpi_rsdp)?;
        self.add_item(apci_tables)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_kernel_data(&mut self, p: &Path) -> Result<()> {
        let file = File::open(p)?;
        let mut buffer = vec![0u8; size_of::<BootParams>()];
        file.read_exact_at(&mut buffer, 0)?;
        let bp = BootParams::mut_from_bytes(&mut buffer).unwrap();
        if bp.hdr.setup_sects == 0 {
            bp.hdr.setup_sects = 4;
        }
        bp.hdr.type_of_loader = 0xff;
        let kernel_start = (bp.hdr.setup_sects as usize + 1) * 512;
        self.known_items[FW_CFG_SETUP_SIZE as usize] =
            FwCfgContent::Lu32((buffer.len() as u32).into());
        self.known_items[FW_CFG_SETUP_DATA as usize] = FwCfgContent::Bytes(buffer);
        self.known_items[FW_CFG_KERNEL_SIZE as usize] =
            FwCfgContent::Lu32((file.metadata()?.len() as u32 - kernel_start as u32).into());
        self.known_items[FW_CFG_KERNEL_DATA as usize] =
            FwCfgContent::File(kernel_start as u64, file);
        Ok(())
    }

    pub fn add_initramfs_data(&mut self, p: &Path) -> Result<()> {
        let file = File::open(p)?;
        let initramfs_size = file.metadata()?.len() as u32;
        self.known_items[FW_CFG_INITRD_SIZE as usize] = FwCfgContent::Lu32(initramfs_size.into());
        self.known_items[FW_CFG_INITRD_DATA as usize] = FwCfgContent::File(0, file);
        Ok(())
    }

    pub fn add_kernel_cmdline(&mut self, s: CString) {
        let bytes = s.into_bytes_with_nul();
        self.known_items[FW_CFG_CMDLINE_SIZE as usize] =
            FwCfgContent::Lu32((bytes.len() as u32).into());
        self.known_items[FW_CFG_CMDLINE_DATA as usize] = FwCfgContent::Bytes(bytes);
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let index = self.items.len();
        let c_name = create_file_name(&item.name);
        let size = item.content.size()?;
        let cfg_file = FwCfgFile {
            size: size.into(),
            select: (FW_CFG_FILE_FIRST + index as u16).into(),
            _reserved: 0,
            name: c_name,
        };
        self.get_file_dir_mut()
            .extend_from_slice(cfg_file.as_bytes());
        self.items.push(item);
        self.update_count();
        Ok(())
    }

    fn dma_read_content(
        &self,
        content: &FwCfgContent,
        offset: u32,
        len: u32,
        address: u64,
    ) -> Result<u32> {
        let content_size = content.size()?.saturating_sub(offset);
        let op_size = std::cmp::min(content_size, len);
        let r = self
            .memory
            .write_range(address, op_size as u64, content.access(offset));
        match r {
            Err(e) => {
                log::error!("fw_cfg: dam read error: {e:x?}");
                Err(ErrorKind::InvalidInput.into())
            }
            Ok(()) => Ok(op_size),
        }
    }

    fn dma_read(&mut self, selector: u16, len: u32, address: u64) -> Result<()> {
        let op_size = if let Some(content) = self.known_items.get(selector as usize) {
            self.dma_read_content(content, self.data_offset, len, address)
        } else if let Some(item) = self.items.get((selector - FW_CFG_FILE_FIRST) as usize) {
            self.dma_read_content(&item.content, self.data_offset, len, address)
        } else {
            log::error!("fw_cfg: selector {selector:#x} does not exist.");
            Err(ErrorKind::NotFound.into())
        }?;
        self.data_offset += op_size;
        Ok(())
    }

    fn dma_write(&self, _selector: u16, _len: u32, _address: u64) -> Result<()> {
        unimplemented!()
    }

    fn do_dma(&mut self) {
        let dma_address = self.dma_address;
        let dma_access: FwCfgDmaAccess = match self.memory.read_t(dma_address) {
            Ok(access) => access,
            Err(e) => {
                log::error!("fw_cfg: invalid address of dma access {dma_address:#x}: {e:?}");
                return;
            }
        };
        let control = AccessControl(dma_access.control.into());
        if control.select() {
            self.selector = control.select() as u16;
        }
        let len = dma_access.length.to_ne();
        let addr = dma_access.address.to_ne();
        let ret = if control.read() {
            self.dma_read(self.selector, len, addr)
        } else if control.write() {
            self.dma_write(self.selector, len, addr)
        } else if control.skip() {
            self.data_offset += len;
            Ok(())
        } else {
            Err(ErrorKind::InvalidData.into())
        };
        let mut access_resp = AccessControl(0);
        if let Err(e) = ret {
            log::error!("fw_cfg: dma operation {dma_access:x?}: {e:x?}");
            access_resp.set_error(true);
        }
        if let Err(e) = self.memory.write_t(
            dma_address + FwCfgDmaAccess::OFFSET_CONTROL as u64,
            &Bu32::from(access_resp.0),
        ) {
            log::error!("fw_cfg: finishing dma: {e:?}")
        }
    }

    fn read_data(&mut self) -> u8 {
        let ret = if let Some(content) = self.known_items.get(self.selector as usize) {
            content.read(self.data_offset)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            item.content.read(self.data_offset)
        } else {
            log::error!("fw_cfg: selector {:#x} does not exist.", self.selector);
            None
        };
        if let Some(val) = ret {
            self.data_offset += 1;
            val
        } else {
            0
        }
    }

    fn write_data(&self, _val: u8) {
        if self.selector & SELECTOR_WR != SELECTOR_WR {
            log::error!("fw_cfg: data is read only");
            return;
        }
        log::warn!("fw_cfg: write data no op.")
    }
}

impl Mmio for Mutex<FwCfg> {
    fn size(&self) -> u64 {
        16
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let mut fw_cfg = self.lock();
        let port = offset as u16 + PORT_FW_CFG_SELECTOR;
        let ret = match (port, size) {
            (PORT_FW_CFG_SELECTOR, _) => {
                log::error!("fw_cfg: selector registeris write-only.");
                0
            }
            (PORT_FW_CFG_DATA, 1) => fw_cfg.read_data() as u64,
            (PORT_FW_CFG_DMA_HI, 4) => {
                let addr = fw_cfg.dma_address;
                let addr_hi = (addr >> 32) as u32;
                addr_hi.to_be() as u64
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                let addr = fw_cfg.dma_address;
                let addr_lo = (addr & 0xffff_ffff) as u32;
                addr_lo.to_be() as u64
            }
            _ => {
                log::error!("fw_cfg: read unknown port {port:#x} with size {size}.");
                0
            }
        };
        Ok(ret)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let mut fw_cfg = self.lock();
        let port = offset as u16 + PORT_FW_CFG_SELECTOR;
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, 2) => {
                fw_cfg.selector = val as u16;
                fw_cfg.data_offset = 0;
            }
            (PORT_FW_CFG_DATA, 1) => fw_cfg.write_data(val as u8),
            (PORT_FW_CFG_DMA_HI, 4) => {
                fw_cfg.dma_address &= 0xffff_ffff;
                fw_cfg.dma_address |= (u32::from_be(val as u32) as u64) << 32;
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                fw_cfg.dma_address &= !0xffff_ffff;
                fw_cfg.dma_address |= u32::from_be(val as u32) as u64;
                fw_cfg.do_dma();
            }
            _ => log::error!(
                "fw_cfg: write 0x{val:0width$x} to unknown port {port:#x}.",
                width = 2 * size as usize,
            ),
        };
        Ok(Action::None)
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Help)]
pub enum FwCfgContentParam {
    /// Path to a file with binary contents.
    #[serde(alias = "file")]
    File(Box<Path>),
    /// A UTF-8 encoded string.
    #[serde(alias = "string")]
    String(String),
}

#[derive(Debug, PartialEq, Eq, Help)]
pub struct FwCfgItemParam {
    /// Selector key of an item.
    pub name: String,
    /// Item content.
    #[serde_aco(flatten)]
    pub content: FwCfgContentParam,
}

impl<'de> Deserialize<'de> for FwCfgItemParam {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Name,
            File,
            String,
        }

        struct ParamVisitor;

        impl<'de> Visitor<'de> for ParamVisitor {
            type Value = FwCfgItemParam;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct FwCfgItemParam")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut name = None;
                let mut content = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Name => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("file"));
                            }
                            name = Some(map.next_value()?);
                        }
                        Field::String => {
                            if content.is_some() {
                                return Err(de::Error::duplicate_field("string,file"));
                            }
                            content = Some(FwCfgContentParam::String(map.next_value()?));
                        }
                        Field::File => {
                            if content.is_some() {
                                return Err(de::Error::duplicate_field("string,file"));
                            }
                            content = Some(FwCfgContentParam::File(map.next_value()?));
                        }
                    }
                }
                let name = name.ok_or_else(|| de::Error::missing_field("name"))?;
                let content = content.ok_or_else(|| de::Error::missing_field("file,string"))?;
                Ok(FwCfgItemParam { name, content })
            }
        }

        const FIELDS: &[&str] = &["name", "file", "string"];
        deserializer.deserialize_struct("FwCfgItemParam", FIELDS, ParamVisitor)
    }
}

impl FwCfgItemParam {
    pub fn build(self) -> Result<FwCfgItem> {
        match self.content {
            FwCfgContentParam::File(file) => {
                let f = File::open(file)?;
                Ok(FwCfgItem {
                    name: self.name,
                    content: FwCfgContent::File(0, f),
                })
            }
            FwCfgContentParam::String(string) => Ok(FwCfgItem {
                name: self.name,
                content: FwCfgContent::Bytes(string.into()),
            }),
        }
    }
}

#[cfg(test)]
#[path = "fw_cfg_test.rs"]
mod tests;
