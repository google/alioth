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

use core::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read, Result, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;

use bitfield::bitfield;
use macros::Layout;
use parking_lot::Mutex;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::firmware::acpi::AcpiTable;
use crate::loader::linux::bootparams::{
    BootE820Entry, E820_ACPI, E820_PMEM, E820_RAM, E820_RESERVED,
};
use crate::mem;
use crate::mem::emulated::Mmio;
use crate::mem::mapped::RamBus;
use crate::mem::{MemRegionEntry, MemRegionType};

pub mod acpi;

use acpi::create_acpi_loader;

pub const PORT_SELECTOR: u16 = 0x510;
pub const PORT_DATA: u16 = 0x511;
pub const PORT_DMA_ADDRESS_HI: u16 = 0x514;
pub const PORT_DMA_ADDRESS_LO: u16 = 0x518;

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
    File(File),
}

struct FwCfgContentAccess<'a> {
    content: &'a FwCfgContent,
    offset: usize,
}

impl<'a> Read for FwCfgContentAccess<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.content {
            FwCfgContent::File(f) => {
                (&*f).seek(SeekFrom::Start(self.offset as u64))?;
                (&*f).read(buf)
            }
            FwCfgContent::Bytes(b) => match b.get(self.offset..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Slice(b) => match b.get(self.offset..) {
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
    fn size(&self) -> Result<usize> {
        let ret = match self {
            FwCfgContent::Bytes(v) => v.len(),
            FwCfgContent::File(f) => f.metadata()?.len() as usize,
            FwCfgContent::Slice(s) => s.len(),
        };
        Ok(ret)
    }

    fn access(&self, offset: usize) -> FwCfgContentAccess {
        FwCfgContentAccess {
            content: self,
            offset,
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
    data_offset: usize,
    dma_address: u64,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
    memory: Arc<RamBus>,
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, FromZeroes, Layout)]
struct FwCfgDmaAccess {
    control_be: u32,
    length_be: u32,
    address_be: u64,
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
#[derive(Debug, AsBytes)]
struct FwCfgFilesHeader {
    count_be: u32,
}

#[repr(C)]
#[derive(Debug, AsBytes)]
struct FwCfgFile {
    size_be: u32,
    select_be: u16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

impl FwCfg {
    pub fn new(memory: Arc<RamBus>, items: Vec<FwCfgItem>) -> Result<Self> {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_DMA_SIGNATURE);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_bytes());
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
            count_be: (self.items.len() as u32).to_be(),
        };
        self.get_file_dir_mut()[0..4].copy_from_slice(header.as_bytes());
    }

    pub(crate) fn add_e820(&mut self, mem_regions: &[(usize, MemRegionEntry)]) -> Result<()> {
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
                addr: *addr as u64,
                size: region.size as u64,
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

    pub(crate) fn add_acpi(&mut self, acpi_table: AcpiTable) -> Result<()> {
        let [table_loader, acpi_rsdp, apci_tables] = create_acpi_loader(acpi_table);
        self.add_item(table_loader)?;
        self.add_item(acpi_rsdp)?;
        self.add_item(apci_tables)
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let index = self.items.len();
        let c_name = create_file_name(&item.name);
        let size = item.content.size()?;
        let item_size = if size > u32::MAX as usize {
            // TODO use FileTooLarge
            return Err(ErrorKind::Unsupported.into());
        } else {
            size as u32
        };
        let cfg_file = FwCfgFile {
            size_be: item_size.to_be(),
            select_be: (FW_CFG_FILE_FIRST + index as u16).to_be(),
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
        offset: usize,
        len: usize,
        address: usize,
    ) -> Result<usize> {
        let content_size = content.size()?.saturating_sub(offset);
        let op_size = std::cmp::min(content_size, len);
        let r = self
            .memory
            .write_range(address, op_size, content.access(offset));
        match r {
            Err(e) => {
                log::error!("fw_cfg: dam read error: {e:x?}");
                Err(ErrorKind::InvalidInput.into())
            }
            Ok(()) => Ok(op_size),
        }
    }

    fn dma_read(&mut self, selector: u16, len: usize, address: usize) -> Result<()> {
        let op_size = if let Some(content) = self.known_items.get(selector as usize) {
            self.dma_read_content(content, self.data_offset, len, address)
        } else if let Some(item) = self.items.get((selector - FW_CFG_FILE_FIRST) as usize) {
            self.dma_read_content(&item.content, self.data_offset, len, address)
        } else {
            log::error!("fw_cfg: selector {selector:#x} does not exist.");
            Err(ErrorKind::NotFound.into())
        }?;
        self.data_offset += op_size as usize;
        Ok(())
    }

    fn dma_write(&self, _selector: u16, _len: usize, _address: usize) -> Result<()> {
        unimplemented!()
    }

    fn do_dma(&mut self) {
        let dma_address = self.dma_address as usize;
        let dma_access = match self.memory.read::<FwCfgDmaAccess>(dma_address) {
            Ok(access) => access,
            Err(e) => {
                log::error!("fw_cfg: invalid address of dma access {dma_address:#x}: {e:?}");
                return;
            }
        };
        let control = AccessControl(u32::from_be(dma_access.control_be));
        if control.select() {
            self.selector = control.select() as u16;
        }
        let len = u32::from_be(dma_access.length_be) as usize;
        let addr = u64::from_be(dma_access.address_be) as usize;
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
        if let Err(e) = self.memory.write(
            dma_address + FwCfgDmaAccess::OFFSET_CONTROL_BE,
            &access_resp.0.to_be(),
        ) {
            log::error!("fw_cfg: finishing dma: {e:?}")
        }
    }

    fn read_content(content: &FwCfgContent, offset: usize) -> Option<u8> {
        match content {
            FwCfgContent::Bytes(b) => b.get(offset).copied(),
            FwCfgContent::Slice(s) => s.get(offset).copied(),
            FwCfgContent::File(f) => {
                let mut buf = [0u8];
                match f.read_exact_at(&mut buf, offset as u64) {
                    Ok(_) => Some(buf[0]),
                    Err(e) => {
                        log::error!("fw_cfg: reading {f:?}: {e:?}");
                        None
                    }
                }
            }
        }
    }

    fn read_data(&mut self) -> u8 {
        let ret = if let Some(content) = self.known_items.get(self.selector as usize) {
            Self::read_content(content, self.data_offset)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            Self::read_content(&item.content, self.data_offset)
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
    fn size(&self) -> usize {
        16
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let mut fw_cfg = self.lock();
        let port = offset as u16 + PORT_SELECTOR;
        let ret = match (port, size) {
            (PORT_SELECTOR, _) => {
                log::error!("fw_cfg: selector registeris write-only.");
                0
            }
            (PORT_DATA, 1) => fw_cfg.read_data() as u64,
            (PORT_DMA_ADDRESS_HI, 4) => {
                let addr = fw_cfg.dma_address;
                let addr_hi = (addr >> 32) as u32;
                addr_hi.to_be() as u64
            }
            (PORT_DMA_ADDRESS_LO, 4) => {
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

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let mut fw_cfg = self.lock();
        let port = offset as u16 + PORT_SELECTOR;
        match (port, size) {
            (PORT_SELECTOR, 2) => {
                fw_cfg.selector = val as u16;
                fw_cfg.data_offset = 0;
            }
            (PORT_DATA, 1) => fw_cfg.write_data(val as u8),
            (PORT_DMA_ADDRESS_HI, 4) => {
                fw_cfg.dma_address &= 0xffff_ffff;
                fw_cfg.dma_address |= (u32::from_be(val as u32) as u64) << 32;
            }
            (PORT_DMA_ADDRESS_LO, 4) => {
                fw_cfg.dma_address &= !0xffff_ffff;
                fw_cfg.dma_address |= u32::from_be(val as u32) as u64;
                fw_cfg.do_dma();
            }
            _ => log::error!(
                "fw_cfg: write 0x{val:0width$x} to unknown port {port:#x}.",
                width = 2 * size as usize,
            ),
        };
        Ok(())
    }
}

#[derive(Debug)]
pub enum FwCfgContentParam {
    File(PathBuf),
    String(String),
}

#[derive(Debug)]
pub struct FwCfgItemParam {
    pub name: String,
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
                    content: FwCfgContent::File(f),
                })
            }
            FwCfgContentParam::String(string) => Ok(FwCfgItem {
                name: self.name,
                content: FwCfgContent::Bytes(string.into()),
            }),
        }
    }
}
