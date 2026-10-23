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

use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::sync::Arc;

use bitflags::bitflags;
use thiserror::Error;

use crate::virtio::dev::net::NetFeature;

pub mod arch {
    use crate::hw::reg::SegAccess;

    #[derive(Debug, Default, Clone)]
    pub struct Cpuid {
        pub func: u32,
        pub index: Option<u32>,
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum Reg {
        Rax,
        Rbx,
        Rcx,
        Rdx,
        Rsi,
        Rdi,
        Rsp,
        Rbp,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        Rip,
        Rflags,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum SReg {
        Cr0,
        Cr2,
        Cr3,
        Cr4,
        Cr8,
        Efer,
        ApicBase,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum SegReg {
        Cs,
        Ds,
        Es,
        Fs,
        Gs,
        Ss,
        Tr,
        Ldtr,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum DtReg {
        Gdtr,
        Idtr,
    }

    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct SegRegVal {
        pub selector: u16,
        pub base: u64,
        pub limit: u32,
        pub access: SegAccess,
    }

    impl SegRegVal {
        pub fn to_desc(&self) -> u64 {
            ((self.base & 0xff00_0000) << (56 - 24))
                | (((self.access.0 as u64) & 0x0000_f0ff) << 40)
                | (((self.limit as u64) & 0x000f_0000) << (48 - 16))
                | ((self.base & 0x00ff_ffff) << 16)
                | ((self.limit as u64) & 0x0000_ffff)
        }
    }

    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
    pub struct DtRegVal {
        pub base: u64,
        pub limit: u16,
    }
}

pub use arch::{Cpuid, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Interest: u8 {
        const READABLE = 1 << 0;
        const WRITABLE = 1 << 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct PollEvent {
    pub token: Token,
    pub is_readable: bool,
    pub is_writable: bool,
}

impl PollEvent {
    pub fn token(&self) -> Token {
        self.token
    }

    pub fn is_readable(&self) -> bool {
        self.is_readable
    }

    pub fn is_writable(&self) -> bool {
        self.is_writable
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid memory map option for {hypervisor}: {option:?}")]
    MemMapOption {
        option: MemMapOption,
        hypervisor: &'static str,
    },
    #[error("IO error: {source}")]
    StdIo {
        #[from]
        source: std::io::Error,
    },
    #[error("{msg}")]
    Unexpected { msg: String },
    #[error("lack capability: {cap}")]
    LackCap { cap: String },
    #[error("creating multiple memory")]
    CreatingMultipleMemory,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemMapOption {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub log_dirty: bool,
}

impl Default for MemMapOption {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            exec: true,
            log_dirty: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    Io {
        port: u16,
        write: Option<u32>,
        size: u8,
    },
    Mmio {
        addr: u64,
        write: Option<u64>,
        size: u8,
    },
    Shutdown,
    Reboot,
    Unknown(String),
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmEntry {
    None,
    Shutdown,
    Reboot,
    Io { data: u32 },
    Mmio { data: u64 },
}

#[derive(Debug, Clone)]
pub enum IoEvent {
    SerialInput,
    Poll(PollEvent),
    Shutdown,
}

pub trait MemPages: Debug + Send + Sync + 'static {
    fn addr(&self) -> u64;
    fn size(&self) -> usize;
    fn sync(&self) -> std::io::Result<()>;
    fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()>;
    fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()>;
}

pub trait VmMemory: Debug + Send + Sync + 'static {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
        size: usize,
        hva: u64,
        option: MemMapOption,
    ) -> Result<(), Error>;

    fn unmap(&self, slot: u32, gpa: u64, size: usize) -> Result<(), Error>;

    fn max_mem_slots(&self) -> Result<u32, Error>;

    fn register_encrypted_range(&self, addr: u64, size: usize) -> Result<()>;

    fn deregister_encrypted_range(&self, addr: u64, size: usize) -> Result<()>;

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>>;
}

pub trait IntxSender: Debug + Send + Sync + 'static {
    fn send(&self) -> Result<(), Error>;
}

impl<T: IntxSender + ?Sized> IntxSender for Arc<T> {
    fn send(&self) -> Result<(), Error> {
        IntxSender::send(self.as_ref())
    }
}

impl<T: IntxSender + ?Sized> IntxSender for Box<T> {
    fn send(&self) -> Result<(), Error> {
        IntxSender::send(self.as_ref())
    }
}

pub trait MsiSender: Debug + Send + Sync + 'static {
    fn send(&self, addr: u64, data: u32) -> Result<()>;
}

impl<T: MsiSender + ?Sized> MsiSender for Arc<T> {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        MsiSender::send(self.as_ref(), addr, data)
    }
}

impl<T: MsiSender + ?Sized> MsiSender for Box<T> {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        MsiSender::send(self.as_ref(), addr, data)
    }
}

pub trait SerialConsole: Debug + Send + Sync + 'static {
    fn write_byte(&self, byte: u8) -> std::io::Result<()>;
    fn read_input(&self, data: &mut VecDeque<u8>) -> std::io::Result<Option<usize>>;
    fn shutdown(&self) -> std::io::Result<()>;
}

pub trait Tap: Debug + Send + Sync + 'static {
    fn detected_offload(&self) -> NetFeature;
    fn enable_offload(&mut self, feature: NetFeature) -> std::io::Result<()>;
    fn register(&self, token: Token, interests: Interest) -> std::io::Result<()>;
    fn deregister(&self);
    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize>;
    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize>;
}

impl Read for &dyn Tap {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Tap::read_vectored(*self, &mut [IoSliceMut::new(buf)])
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        Tap::read_vectored(*self, bufs)
    }
}

impl Write for &dyn Tap {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Tap::write_vectored(*self, &[IoSlice::new(buf)])
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        Tap::write_vectored(*self, bufs)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub trait Vcpu: Send + Sync + 'static {
    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error>;
    fn get_reg(&self, reg: Reg) -> Result<u64, Error>;
    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error>;
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error>;
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error>;
    fn get_sreg(&self, reg: SReg) -> Result<u64, Error>;
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error>;
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error>;
    fn dump(&self) -> Result<(), Error>;
}

pub trait Vm: Debug + Send + Sync + 'static {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error>;
    fn stop_vcpu(&self, id: u32) -> Result<(), Error>;
    fn next_io_event(&self) -> Result<IoEvent, Error>;
    fn stop_io_poll(&self) -> Result<(), Error>;
    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error>;
    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error>;
    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error>;
    fn create_serial_console(&self) -> std::io::Result<Box<dyn SerialConsole>>;
    fn create_tap(&self, if_name: Option<&str>) -> std::io::Result<Box<dyn Tap>>;
}

pub trait Hypervisor: Debug + Send + Sync + 'static {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error>;
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error>;
}

pub mod abi {
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use super::{
        Cpuid, DtReg, DtRegVal, IoEvent, MemMapOption, PollEvent, Reg, SReg, SegReg, SegRegVal,
        Token, VmEntry,
    };
    use crate::hw::reg::SegAccess;

    pub const ERR_GENERIC: i32 = -1;
    pub const ERR_WOULD_BLOCK: i32 = -2;
    pub const ERR_INTERRUPTED: i32 = -3;
    pub const ERR_EOF: i32 = -4;

    pub const ENTRY_NONE: u32 = 0;
    pub const ENTRY_SHUTDOWN: u32 = 1;
    pub const ENTRY_REBOOT: u32 = 2;
    pub const ENTRY_IO: u32 = 3;
    pub const ENTRY_MMIO: u32 = 4;

    pub const EXIT_IO: u32 = 0;
    pub const EXIT_MMIO: u32 = 1;
    pub const EXIT_SHUTDOWN: u32 = 2;
    pub const EXIT_REBOOT: u32 = 3;
    pub const EXIT_INTERRUPTED: u32 = 4;
    pub const EXIT_UNKNOWN: u32 = 5;

    pub const IO_EVENT_SERIAL_INPUT: u32 = 0;
    pub const IO_EVENT_POLL: u32 = 1;
    pub const IO_EVENT_SHUTDOWN: u32 = 2;

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawCpuid {
        pub func: u32,
        pub has_index: u32,
        pub index: u32,
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    impl From<Cpuid> for RawCpuid {
        fn from(c: Cpuid) -> Self {
            Self {
                func: c.func,
                has_index: u32::from(c.index.is_some()),
                index: c.index.unwrap_or(0),
                eax: c.eax,
                ebx: c.ebx,
                ecx: c.ecx,
                edx: c.edx,
            }
        }
    }

    impl From<RawCpuid> for Cpuid {
        fn from(r: RawCpuid) -> Self {
            Self {
                func: r.func,
                index: if r.has_index != 0 {
                    Some(r.index)
                } else {
                    None
                },
                eax: r.eax,
                ebx: r.ebx,
                ecx: r.ecx,
                edx: r.edx,
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawRegVal {
        pub reg: u32,
        pub _pad: u32,
        pub val: u64,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawSegRegVal {
        pub base: u64,
        pub limit: u32,
        pub access: u32,
        pub selector: u16,
        pub _pad: [u8; 6],
    }

    impl From<SegRegVal> for RawSegRegVal {
        fn from(v: SegRegVal) -> Self {
            Self {
                base: v.base,
                limit: v.limit,
                access: v.access.0,
                selector: v.selector,
                _pad: [0; 6],
            }
        }
    }

    impl From<RawSegRegVal> for SegRegVal {
        fn from(v: RawSegRegVal) -> Self {
            Self {
                selector: v.selector,
                base: v.base,
                limit: v.limit,
                access: SegAccess(v.access),
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawSegRegEntry {
        pub reg: u32,
        pub _pad: u32,
        pub val: RawSegRegVal,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawDtRegVal {
        pub base: u64,
        pub limit: u16,
        pub _pad: [u8; 6],
    }

    impl From<DtRegVal> for RawDtRegVal {
        fn from(v: DtRegVal) -> Self {
            Self {
                base: v.base,
                limit: v.limit,
                _pad: [0; 6],
            }
        }
    }

    impl From<RawDtRegVal> for DtRegVal {
        fn from(v: RawDtRegVal) -> Self {
            Self {
                base: v.base,
                limit: v.limit,
            }
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawDtRegEntry {
        pub reg: u32,
        pub _pad: u32,
        pub val: RawDtRegVal,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawVmExit {
        pub addr_or_port: u64,
        pub data: u64,
        pub kind: u32,
        pub is_write: u8,
        pub size: u8,
        pub _pad: [u8; 2],
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
    pub struct RawIoEvent {
        pub token: u64,
        pub kind: u32,
        pub is_readable: u8,
        pub is_writable: u8,
        pub _pad: [u8; 2],
    }

    impl From<IoEvent> for RawIoEvent {
        fn from(ev: IoEvent) -> Self {
            match ev {
                IoEvent::SerialInput => Self {
                    token: 0,
                    kind: IO_EVENT_SERIAL_INPUT,
                    is_readable: 0,
                    is_writable: 0,
                    _pad: [0; 2],
                },
                IoEvent::Poll(p) => Self {
                    token: p.token.0,
                    kind: IO_EVENT_POLL,
                    is_readable: u8::from(p.is_readable),
                    is_writable: u8::from(p.is_writable),
                    _pad: [0; 2],
                },
                IoEvent::Shutdown => Self {
                    token: 0,
                    kind: IO_EVENT_SHUTDOWN,
                    is_readable: 0,
                    is_writable: 0,
                    _pad: [0; 2],
                },
            }
        }
    }

    impl From<RawIoEvent> for IoEvent {
        fn from(r: RawIoEvent) -> Self {
            match r.kind {
                IO_EVENT_SERIAL_INPUT => IoEvent::SerialInput,
                IO_EVENT_POLL => IoEvent::Poll(PollEvent {
                    token: Token(r.token),
                    is_readable: r.is_readable != 0,
                    is_writable: r.is_writable != 0,
                }),
                _ => IoEvent::Shutdown,
            }
        }
    }

    pub fn reg_to_u32(r: Reg) -> u32 {
        match r {
            Reg::Rax => 0,
            Reg::Rbx => 1,
            Reg::Rcx => 2,
            Reg::Rdx => 3,
            Reg::Rsi => 4,
            Reg::Rdi => 5,
            Reg::Rsp => 6,
            Reg::Rbp => 7,
            Reg::R8 => 8,
            Reg::R9 => 9,
            Reg::R10 => 10,
            Reg::R11 => 11,
            Reg::R12 => 12,
            Reg::R13 => 13,
            Reg::R14 => 14,
            Reg::R15 => 15,
            Reg::Rip => 16,
            Reg::Rflags => 17,
        }
    }

    pub fn reg_from_u32(v: u32) -> Reg {
        match v {
            0 => Reg::Rax,
            1 => Reg::Rbx,
            2 => Reg::Rcx,
            3 => Reg::Rdx,
            4 => Reg::Rsi,
            5 => Reg::Rdi,
            6 => Reg::Rsp,
            7 => Reg::Rbp,
            8 => Reg::R8,
            9 => Reg::R9,
            10 => Reg::R10,
            11 => Reg::R11,
            12 => Reg::R12,
            13 => Reg::R13,
            14 => Reg::R14,
            15 => Reg::R15,
            16 => Reg::Rip,
            _ => Reg::Rflags,
        }
    }

    pub fn sreg_to_u32(r: SReg) -> u32 {
        match r {
            SReg::Cr0 => 0,
            SReg::Cr2 => 1,
            SReg::Cr3 => 2,
            SReg::Cr4 => 3,
            SReg::Cr8 => 4,
            SReg::Efer => 5,
            SReg::ApicBase => 6,
        }
    }

    pub fn sreg_from_u32(v: u32) -> SReg {
        match v {
            0 => SReg::Cr0,
            1 => SReg::Cr2,
            2 => SReg::Cr3,
            3 => SReg::Cr4,
            4 => SReg::Cr8,
            5 => SReg::Efer,
            _ => SReg::ApicBase,
        }
    }

    pub fn seg_reg_to_u32(r: SegReg) -> u32 {
        match r {
            SegReg::Cs => 0,
            SegReg::Ds => 1,
            SegReg::Es => 2,
            SegReg::Fs => 3,
            SegReg::Gs => 4,
            SegReg::Ss => 5,
            SegReg::Tr => 6,
            SegReg::Ldtr => 7,
        }
    }

    pub fn seg_reg_from_u32(v: u32) -> SegReg {
        match v {
            0 => SegReg::Cs,
            1 => SegReg::Ds,
            2 => SegReg::Es,
            3 => SegReg::Fs,
            4 => SegReg::Gs,
            5 => SegReg::Ss,
            6 => SegReg::Tr,
            _ => SegReg::Ldtr,
        }
    }

    pub fn dt_reg_to_u32(r: DtReg) -> u32 {
        match r {
            DtReg::Gdtr => 0,
            DtReg::Idtr => 1,
        }
    }

    pub fn dt_reg_from_u32(v: u32) -> DtReg {
        match v {
            0 => DtReg::Gdtr,
            _ => DtReg::Idtr,
        }
    }

    pub fn mem_map_option_to_u32(o: MemMapOption) -> u32 {
        (u32::from(o.read))
            | (u32::from(o.write) << 1)
            | (u32::from(o.exec) << 2)
            | (u32::from(o.log_dirty) << 3)
    }

    pub fn mem_map_option_from_u32(v: u32) -> MemMapOption {
        MemMapOption {
            read: (v & 1) != 0,
            write: (v & 2) != 0,
            exec: (v & 4) != 0,
            log_dirty: (v & 8) != 0,
        }
    }

    pub fn encode_vm_entry(e: VmEntry) -> (u32, u64) {
        match e {
            VmEntry::None => (ENTRY_NONE, 0),
            VmEntry::Shutdown => (ENTRY_SHUTDOWN, 0),
            VmEntry::Reboot => (ENTRY_REBOOT, 0),
            VmEntry::Io { data } => (ENTRY_IO, data as u64),
            VmEntry::Mmio { data } => (ENTRY_MMIO, data),
        }
    }

    pub fn decode_vm_entry(kind: u32, data: u64) -> VmEntry {
        match kind {
            ENTRY_SHUTDOWN => VmEntry::Shutdown,
            ENTRY_REBOOT => VmEntry::Reboot,
            ENTRY_IO => VmEntry::Io { data: data as u32 },
            ENTRY_MMIO => VmEntry::Mmio { data },
            _ => VmEntry::None,
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::sync::Arc;

    use super::{Error, MemMapOption, MemPages, Result, VmMemory};
    use crate::hw::layout::PAGE_SIZE;

    #[derive(Debug)]
    pub struct FakeMemPages {
        addr: usize,
        size: usize,
        layout: Option<Layout>,
    }

    impl FakeMemPages {
        pub fn new(size: usize) -> Self {
            let layout = Layout::from_size_align(size, PAGE_SIZE).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Self {
                addr: ptr as usize,
                size,
                layout: Some(layout),
            }
        }

        pub unsafe fn from_raw(addr: u64, size: usize) -> Self {
            Self {
                addr: addr as usize,
                size,
                layout: None,
            }
        }
    }

    impl Drop for FakeMemPages {
        fn drop(&mut self) {
            if let Some(layout) = self.layout {
                unsafe { dealloc(self.addr as *mut u8, layout) };
            }
        }
    }

    impl MemPages for FakeMemPages {
        fn addr(&self) -> u64 {
            self.addr as u64
        }

        fn size(&self) -> usize {
            self.size
        }

        fn sync(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()> {
            let src = unsafe { std::slice::from_raw_parts((self.addr + offset) as *const u8, dst.len()) };
            dst.copy_from_slice(src);
            Ok(())
        }

        fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
            let dst = unsafe { std::slice::from_raw_parts_mut((self.addr + offset) as *mut u8, src.len()) };
            dst.copy_from_slice(src);
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct FakeVmMemoryStruct;

    impl VmMemory for FakeVmMemoryStruct {
        fn mem_map(
            &self,
            _slot: u32,
            _gpa: u64,
            _size: usize,
            _hva: u64,
            option: MemMapOption,
        ) -> Result<(), Error> {
            if !option.read || !option.exec {
                return Err(Error::MemMapOption {
                    option,
                    hypervisor: "fake",
                });
            }
            Ok(())
        }

        fn unmap(&self, _slot: u32, _gpa: u64, _size: usize) -> Result<(), Error> {
            Ok(())
        }

        fn max_mem_slots(&self) -> Result<u32, Error> {
            Ok(32)
        }

        fn register_encrypted_range(&self, _addr: u64, _size: usize) -> Result<()> {
            Ok(())
        }

        fn deregister_encrypted_range(&self, _addr: u64, _size: usize) -> Result<()> {
            Ok(())
        }

        fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
            Ok(Arc::new(FakeMemPages::new(size)))
        }
    }

    #[allow(non_snake_case)]
    pub fn FakeVmMemory() -> Box<dyn VmMemory> {
        Box::new(FakeVmMemoryStruct)
    }
}
