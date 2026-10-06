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

use std::any::Any;
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

pub trait Waker: Debug + Send + Sync + 'static {
    fn wake(&self) -> std::io::Result<()>;
}

pub trait Poll: Debug + Send + Sync + 'static {
    fn create_waker(&self, token: Token) -> std::io::Result<Box<dyn Waker>>;
    fn poll(&mut self, events: &mut Vec<PollEvent>) -> std::io::Result<()>;
    fn as_any(&self) -> &dyn Any;
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

pub trait MemPages: Debug + Send + Sync + 'static {
    fn addr(&self) -> usize;
    fn size(&self) -> usize;
    fn sync(&self) -> std::io::Result<()>;
}

pub trait VmMemory: Debug + Send + Sync + 'static {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
        size: usize,
        hva: usize,
        option: MemMapOption,
    ) -> Result<(), Error>;

    fn unmap(&self, slot: u32, gpa: u64, size: usize) -> Result<(), Error>;

    fn max_mem_slots(&self) -> Result<u32, Error>;

    fn register_encrypted_range(&self, range: &[u8]) -> Result<()>;

    fn deregister_encrypted_range(&self, range: &[u8]) -> Result<()>;

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
    fn register(
        &self,
        poll: &dyn Poll,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()>;
    fn deregister(&self, poll: &dyn Poll);
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

pub trait Vcpu {
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
    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error>;
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error>;
    fn dump(&self) -> Result<(), Error>;
}

pub trait Vm: Debug + Send + Sync + 'static {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error>;
    fn stop_vcpu(&self, id: u32) -> Result<(), Error>;
    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error>;
    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error>;
    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error>;
    fn create_serial_console(&self) -> std::io::Result<Box<dyn SerialConsole>>;
    fn create_tap(&self, if_name: Option<&str>) -> std::io::Result<Box<dyn Tap>>;
    fn create_poll(&self) -> std::io::Result<Box<dyn Poll>>;
}

pub trait Hypervisor: Debug + Send + Sync + 'static {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error>;
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error>;
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

        pub unsafe fn from_raw(addr: usize, size: usize) -> Self {
            Self {
                addr,
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
        fn addr(&self) -> usize {
            self.addr
        }

        fn size(&self) -> usize {
            self.size
        }

        fn sync(&self) -> std::io::Result<()> {
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
            _hva: usize,
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

        fn register_encrypted_range(&self, _range: &[u8]) -> Result<()> {
            Ok(())
        }

        fn deregister_encrypted_range(&self, _range: &[u8]) -> Result<()> {
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
