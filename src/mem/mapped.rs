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

use std::fmt::Debug;
use std::fs::File;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;

use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, MS_ASYNC, PROT_EXEC, PROT_READ, PROT_WRITE, c_void,
    mmap, msync, munmap,
};
use zerocopy::{AsBytes, FromBytes};

use crate::ffi;
use crate::mem::addressable::SlotBackend;
use crate::mem::{Error, Result};

#[derive(Debug)]
struct MemPages {
    addr: NonNull<c_void>,
    len: usize,
}

unsafe impl Send for MemPages {}
unsafe impl Sync for MemPages {}

impl Drop for MemPages {
    fn drop(&mut self) {
        let ret = unsafe { munmap(self.addr.as_ptr(), self.len) };
        if ret != 0 {
            log::error!("munmap({:p}, {:x}) = {:x}", self.addr, self.len, ret);
        } else {
            log::info!("munmap({:p}, {:x}) = {:x}, done", self.addr, self.len, ret);
        }
    }
}

// ArcMemPages uses Arc to manage the underlying memory and caches
// the address and size on the stack. Compared with using Arc<MemPages>,
// it avoids a memory load when a caller tries to read/write the pages.
// TODO: is it really necessary?
#[derive(Debug, Clone)]
pub struct ArcMemPages {
    addr: usize,
    size: usize,
    _inner: Arc<MemPages>,
}

impl SlotBackend for ArcMemPages {
    fn size(&self) -> usize {
        self.size
    }
}

impl ArcMemPages {
    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn sync(&self) -> Result<()> {
        ffi!(unsafe { msync(self.addr as *mut _, self.size, MS_ASYNC) })?;
        Ok(())
    }

    pub(super) fn new_raw(addr: *mut c_void, len: usize) -> Self {
        let addr = NonNull::new(addr).expect("address from mmap() should not be null");
        ArcMemPages {
            addr: addr.as_ptr() as usize,
            size: len,
            _inner: Arc::new(MemPages { addr, len }),
        }
    }

    pub fn new_file(file: File) -> Result<Self, Error> {
        let mut prot = PROT_READ | PROT_EXEC;
        let meta = file.metadata().map_err(Error::Mmap)?;
        let is_readonly = meta.permissions().readonly();
        if !is_readonly {
            prot |= PROT_WRITE;
        }
        let size = meta.len() as usize;
        let addr = unsafe { mmap(null_mut(), size, prot, MAP_PRIVATE, file.as_raw_fd(), 0) };
        match addr {
            MAP_FAILED => Err(Error::Mmap(std::io::Error::last_os_error())),
            addr => Ok(Self::new_raw(addr, size)),
        }
    }

    pub fn new_anon(size: usize) -> Result<Self, Error> {
        let prot = PROT_WRITE | PROT_READ | PROT_EXEC;
        let addr = unsafe { mmap(null_mut(), size, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) };
        match addr {
            MAP_FAILED => Err(Error::Mmap(std::io::Error::last_os_error())),
            addr => Ok(Self::new_raw(addr, size)),
        }
    }

    /// Given offset and len, return the host virtual address and len;
    /// len might be truncated.
    fn get_valid_range(&self, offset: usize, len: usize) -> Result<(usize, usize)> {
        let end = offset.wrapping_add(len).wrapping_sub(1);
        if offset >= self.size || end < offset {
            return Err(Error::OutOfRange {
                addr: offset,
                size: len,
            });
        }
        let valid_len = std::cmp::min(self.size - offset, len);
        Ok((self.addr + offset, valid_len))
    }

    pub fn read<T>(&self, offset: usize) -> Result<T, Error>
    where
        T: FromBytes,
    {
        let s = self.get_partial_slice(offset, size_of::<T>())?;
        match FromBytes::read_from(s) {
            None => Err(Error::OutOfRange {
                addr: offset,
                size: size_of::<T>(),
            }),
            Some(v) => Ok(v),
        }
    }

    pub fn write<T>(&self, offset: usize, val: &T) -> Result<(), Error>
    where
        T: AsBytes,
    {
        let s = self.get_partial_slice_mut(offset, size_of::<T>())?;
        match AsBytes::write_to(val, s) {
            None => Err(Error::OutOfRange {
                addr: offset,
                size: size_of::<T>(),
            }),
            Some(()) => Ok(()),
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.addr as *mut u8, self.size) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.addr as *const u8, self.size) }
    }

    /// Given offset and len, return a slice, len might be truncated.
    pub fn get_partial_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        let (addr, len) = self.get_valid_range(offset, len)?;
        Ok(unsafe { std::slice::from_raw_parts(addr as *const u8, len) })
    }

    /// Given offset and len, return a mutable slice, len might be truncated.
    #[allow(clippy::mut_from_ref)]
    pub fn get_partial_slice_mut(&self, offset: usize, len: usize) -> Result<&mut [u8], Error> {
        let (addr, len) = self.get_valid_range(offset, len)?;
        Ok(unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) })
    }
}
