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

use std::cell::UnsafeCell;
#[cfg(target_os = "linux")]
use std::ffi::CStr;
use std::fmt::Debug;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::{align_of, size_of};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use libc::{MADV_HUGEPAGE, MFD_CLOEXEC};
use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, MAP_SHARED, MS_ASYNC, PROT_EXEC, PROT_READ, PROT_WRITE,
    c_void, madvise, mmap, msync, munmap,
};
use parking_lot::{RwLock, RwLockReadGuard};
use snafu::ResultExt;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::ffi;
use crate::mem::addressable::{Addressable, SlotBackend};
use crate::mem::{Error, Result, error};

#[derive(Debug)]
struct MemPages {
    addr: NonNull<c_void>,
    len: usize,
    fd: Option<(File, u64)>,
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
    fn size(&self) -> u64 {
        self.size as u64
    }
}

impl ArcMemPages {
    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn size(&self) -> u64 {
        self.size as u64
    }

    pub fn fd(&self) -> Option<(BorrowedFd, u64)> {
        self._inner
            .fd
            .as_ref()
            .map(|(f, offset)| (f.as_fd(), *offset))
    }

    pub fn sync(&self) -> Result<()> {
        ffi!(unsafe { msync(self.addr as *mut _, self.size, MS_ASYNC) })?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn madvise_hugepage(&self) -> Result<()> {
        ffi!(unsafe { madvise(self.addr as *mut _, self.size, MADV_HUGEPAGE) })?;
        Ok(())
    }

    fn from_raw(addr: *mut c_void, len: usize, fd: Option<(File, u64)>) -> Self {
        let addr = NonNull::new(addr).expect("address from mmap() should not be null");
        ArcMemPages {
            addr: addr.as_ptr() as usize,
            size: len,
            _inner: Arc::new(MemPages { addr, len, fd }),
        }
    }

    pub fn from_file(file: File, offset: i64, len: usize, prot: i32) -> Result<Self> {
        let addr = ffi!(
            unsafe { mmap(null_mut(), len, prot, MAP_SHARED, file.as_raw_fd(), offset) },
            MAP_FAILED
        )?;
        Ok(Self::from_raw(addr, len, Some((file, offset as u64))))
    }

    #[cfg(target_os = "linux")]
    pub fn from_memfd(name: &CStr, size: usize, prot: Option<i32>) -> Result<Self> {
        let fd = ffi!(unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC) })?;
        let prot = prot.unwrap_or(PROT_WRITE | PROT_READ | PROT_EXEC);
        let addr = ffi!(
            unsafe { mmap(null_mut(), size, prot, MAP_SHARED, fd, 0) },
            MAP_FAILED
        )?;
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(size as _)?;
        Ok(Self::from_raw(addr, size, Some((file, 0))))
    }

    pub fn from_anonymous(size: usize, prot: Option<i32>, flags: Option<i32>) -> Result<Self> {
        let prot = prot.unwrap_or(PROT_WRITE | PROT_READ | PROT_EXEC);
        let flags = flags.unwrap_or(MAP_PRIVATE) | MAP_ANONYMOUS;
        let addr = ffi!(
            unsafe { mmap(null_mut(), size, prot, flags, -1, 0) },
            MAP_FAILED
        )?;
        Ok(Self::from_raw(addr, size, None))
    }

    /// Given offset and len, return the host virtual address and len;
    /// len might be truncated.
    fn get_valid_range(&self, offset: usize, len: usize) -> Result<(usize, usize)> {
        let end = offset.wrapping_add(len).wrapping_sub(1);
        if offset >= self.size || end < offset {
            return error::ExceedsLimit {
                addr: offset as u64,
                size: len as u64,
            }
            .fail();
        }
        let valid_len = std::cmp::min(self.size - offset, len);
        Ok((self.addr + offset, valid_len))
    }

    pub fn read<T>(&self, offset: usize) -> Result<T, Error>
    where
        T: FromBytes,
    {
        let s = self.get_partial_slice(offset, size_of::<T>())?;
        match FromBytes::read_from_bytes(s) {
            Err(_) => error::ExceedsLimit {
                addr: offset as u64,
                size: size_of::<T>() as u64,
            }
            .fail(),
            Ok(v) => Ok(v),
        }
    }

    pub fn write<T>(&self, offset: usize, val: &T) -> Result<(), Error>
    where
        T: IntoBytes + Immutable,
    {
        let s = self.get_partial_slice_mut(offset, size_of::<T>())?;
        match IntoBytes::write_to(val, s) {
            Err(_) => error::ExceedsLimit {
                addr: offset as u64,
                size: size_of::<T>() as u64,
            }
            .fail(),
            Ok(()) => Ok(()),
        }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.addr as *mut u8, self.size) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.addr as *const u8, self.size) }
    }

    /// Given offset and len, return a slice, len might be truncated.
    fn get_partial_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        let (addr, len) = self.get_valid_range(offset, len)?;
        Ok(unsafe { std::slice::from_raw_parts(addr as *const u8, len) })
    }

    /// Given offset and len, return a mutable slice, len might be truncated.
    #[allow(clippy::mut_from_ref)]
    fn get_partial_slice_mut(&self, offset: usize, len: usize) -> Result<&mut [u8], Error> {
        let (addr, len) = self.get_valid_range(offset, len)?;
        Ok(unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) })
    }
}

#[derive(Debug)]
pub struct Ram {
    inner: Addressable<ArcMemPages>,
}

#[derive(Debug)]
pub struct RamBus {
    ram: RwLock<Ram>,
}

struct Iter<'m> {
    ram: &'m Ram,
    gpa: u64,
    remain: u64,
}

impl<'m> Iterator for Iter<'m> {
    type Item = Result<&'m [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remain == 0 {
            return None;
        }
        let r = self.ram.get_partial_slice(self.gpa, self.remain);
        if let Ok(s) = r {
            self.gpa += s.len() as u64;
            self.remain -= s.len() as u64;
        }
        Some(r)
    }
}

struct IterMut<'m> {
    ram: &'m Ram,
    gpa: u64,
    remain: u64,
}

impl<'m> Iterator for IterMut<'m> {
    type Item = Result<&'m mut [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remain == 0 {
            return None;
        }
        let r = self.ram.get_partial_slice_mut(self.gpa, self.remain);
        if let Ok(ref s) = r {
            self.gpa += s.len() as u64;
            self.remain -= s.len() as u64;
        }
        Some(r)
    }
}

impl Ram {
    fn slice_iter(&self, gpa: u64, len: u64) -> Iter {
        Iter {
            ram: self,
            gpa,
            remain: len,
        }
    }

    fn slice_iter_mut(&self, gpa: u64, len: u64) -> IterMut {
        IterMut {
            ram: self,
            gpa,
            remain: len,
        }
    }

    fn get_partial_slice(&self, gpa: u64, len: u64) -> Result<&[u8]> {
        let Some((start, user_mem)) = self.inner.search(gpa) else {
            return error::NotMapped { addr: gpa }.fail();
        };
        user_mem.get_partial_slice((gpa - start) as usize, len as usize)
    }

    fn get_partial_slice_mut(&self, gpa: u64, len: u64) -> Result<&mut [u8]> {
        let Some((start, user_mem)) = self.inner.search(gpa) else {
            return error::NotMapped { addr: gpa }.fail();
        };
        user_mem.get_partial_slice_mut((gpa - start) as usize, len as usize)
    }

    pub fn get_slice<T>(&self, gpa: u64, len: u64) -> Result<&[UnsafeCell<T>], Error> {
        let total_len = len * size_of::<T>() as u64;
        let host_ref = self.get_partial_slice(gpa, total_len)?;
        let ptr = host_ref.as_ptr() as *const UnsafeCell<T>;
        if host_ref.len() as u64 != total_len {
            error::NotContinuous {
                addr: gpa,
                size: total_len,
            }
            .fail()
        } else if !ptr.is_aligned() {
            error::NotAligned {
                addr: ptr as u64,
                align: align_of::<T>(),
            }
            .fail()
        } else {
            Ok(unsafe { &*core::ptr::slice_from_raw_parts(ptr, len as usize) })
        }
    }

    pub fn get_ptr<T>(&self, gpa: u64) -> Result<*mut T, Error> {
        let host_ref = self.get_partial_slice_mut(gpa, size_of::<T>() as u64)?;
        let ptr = host_ref.as_mut_ptr();
        if host_ref.len() != size_of::<T>() {
            error::NotContinuous {
                addr: gpa,
                size: size_of::<T>() as u64,
            }
            .fail()
        } else if !ptr.is_aligned() {
            error::NotAligned {
                addr: ptr as u64,
                align: align_of::<T>(),
            }
            .fail()
        } else {
            Ok(ptr as *mut T)
        }
    }

    pub fn read<T>(&self, gpa: u64) -> Result<T, Error>
    where
        T: FromBytes + IntoBytes,
    {
        let mut val = T::new_zeroed();
        let buf = val.as_mut_bytes();
        let host_ref = self.get_partial_slice(gpa, size_of::<T>() as u64)?;
        if host_ref.len() == buf.len() {
            buf.copy_from_slice(host_ref);
            Ok(val)
        } else {
            let mut cur = 0;
            for r in self.slice_iter(gpa, size_of::<T>() as u64) {
                let s = r?;
                let s_len = s.len();
                buf[cur..(cur + s_len)].copy_from_slice(s);
                cur += s_len;
            }
            Ok(val)
        }
    }

    pub fn write<T>(&self, gpa: u64, val: &T) -> Result<(), Error>
    where
        T: IntoBytes + Immutable,
    {
        let buf = val.as_bytes();
        let host_ref = self.get_partial_slice_mut(gpa, size_of::<T>() as u64)?;
        if host_ref.len() == buf.len() {
            host_ref.copy_from_slice(buf);
            Ok(())
        } else {
            let mut cur = 0;
            for r in self.slice_iter_mut(gpa, size_of::<T>() as u64) {
                let s = r?;
                let s_len = s.len();
                s.copy_from_slice(&buf[cur..(cur + s_len)]);
                cur += s_len;
            }
            Ok(())
        }
    }

    pub fn translate(&self, gpa: u64) -> Result<*const u8> {
        let s = self.get_partial_slice(gpa, 1)?;
        Ok(s.as_ptr())
    }

    pub fn translate_iov<'a>(&'a self, iov: &[(u64, u64)]) -> Result<Vec<IoSlice<'a>>> {
        let mut slices = vec![];
        for (gpa, len) in iov {
            for r in self.slice_iter(*gpa, *len) {
                slices.push(IoSlice::new(r?));
            }
        }
        Ok(slices)
    }

    pub fn translate_iov_mut<'a>(&'a self, iov: &[(u64, u64)]) -> Result<Vec<IoSliceMut<'a>>> {
        let mut slices = vec![];
        for (gpa, len) in iov {
            for r in self.slice_iter_mut(*gpa, *len) {
                slices.push(IoSliceMut::new(r?));
            }
        }
        Ok(slices)
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, &ArcMemPages)> {
        self.inner.iter()
    }

    pub fn madvise(&self, gpa: u64, size: u64, advice: i32) -> Result<()> {
        for r in self.slice_iter_mut(gpa, size) {
            let s = r?;
            ffi!(unsafe { madvise(s.as_mut_ptr() as _, s.len(), advice) })?;
        }
        Ok(())
    }
}

impl Default for RamBus {
    fn default() -> Self {
        Self::new()
    }
}

impl RamBus {
    pub fn lock_layout(&self) -> RwLockReadGuard<'_, Ram> {
        self.ram.read()
    }

    pub fn new() -> Self {
        Self {
            ram: RwLock::new(Ram {
                inner: Addressable::default(),
            }),
        }
    }

    pub(crate) fn add(&self, gpa: u64, user_mem: ArcMemPages) -> Result<(), Error> {
        let mut ram = self.ram.write();
        ram.inner.add(gpa, user_mem)?;
        Ok(())
    }

    pub(crate) fn remove(&self, gpa: u64) -> Result<ArcMemPages, Error> {
        let mut ram = self.ram.write();
        ram.inner.remove(gpa)
    }

    pub fn read<T>(&self, gpa: u64) -> Result<T, Error>
    where
        T: FromBytes + IntoBytes,
    {
        let ram = self.ram.read();
        ram.read(gpa)
    }

    pub fn write<T>(&self, gpa: u64, val: &T) -> Result<(), Error>
    where
        T: IntoBytes + Immutable,
    {
        let ram = self.ram.read();
        ram.write(gpa, val)
    }

    pub fn read_range(&self, gpa: u64, len: u64, dst: &mut impl Write) -> Result<()> {
        let ram = self.ram.read();
        for r in ram.slice_iter(gpa, len) {
            dst.write_all(r?).context(error::Write)?;
        }
        Ok(())
    }

    pub fn write_range(&self, gpa: u64, len: u64, mut src: impl Read) -> Result<()> {
        let ram = self.ram.read();
        for r in ram.slice_iter_mut(gpa, len) {
            src.read_exact(r?).context(error::Read)?;
        }
        Ok(())
    }

    pub fn read_vectored<T, F>(&self, bufs: &[(u64, u64)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&[IoSlice<'_>]) -> T,
    {
        let ram = self.ram.read();
        let mut iov = vec![];
        for (gpa, len) in bufs {
            for r in ram.slice_iter(*gpa, *len) {
                iov.push(IoSlice::new(r?));
            }
        }
        Ok(callback(&iov))
    }

    pub fn write_vectored<T, F>(&self, bufs: &[(u64, u64)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&mut [IoSliceMut<'_>]) -> T,
    {
        let ram = self.ram.read();
        let mut iov = vec![];
        for (gpa, len) in bufs {
            for r in ram.slice_iter_mut(*gpa, *len) {
                iov.push(IoSliceMut::new(r?));
            }
        }
        Ok(callback(&mut iov))
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::mem::size_of;

    use assert_matches::assert_matches;
    use libc::{PROT_READ, PROT_WRITE};
    use zerocopy::{FromBytes, Immutable, IntoBytes};

    use super::{ArcMemPages, RamBus};

    #[derive(Debug, IntoBytes, FromBytes, Immutable, PartialEq, Eq)]
    #[repr(C)]
    struct MyStruct {
        data: [u32; 8],
    }

    const PAGE_SIZE: u64 = 1 << 12;

    #[test]
    fn test_ram_bus_read() {
        let bus = RamBus::new();
        let prot = PROT_READ | PROT_WRITE;
        let mem1 = ArcMemPages::from_anonymous(PAGE_SIZE as usize, Some(prot), None).unwrap();
        let mem2 = ArcMemPages::from_anonymous(PAGE_SIZE as usize, Some(prot), None).unwrap();

        if mem1.addr > mem2.addr {
            bus.add(0x0, mem1).unwrap();
            bus.add(PAGE_SIZE, mem2).unwrap();
        } else {
            bus.add(0x0, mem2).unwrap();
            bus.add(PAGE_SIZE, mem1).unwrap();
        }

        let data = MyStruct {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let data_size = size_of::<MyStruct>() as u64;
        for gpa in (PAGE_SIZE - data_size)..=PAGE_SIZE {
            bus.write(gpa, &data).unwrap();
            let r: MyStruct = bus.read(gpa).unwrap();
            assert_eq!(r, data)
        }
        let memory_end = PAGE_SIZE * 2;
        for gpa in (memory_end - data_size - 10)..=(memory_end - data_size) {
            bus.write(gpa, &data).unwrap();
            let r: MyStruct = bus.read(gpa).unwrap();
            assert_eq!(r, data)
        }
        for gpa in (memory_end - data_size + 1)..memory_end {
            assert_matches!(bus.write(gpa, &data), Err(_));
            assert_matches!(bus.read::<MyStruct>(gpa), Err(_));
        }

        let data: Vec<u8> = (0..64).collect();
        for gpa in (PAGE_SIZE - 64)..=PAGE_SIZE {
            bus.write_range(gpa, 64, &*data).unwrap();
            let mut buf = Vec::new();
            bus.read_range(gpa, 64, &mut buf).unwrap();
            assert_eq!(data, buf)
        }

        let guest_iov = [(0, 16), (PAGE_SIZE - 16, 32), (2 * PAGE_SIZE - 16, 16)];
        let write_ret = bus.write_vectored(&guest_iov, |iov| {
            assert_eq!(iov.len(), 4);
            (&*data).read_vectored(iov)
        });
        assert_matches!(write_ret, Ok(Ok(64)));
        let mut buf_read = Vec::new();
        let read_ret = bus.read_vectored(&guest_iov, |iov| {
            assert_eq!(iov.len(), 4);
            buf_read.write_vectored(iov)
        });
        assert_matches!(read_ret, Ok(Ok(64)));

        let locked_bus = bus.lock_layout();
        let bufs = locked_bus.translate_iov(&guest_iov).unwrap();
        println!("{bufs:?}");
        drop(locked_bus);
        bus.remove(0x0).unwrap();
    }
}
