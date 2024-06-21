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
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::ptr::{null_mut, NonNull};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use libc::MFD_CLOEXEC;
use libc::{
    c_void, mmap, msync, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, MAP_SHARED, MS_ASYNC,
    PROT_EXEC, PROT_READ, PROT_WRITE,
};
use parking_lot::{RwLock, RwLockReadGuard};
use zerocopy::{AsBytes, FromBytes};

use crate::ffi;
use crate::hv::{MemMapOption, VmMemory};

use super::addressable::{Addressable, SlotBackend};
use super::{Error, Result};

#[derive(Debug)]
struct MemPages {
    addr: NonNull<c_void>,
    len: usize,
    fd: Option<File>,
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

    pub fn fd(&self) -> Option<BorrowedFd> {
        self._inner.fd.as_ref().map(|f| f.as_fd())
    }

    pub fn sync(&self) -> Result<()> {
        ffi!(unsafe { msync(self.addr as *mut _, self.size, MS_ASYNC) })?;
        Ok(())
    }

    fn from_raw(addr: *mut c_void, len: usize, fd: Option<File>) -> Self {
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
        Ok(Self::from_raw(addr, len, Some(file)))
    }

    #[cfg(target_os = "linux")]
    pub fn from_memfd(size: usize, prot: Option<i32>, name: Option<&CStr>) -> Result<Self> {
        let name = name.unwrap_or(c"anon");
        let fd = ffi!(unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC) })?;
        let prot = prot.unwrap_or(PROT_WRITE | PROT_READ | PROT_EXEC);
        let addr = ffi!(
            unsafe { mmap(null_mut(), size, prot, MAP_SHARED, fd, 0) },
            MAP_FAILED
        )?;
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(size as _)?;
        Ok(Self::from_raw(addr, size, Some(file)))
    }

    pub fn from_anonymous(size: usize, prot: Option<i32>) -> Result<Self> {
        let prot = prot.unwrap_or(PROT_WRITE | PROT_READ | PROT_EXEC);
        let addr = ffi!(
            unsafe { mmap(null_mut(), size, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) },
            MAP_FAILED
        )?;
        Ok(Self::from_raw(addr, size, None))
    }

    /// Given offset and len, return the host virtual address and len;
    /// len might be truncated.
    fn get_valid_range(&self, offset: usize, len: usize) -> Result<(usize, usize)> {
        let end = offset.wrapping_add(len).wrapping_sub(1);
        if offset >= self.size || end < offset {
            return Err(Error::OutOfRange {
                addr: offset as _,
                size: len as _,
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
                addr: offset as _,
                size: size_of::<T>() as _,
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
                addr: offset as _,
                size: size_of::<T>() as _,
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
    fn get_partial_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        let (addr, len) = self.get_valid_range(offset, len)?;
        Ok(unsafe { std::slice::from_raw_parts(addr as *const u8, len) })
    }

    /// Given offset and len, return a mutable slice, len might be truncated.
    fn get_partial_slice_mut(&self, offset: usize, len: usize) -> Result<&mut [u8], Error> {
        let (addr, len) = self.get_valid_range(offset, len)?;
        Ok(unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) })
    }
}

#[derive(Debug)]
pub struct MappedSlot {
    pub pages: ArcMemPages,
    slot_id: u32,
}

impl SlotBackend for MappedSlot {
    fn size(&self) -> u64 {
        self.pages.size as u64
    }
}

#[derive(Debug)]
pub struct RamBus {
    inner: RwLock<Addressable<MappedSlot>>,
    vm_memory: Box<dyn VmMemory>,
    pub(super) next_slot_id: AtomicU32,
    max_mem_slots: u32,
}

pub struct RamLayoutGuard<'a> {
    inner: RwLockReadGuard<'a, Addressable<MappedSlot>>,
}

impl Deref for RamLayoutGuard<'_> {
    type Target = Addressable<MappedSlot>;

    fn deref(&self) -> &Addressable<MappedSlot> {
        &self.inner
    }
}

struct Iter<'a> {
    inner: &'a Addressable<MappedSlot>,
    gpa: u64,
    remain: u64,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remain == 0 {
            return None;
        }
        let r = self.inner.get_partial_slice(self.gpa, self.remain);
        if let Ok(s) = r {
            self.gpa += s.len() as u64;
            self.remain -= s.len() as u64;
        }
        Some(r)
    }
}

struct IterMut<'a> {
    inner: &'a Addressable<MappedSlot>,
    gpa: u64,
    remain: u64,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = Result<&'a mut [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remain == 0 {
            return None;
        }
        let r = self.inner.get_partial_slice_mut(self.gpa, self.remain);
        if let Ok(ref s) = r {
            self.gpa += s.len() as u64;
            self.remain -= s.len() as u64;
        }
        Some(r)
    }
}

impl Addressable<MappedSlot> {
    fn slice_iter(&self, gpa: u64, len: u64) -> Iter {
        Iter {
            inner: self,
            gpa,
            remain: len,
        }
    }

    fn slice_iter_mut(&self, gpa: u64, len: u64) -> IterMut {
        IterMut {
            inner: self,
            gpa,
            remain: len,
        }
    }

    fn get_partial_slice(&self, gpa: u64, len: u64) -> Result<&[u8]> {
        let Some((start, user_mem)) = self.search(gpa) else {
            return Err(Error::NotMapped(gpa));
        };
        user_mem
            .pages
            .get_partial_slice((gpa - start) as usize, len as usize)
    }

    fn get_partial_slice_mut(&self, gpa: u64, len: u64) -> Result<&mut [u8]> {
        let Some((start, user_mem)) = self.search(gpa) else {
            return Err(Error::NotMapped(gpa));
        };
        user_mem
            .pages
            .get_partial_slice_mut((gpa - start) as usize, len as usize)
    }

    pub fn get_slice<T>(&self, gpa: u64, len: u64) -> Result<&[UnsafeCell<T>], Error> {
        let total_len = len * size_of::<T>() as u64;
        let host_ref = self.get_partial_slice(gpa, total_len)?;
        let ptr = host_ref.as_ptr() as *const UnsafeCell<T>;
        if host_ref.len() as u64 != total_len {
            Err(Error::NotContinuous)
        } else if ptr as usize & (align_of::<T>() - 1) != 0 {
            // TODO: use is_aligned
            Err(Error::NotAligned)
        } else {
            Ok(unsafe { &*core::ptr::slice_from_raw_parts(ptr, len as usize) })
        }
    }

    pub fn get_ref<T>(&self, gpa: u64) -> Result<&UnsafeCell<T>, Error> {
        let host_ref = self.get_partial_slice(gpa, size_of::<T>() as u64)?;
        let ptr = host_ref.as_ptr() as *const UnsafeCell<T>;
        if host_ref.len() != size_of::<T>() {
            Err(Error::NotContinuous)
        } else if ptr as usize & (align_of::<T>() - 1) != 0 {
            // TODO: use is_aligned
            Err(Error::NotAligned)
        } else {
            Ok(unsafe { &*ptr })
        }
    }

    pub fn read<T>(&self, gpa: u64) -> Result<T, Error>
    where
        T: FromBytes + AsBytes,
    {
        let mut val = T::new_zeroed();
        let buf = val.as_bytes_mut();
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
        T: AsBytes,
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
}

impl Drop for RamBus {
    fn drop(&mut self) {
        if let Err(e) = self.clear() {
            log::info!("dropping RamBus: {:x?}", e)
        }
    }
}

impl RamBus {
    pub fn lock_layout(&self) -> RamLayoutGuard<'_> {
        RamLayoutGuard {
            inner: self.inner.read(),
        }
    }

    pub fn new<M: VmMemory>(vm_memory: M) -> Self {
        let max_mem_slots = match vm_memory.max_mem_slots() {
            Ok(val) => val,
            Err(e) => {
                log::error!(
                    "quering hypervisor for maximum supported memory slots, got error {e:?}"
                );
                log::error!(
                    "assuming the maximum assuported memory slots is {:#x}",
                    u16::MAX
                );
                u16::MAX as u32
            }
        };
        Self {
            inner: RwLock::new(Addressable::default()),
            vm_memory: Box::new(vm_memory),
            next_slot_id: AtomicU32::new(0),
            max_mem_slots,
        }
    }

    fn map_to_vm(&self, user_mem: &MappedSlot, addr: u64) -> Result<(), Error> {
        let mem_options = MemMapOption {
            read: true,
            write: true,
            exec: true,
            log_dirty: false,
        };
        self.vm_memory.mem_map(
            user_mem.slot_id,
            addr,
            user_mem.pages.size as u64,
            user_mem.pages.addr,
            mem_options,
        )?;
        log::trace!(
            "user memory {} mapped: {:#018x} -> {addr:#018x}, size = {:#x}",
            user_mem.slot_id,
            user_mem.pages.addr,
            user_mem.pages.size
        );
        Ok(())
    }

    fn unmap_from_vm(&self, user_mem: &MappedSlot, addr: u64) -> Result<(), Error> {
        self.vm_memory
            .unmap(user_mem.slot_id, addr, user_mem.size())?;
        log::trace!(
            "user memory {} unmapped: {:#018x} -> {addr:#018x}, size = {:#x}",
            user_mem.slot_id,
            user_mem.pages.addr,
            user_mem.pages.size
        );
        Ok(())
    }

    pub(crate) fn add(&self, gpa: u64, user_mem: ArcMemPages) -> Result<(), Error> {
        let mut inner = self.inner.write();
        let slot = MappedSlot {
            slot_id: self.next_slot_id.fetch_add(1, Ordering::AcqRel) % self.max_mem_slots,
            pages: user_mem,
        };
        let slot = inner.add(gpa, slot)?;
        self.map_to_vm(slot, gpa)?;
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let mut innter = self.inner.write();
        for (gpa, user_mem) in innter.drain(..) {
            self.unmap_from_vm(&user_mem, gpa)?;
        }
        Ok(())
    }

    pub(super) fn remove(&self, gpa: u64) -> Result<ArcMemPages, Error> {
        let mut inner = self.inner.write();
        let mem = inner.remove(gpa)?;
        self.unmap_from_vm(&mem, gpa)?;
        Ok(mem.pages)
    }

    pub fn read<T>(&self, gpa: u64) -> Result<T, Error>
    where
        T: FromBytes + AsBytes,
    {
        let inner = self.inner.read();
        inner.read(gpa)
    }

    pub fn write<T>(&self, gpa: u64, val: &T) -> Result<(), Error>
    where
        T: AsBytes,
    {
        let inner = self.inner.read();
        inner.write(gpa, val)
    }

    pub fn read_range(&self, gpa: u64, len: u64, dst: &mut impl Write) -> Result<()> {
        let inner = self.inner.read();
        for r in inner.slice_iter(gpa, len) {
            dst.write_all(r?)?;
        }
        Ok(())
    }

    pub fn write_range(&self, gpa: u64, len: u64, mut src: impl Read) -> Result<()> {
        let inner = self.inner.read();
        for r in inner.slice_iter_mut(gpa, len) {
            src.read_exact(r?)?;
        }
        Ok(())
    }

    pub fn read_vectored<T, F>(&self, bufs: &[(u64, u64)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&[IoSlice<'_>]) -> T,
    {
        let inner = self.inner.read();
        let mut iov = vec![];
        for (gpa, len) in bufs {
            for r in inner.slice_iter(*gpa, *len) {
                iov.push(IoSlice::new(r?));
            }
        }
        Ok(callback(&iov))
    }

    pub fn write_vectored<T, F>(&self, bufs: &[(u64, u64)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&mut [IoSliceMut<'_>]) -> T,
    {
        let inner = self.inner.read();
        let mut iov = vec![];
        for (gpa, len) in bufs {
            for r in inner.slice_iter_mut(*gpa, *len) {
                iov.push(IoSliceMut::new(r?));
            }
        }
        Ok(callback(&mut iov))
    }

    pub fn mark_private_memory(&self, gpa: u64, size: u64, private: bool) -> Result<()> {
        let inner = self.inner.read();
        let mut start = gpa;
        let end = gpa + size;
        while let Some((addr, slot)) = inner.search_next(start) {
            let gpa_start = std::cmp::max(addr, start);
            let gpa_end = std::cmp::min(end, addr + slot.size());
            if gpa_start >= gpa_end {
                break;
            }
            self.vm_memory
                .mark_private_memory(gpa_start, gpa_end - gpa_start, private)?;
            start = gpa_end;
            if start >= end {
                break;
            }
        }
        Ok(())
    }

    pub fn register_encrypted_pages(&self, pages: &ArcMemPages) -> Result<()> {
        self.vm_memory.register_encrypted_range(pages.as_slice())?;
        Ok(())
    }

    pub fn deregister_encrypted_pages(&self, pages: &ArcMemPages) -> Result<()> {
        self.vm_memory
            .deregister_encrypted_range(pages.as_slice())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use std::io::{Read, Write};
    use std::mem::size_of;

    use libc::{PROT_READ, PROT_WRITE};
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use crate::hv::test::FakeVmMemory;

    use super::{ArcMemPages, RamBus};

    #[derive(Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
    #[repr(C)]
    struct MyStruct {
        data: [u32; 8],
    }

    const PAGE_SIZE: u64 = 1 << 12;

    #[test]
    fn test_ram_bus_read() {
        let bus = RamBus::new(FakeVmMemory);
        let prot = PROT_READ | PROT_WRITE;
        let mem1 = ArcMemPages::from_anonymous(PAGE_SIZE as usize, Some(prot)).unwrap();
        let mem2 = ArcMemPages::from_anonymous(PAGE_SIZE as usize, Some(prot)).unwrap();

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
        println!("{:?}", bufs);
        drop(locked_bus);
        bus.remove(0x0).unwrap();
    }
}
