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

use std::fmt::{self, Debug, Formatter};
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::size_of;
use std::ops::Deref;
use std::sync::Arc;

use zerocopy::{AsBytes, FromBytes};

use crate::host::{MemObjId, MemProt, VmmHostCore};
use crate::sync::{RwLock, RwLockReadGuard};

use super::addressable::{Addressable, SlotBackend};
use super::{Error, Result};

struct MemObjHandle {
    id: MemObjId,
    total_size: usize,
    hv: Arc<dyn VmmHostCore>,
}

impl Debug for MemObjHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemObjHandle")
            .field("id", &self.id)
            .field("total_size", &self.total_size)
            .finish()
    }
}

impl Drop for MemObjHandle {
    fn drop(&mut self) {
        let _ = self.hv.mem_free(self.id);
    }
}

#[derive(Debug, Clone)]
pub struct ArcMemPages {
    obj: Arc<MemObjHandle>,
    offset: usize,
    size: usize,
}

impl SlotBackend for ArcMemPages {
    fn size(&self) -> usize {
        self.size
    }
}

impl ArcMemPages {
    pub fn alloc(hv: Arc<dyn VmmHostCore>, size: usize) -> Result<Self> {
        let id = hv.mem_alloc(size as u64)?;
        Ok(Self {
            obj: Arc::new(MemObjHandle {
                id,
                total_size: size,
                hv,
            }),
            offset: 0,
            size,
        })
    }

    pub fn subslice(&self, offset: usize, size: usize) -> Result<Self> {
        let abs_offset = self
            .offset
            .checked_add(offset)
            .ok_or(Error::OutOfRange {
                addr: offset as u64,
                size,
            })?;
        let end = abs_offset.checked_add(size).ok_or(Error::OutOfRange {
            addr: offset as u64,
            size,
        })?;
        if end > self.obj.total_size {
            return Err(Error::OutOfRange {
                addr: offset as u64,
                size,
            });
        }
        Ok(Self {
            obj: self.obj.clone(),
            offset: abs_offset,
            size,
        })
    }

    pub fn mem_obj_id(&self) -> MemObjId {
        self.obj.id
    }

    pub fn mem_obj_offset(&self) -> u64 {
        self.offset as u64
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn get_valid_len(&self, offset: usize, len: usize) -> Result<usize> {
        let end = offset.wrapping_add(len).wrapping_sub(1);
        if offset >= self.size || end < offset {
            return Err(Error::OutOfRange {
                addr: offset as u64,
                size: len,
            });
        }
        Ok(core::cmp::min(self.size - offset, len))
    }

    pub fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, Error> {
        if dst.is_empty() {
            return Ok(0);
        }
        let valid_len = self.get_valid_len(offset, dst.len())?;
        self.obj.hv.mem_read(
            self.obj.id,
            (self.offset + offset) as u64,
            &mut dst[..valid_len],
        )?;
        Ok(valid_len)
    }

    pub fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<usize, Error> {
        if src.is_empty() {
            return Ok(0);
        }
        let valid_len = self.get_valid_len(offset, src.len())?;
        self.obj.hv.mem_write(
            self.obj.id,
            (self.offset + offset) as u64,
            &src[..valid_len],
        )?;
        Ok(valid_len)
    }

    pub fn read<T>(&self, offset: usize) -> Result<T, Error>
    where
        T: FromBytes + AsBytes,
    {
        let mut val = T::new_zeroed();
        let len = self.read_bytes(offset, val.as_bytes_mut())?;
        if len != size_of::<T>() {
            return Err(Error::OutOfRange {
                addr: offset as u64,
                size: size_of::<T>(),
            });
        }
        Ok(val)
    }

    pub fn write<T>(&self, offset: usize, val: &T) -> Result<(), Error>
    where
        T: AsBytes,
    {
        let bytes = val.as_bytes();
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.size)
        {
            return Err(Error::OutOfRange {
                addr: offset as u64,
                size: size_of::<T>(),
            });
        }
        self.write_bytes(offset, bytes)?;
        Ok(())
    }
}

pub struct RamBus {
    inner: RwLock<Addressable<ArcMemPages>>,
    hv: Arc<dyn VmmHostCore>,
}

impl Debug for RamBus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamBus")
            .field("inner", &self.inner)
            .finish()
    }
}

pub struct RamLayoutGuard<'a> {
    inner: RwLockReadGuard<'a, Addressable<ArcMemPages>>,
}

impl Deref for RamLayoutGuard<'_> {
    type Target = Addressable<ArcMemPages>;

    fn deref(&self) -> &Addressable<ArcMemPages> {
        &self.inner
    }
}

impl Addressable<ArcMemPages> {
    pub fn get_chunk_len(&self, gpa: u64, len: usize) -> Result<usize> {
        let Some((start, user_mem)) = self.search(gpa) else {
            return Err(Error::NotMapped(gpa));
        };
        user_mem.get_valid_len((gpa - start) as usize, len)
    }

    pub fn read_partial(&self, gpa: u64, dst: &mut [u8]) -> Result<usize> {
        let Some((start, user_mem)) = self.search(gpa) else {
            return Err(Error::NotMapped(gpa));
        };
        user_mem.read_bytes((gpa - start) as usize, dst)
    }

    pub fn write_partial(&self, gpa: u64, src: &[u8]) -> Result<usize> {
        let Some((start, user_mem)) = self.search(gpa) else {
            return Err(Error::NotMapped(gpa));
        };
        user_mem.write_bytes((gpa - start) as usize, src)
    }

    pub fn validate_range(&self, mut gpa: u64, mut remain: usize) -> Result<Vec<(u64, usize)>> {
        let mut chunks = Vec::new();
        while remain > 0 {
            let chunk_len = self.get_chunk_len(gpa, remain)?;
            chunks.push((gpa, chunk_len));
            gpa += chunk_len as u64;
            remain -= chunk_len;
        }
        Ok(chunks)
    }

    pub fn read_exact_bytes(&self, mut gpa: u64, mut dst: &mut [u8]) -> Result<()> {
        self.validate_range(gpa, dst.len())?;
        while !dst.is_empty() {
            let n = self.read_partial(gpa, dst)?;
            gpa += n as u64;
            dst = &mut dst[n..];
        }
        Ok(())
    }

    pub fn write_exact_bytes(&self, mut gpa: u64, mut src: &[u8]) -> Result<()> {
        self.validate_range(gpa, src.len())?;
        while !src.is_empty() {
            let n = self.write_partial(gpa, src)?;
            gpa += n as u64;
            src = &src[n..];
        }
        Ok(())
    }

    pub fn read<T>(&self, gpa: u64) -> Result<T, Error>
    where
        T: FromBytes + AsBytes,
    {
        let mut val = T::new_zeroed();
        self.read_exact_bytes(gpa, val.as_bytes_mut())?;
        Ok(val)
    }

    pub fn write<T>(&self, gpa: u64, val: &T) -> Result<(), Error>
    where
        T: AsBytes,
    {
        self.write_exact_bytes(gpa, val.as_bytes())
    }

    pub fn translate_iov(&self, iov: &[(u64, usize)]) -> Result<Vec<Vec<u8>>> {
        let mut bufs = vec![];
        for (gpa, len) in iov {
            for (chunk_gpa, chunk_len) in self.validate_range(*gpa, *len)? {
                let mut buf = vec![0u8; chunk_len];
                self.read_exact_bytes(chunk_gpa, &mut buf)?;
                bufs.push(buf);
            }
        }
        Ok(bufs)
    }
}

impl Drop for RamBus {
    fn drop(&mut self) {
        if let Err(e) = self.clear() {
            log::info!("dropping RamBus: {e:x?}")
        }
    }
}

impl RamBus {
    pub fn lock_layout(&self) -> RamLayoutGuard<'_> {
        RamLayoutGuard {
            inner: self.inner.read(),
        }
    }

    pub fn new(hv: Arc<dyn VmmHostCore>) -> Self {
        Self {
            inner: RwLock::new(Addressable::default()),
            hv,
        }
    }

    pub fn alloc_anon_mem(&self, size: usize) -> Result<ArcMemPages, Error> {
        ArcMemPages::alloc(self.hv.clone(), size)
    }

    fn map_to_vm(&self, user_mem: &ArcMemPages, gpa: u64) -> Result<(), Error> {
        self.hv.gpa_map(
            gpa,
            user_mem.size as u64,
            user_mem.mem_obj_id(),
            user_mem.mem_obj_offset(),
            MemProt::RWX,
        )?;
        log::trace!(
            "mem_obj {} (off={:#x}) mapped at gpa {gpa:#018x}, size = {:#x}",
            user_mem.mem_obj_id(),
            user_mem.mem_obj_offset(),
            user_mem.size
        );
        Ok(())
    }

    fn unmap_from_vm(&self, user_mem: &ArcMemPages, gpa: u64) -> Result<(), Error> {
        self.hv.gpa_unmap(gpa, user_mem.size as u64)?;
        log::trace!(
            "mem_obj {} unmapped from gpa {gpa:#018x}, size = {:#x}",
            user_mem.mem_obj_id(),
            user_mem.size
        );
        Ok(())
    }

    pub(crate) fn add(&self, gpa: u64, user_mem: ArcMemPages) -> Result<(), Error> {
        let mut inner = self.inner.write();
        let added = inner.add(gpa, user_mem)?;
        if let Err(e) = self.map_to_vm(added, gpa) {
            let _ = inner.remove(gpa);
            return Err(e);
        }
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let mut inner = self.inner.write();
        for (gpa, user_mem) in inner.drain(..) {
            self.unmap_from_vm(&user_mem, gpa)?;
        }
        Ok(())
    }

    pub(super) fn remove(&self, gpa: u64) -> Result<ArcMemPages, Error> {
        let mut inner = self.inner.write();
        let mem = inner.remove(gpa)?;
        self.unmap_from_vm(&mem, gpa)?;
        Ok(mem)
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

    pub fn read_range(&self, gpa: u64, len: usize, dst: &mut impl Write) -> Result<()> {
        const CHUNK: usize = 64 * 1024;
        let inner = self.inner.read();
        let ranges = inner.validate_range(gpa, len)?;
        let mut buf = vec![0u8; len.min(CHUNK)];
        for (mut chunk_gpa, mut remain) in ranges {
            while remain > 0 {
                let n = remain.min(buf.len());
                inner.read_exact_bytes(chunk_gpa, &mut buf[..n])?;
                dst.write_all(&buf[..n])?;
                chunk_gpa += n as u64;
                remain -= n;
            }
        }
        Ok(())
    }

    pub fn write_range(&self, gpa: u64, len: usize, mut src: impl Read) -> Result<()> {
        const CHUNK: usize = 64 * 1024;
        let inner = self.inner.read();
        let ranges = inner.validate_range(gpa, len)?;
        let mut buf = vec![0u8; len.min(CHUNK)];
        for (mut chunk_gpa, mut remain) in ranges {
            while remain > 0 {
                let n = remain.min(buf.len());
                src.read_exact(&mut buf[..n])?;
                inner.write_exact_bytes(chunk_gpa, &buf[..n])?;
                chunk_gpa += n as u64;
                remain -= n;
            }
        }
        Ok(())
    }

    pub fn read_vectored<T, F>(&self, bufs: &[(u64, usize)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&[IoSlice<'_>]) -> T,
    {
        let inner = self.inner.read();
        let vecs = inner.translate_iov(bufs)?;
        let iov: Vec<IoSlice<'_>> = vecs.iter().map(|v| IoSlice::new(v)).collect();
        Ok(callback(&iov))
    }

    pub fn write_vectored<T, F>(&self, bufs: &[(u64, usize)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&mut [IoSliceMut<'_>]) -> T,
    {
        let inner = self.inner.read();
        let mut chunks = Vec::new();
        for (gpa, len) in bufs {
            for (chunk_gpa, chunk_len) in inner.validate_range(*gpa, *len)? {
                chunks.push((chunk_gpa, vec![0u8; chunk_len]));
            }
        }
        let mut iov: Vec<IoSliceMut<'_>> =
            chunks.iter_mut().map(|(_, v)| IoSliceMut::new(v)).collect();
        let res = callback(&mut iov);
        drop(iov);
        for (chunk_gpa, buf) in chunks {
            inner.write_exact_bytes(chunk_gpa, &buf)?;
        }
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::mem::size_of;

    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use crate::host::test::FakeHost;

    use super::{ArcMemPages, RamBus};

    macro_rules! assert_matches {
        ($expression:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
            assert!(matches!($expression, $pattern $(if $guard)?))
        };
    }

    #[derive(Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
    #[repr(C)]
    struct MyStruct {
        data: [u32; 8],
    }

    const PAGE_SIZE: usize = 1 << 12;
    const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

    #[test]
    fn test_ram_bus_read() {
        let hv = FakeHost::new_arc();
        let bus = RamBus::new(hv.clone());
        let backing = ArcMemPages::alloc(hv, 3 * PAGE_SIZE).unwrap();
        let mem1 = backing.subslice(0, PAGE_SIZE).unwrap();
        let mem2 = backing.subslice(2 * PAGE_SIZE, PAGE_SIZE).unwrap();

        bus.add(0x0, mem1).unwrap();
        bus.add(PAGE_SIZE_U64, mem2).unwrap();

        let data = MyStruct {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let data_size = size_of::<MyStruct>() as u64;
        for gpa in (PAGE_SIZE_U64 - data_size)..=PAGE_SIZE_U64 {
            bus.write(gpa, &data).unwrap();
            let r: MyStruct = bus.read(gpa).unwrap();
            assert_eq!(r, data)
        }
        let memory_end = PAGE_SIZE_U64 * 2;
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
        for gpa in (PAGE_SIZE_U64 - 64)..=PAGE_SIZE_U64 {
            bus.write_range(gpa, 64, &*data).unwrap();
            let mut buf = Vec::new();
            bus.read_range(gpa, 64, &mut buf).unwrap();
            assert_eq!(data, buf)
        }

        let guest_iov = [
            (0, 16),
            (PAGE_SIZE_U64 - 16, 32),
            (2 * PAGE_SIZE_U64 - 16, 16),
        ];
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
        assert_eq!(bufs.len(), 4);
        drop(locked_bus);
        bus.remove(0x0).unwrap();
        bus.remove(PAGE_SIZE_U64).unwrap();
        drop(backing);
    }
}
