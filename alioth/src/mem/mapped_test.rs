// Copyright 2025 Google LLC
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
        bus.update(|ram| ram.add(0x0, mem1)).unwrap();
        bus.update(|ram| ram.add(PAGE_SIZE, mem2)).unwrap();
    } else {
        bus.update(|ram| ram.add(0x0, mem2)).unwrap();
        bus.update(|ram| ram.add(PAGE_SIZE, mem1)).unwrap();
    }

    let data = MyStruct {
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let data_size = size_of::<MyStruct>() as u64;
    for gpa in (PAGE_SIZE - data_size)..=PAGE_SIZE {
        bus.write_t(gpa, &data).unwrap();
        let r: MyStruct = bus.read_t(gpa).unwrap();
        assert_eq!(r, data)
    }
    let memory_end = PAGE_SIZE * 2;
    for gpa in (memory_end - data_size - 10)..=(memory_end - data_size) {
        bus.write_t(gpa, &data).unwrap();
        let r: MyStruct = bus.read_t(gpa).unwrap();
        assert_eq!(r, data)
    }
    for gpa in (memory_end - data_size + 1)..memory_end {
        assert_matches!(bus.write_t(gpa, &data), Err(_));
        assert_matches!(bus.read_t::<MyStruct>(gpa), Err(_));
    }

    let data: Vec<u8> = (0..64).collect();
    for gpa in (PAGE_SIZE - 64)..=PAGE_SIZE {
        bus.write_range(gpa, 64, &*data).unwrap();
        let mut buf = Vec::new();
        bus.read_range(gpa, 64, &mut buf).unwrap();
        assert_eq!(data, buf)
    }

    let guest_iov = [(0, 16), (PAGE_SIZE - 16, 32), (2 * PAGE_SIZE - 16, 16)];

    let ram = bus.load();
    let mut iov = ram.translate_iov_mut(&guest_iov).unwrap();
    assert_eq!(iov.len(), 4);
    assert_matches!((&*data).read_vectored(&mut iov), Ok(64));
    drop(iov);
    let iov = ram.translate_iov(&guest_iov).unwrap();
    assert_eq!(iov.len(), 4);
    let mut buf_read = Vec::new();
    assert_matches!(buf_read.write_vectored(&iov), Ok(64));
    assert_eq!(buf_read, data);
    drop(iov);
    drop(ram);
    bus.update(|ram| ram.remove(0x0)).unwrap();
}

#[test]
fn test_ram_bus_snapshot() {
    let bus = RamBus::new();
    assert_eq!(bus.generation(), 0);
    let empty = bus.load();
    assert_eq!(empty.generation(), 0);

    let mem = ArcMemPages::from_anonymous(PAGE_SIZE as usize, None, None).unwrap();
    bus.update(|ram| ram.add(0x0, mem.clone())).unwrap();
    assert_eq!(bus.generation(), 1);

    // An old snapshot is not affected by later updates.
    assert_matches!(empty.read_t::<u32>(0x0), Err(_));
    let snapshot = bus.load();
    assert_eq!(snapshot.generation(), 1);
    snapshot.write_t(0x0, &0xdeadbeef_u32).unwrap();

    // A failed update publishes nothing.
    let r = bus.update(|ram| {
        ram.add(PAGE_SIZE, mem.clone())?;
        ram.add(0x0, mem.clone())
    });
    assert_matches!(r, Err(_));
    assert_eq!(bus.generation(), 1);
    assert_matches!(bus.read_t::<u32>(PAGE_SIZE), Err(_));

    // Removing a slot keeps it accessible through older snapshots.
    bus.update(|ram| ram.remove(0x0)).unwrap();
    assert_eq!(bus.generation(), 2);
    assert_matches!(bus.read_t::<u32>(0x0), Err(_));
    assert_matches!(snapshot.read_t::<u32>(0x0), Ok(0xdeadbeef));
}
