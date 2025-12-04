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

use assert_matches::assert_matches;

use crate::mem::Error;

use super::*;

#[derive(Debug, PartialEq)]
struct Backend {
    size: u64,
}

impl SlotBackend for Backend {
    fn size(&self) -> u64 {
        self.size
    }
}

#[test]
fn test_new_slot() {
    assert_matches!(
        Slot::new(u64::MAX, Backend { size: 0x10 }),
        Err(Error::ExceedsLimit {
            size: 0x10,
            addr: u64::MAX,
            ..
        })
    );
    assert_matches!(
        Slot::new(0, Backend { size: 0 }),
        Err(Error::ZeroSizedSlot { .. })
    );

    let slot = Slot::new(0x1000, Backend { size: 0x1000 }).unwrap();
    assert_eq!(slot.max_addr(), 0x1fff);
}

#[test]
fn test_addressable() {
    let mut memory = Addressable::<Backend>::new();
    assert_matches!(memory.add(0x1000, Backend { size: 0x1000 }), Ok(_));
    assert_matches!(memory.add(0x5000, Backend { size: 0x1000 }), Ok(_));
    assert_matches!(memory.add(0x2000, Backend { size: 0x2000 }), Ok(_));
    assert_eq!(memory.slots.len(), 3);
    assert!(!memory.is_empty());
    assert_eq!(memory.last(), Some((0x5000, &memory.slots[2].backend)));
    // assert_matches!(memory.last_mut(), Some((0x5000, _)));
    assert_matches!(
        memory.add(0x1000, Backend { size: 0x2000 }),
        Err(Error::Overlap {
            new_item: [0x1000, 0x2fff],
            exist_item: [0x1000, 0x1fff],
            ..
        })
    );
    assert_matches!(
        memory.add(0x1, Backend { size: 0x1000 }),
        Err(Error::Overlap {
            new_item: [0x1, 0x1000],
            exist_item: [0x1000, 0x1fff],
            ..
        })
    );

    assert_matches!(memory.add(0x1, Backend { size: 0xfff }), Ok(_));
    assert_matches!(memory.remove(0x1), Ok(_));

    assert_matches!(
        memory.add(0x0, Backend { size: 0x2000 }),
        Err(Error::Overlap {
            new_item: [0x0, 0x1fff],
            exist_item: [0x1000, 0x1fff],
            ..
        })
    );
    assert_matches!(
        memory.add(0x3000, Backend { size: 0x1000 }),
        Err(Error::Overlap {
            new_item: [0x3000, 0x3fff],
            exist_item: [0x2000, 0x3fff],
            ..
        })
    );

    assert_matches!(
        memory.add(0x4000, Backend { size: 0x1001 }),
        Err(Error::Overlap {
            new_item: [0x4000, 0x5000],
            exist_item: [0x5000, 0x5fff],
            ..
        })
    );
    assert_matches!(
        memory.add(0x3fff, Backend { size: 0x1000 }),
        Err(Error::Overlap {
            new_item: [0x3fff, 0x4ffe],
            exist_item: [0x2000, 0x3fff],
            ..
        })
    );
    memory.add(0x4000, Backend { size: 0x1000 }).unwrap();
    memory.remove(0x4000).unwrap();

    assert_eq!(
        memory.search(0x1000),
        Some((memory.slots[0].addr, &memory.slots[0].backend))
    );
    assert_eq!(memory.search(0x0), None);
    assert_eq!(
        memory.search(0x1500),
        Some((memory.slots[0].addr, &memory.slots[0].backend))
    );
    assert_eq!(memory.search(0x4000), None);

    let mut iter = memory.iter();
    assert_eq!(
        iter.next(),
        Some((memory.slots[0].addr, &memory.slots[0].backend))
    );
    assert_eq!(
        iter.next_back(),
        Some((memory.slots[2].addr, &memory.slots[2].backend))
    );
    assert_eq!(
        iter.next(),
        Some((memory.slots[1].addr, &memory.slots[1].backend))
    );
    assert_eq!(iter.next(), None);
    drop(iter);

    assert_matches!(memory.remove(0x1000), Ok(Backend { size: 0x1000 }));
    assert_matches!(
        memory.remove(0x2001),
        Err(Error::NotMapped { addr: 0x2001, .. })
    );

    assert_matches!(
        memory.add(0u64.wrapping_sub(0x2000), Backend { size: 0x2000 }),
        Ok(_)
    );
    assert_matches!(
        memory.add(0u64.wrapping_sub(0x1000), Backend { size: 0x1000 }),
        Err(_)
    )
}
