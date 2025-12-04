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

use std::ops::RangeBounds;

use crate::mem::{Result, error};

pub trait SlotBackend {
    fn size(&self) -> u64;
}

#[derive(Debug)]
struct Slot<B>
where
    B: SlotBackend,
{
    addr: u64,
    backend: B,
}

impl<B> Slot<B>
where
    B: SlotBackend,
{
    fn new(addr: u64, backend: B) -> Result<Self> {
        if backend.size() == 0 {
            return error::ZeroSizedSlot.fail();
        }
        match (backend.size() - 1).checked_add(addr) {
            None => error::ExceedsLimit {
                addr,
                size: backend.size(),
            }
            .fail(),
            Some(_) => Ok(Self { addr, backend }),
        }
    }

    fn max_addr(&self) -> u64 {
        (self.backend.size() - 1) + self.addr
    }
}

#[derive(Debug)]
pub struct Addressable<B>
where
    B: SlotBackend,
{
    slots: Vec<Slot<B>>,
}

impl<B> Default for Addressable<B>
where
    B: SlotBackend,
{
    fn default() -> Self {
        Addressable { slots: Vec::new() }
    }
}

impl<B> Addressable<B>
where
    B: SlotBackend,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, &B)> {
        self.slots.iter().map(|slot| (slot.addr, &slot.backend))
    }

    pub fn drain(
        &mut self,
        range: impl RangeBounds<usize>,
    ) -> impl DoubleEndedIterator<Item = (u64, B)> + '_ {
        self.slots.drain(range).map(|s| (s.addr, s.backend))
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn last(&self) -> Option<(u64, &B)> {
        self.slots.last().map(|slot| (slot.addr, &slot.backend))
    }
}

impl<B> Addressable<B>
where
    B: SlotBackend,
{
    pub fn add(&mut self, addr: u64, backend: B) -> Result<&mut B> {
        let slot = Slot::new(addr, backend)?;
        let result = match self.slots.binary_search_by_key(&addr, |s| s.addr) {
            Ok(index) => Err(&self.slots[index]),
            Err(index) => {
                if index < self.slots.len() && self.slots[index].addr <= slot.max_addr() {
                    Err(&self.slots[index])
                } else if index > 0 && slot.addr <= self.slots[index - 1].max_addr() {
                    Err(&self.slots[index - 1])
                } else {
                    Ok(index)
                }
            }
        };
        match result {
            Err(curr_slot) => error::Overlap {
                new_item: [slot.addr, slot.max_addr()],
                exist_item: [curr_slot.addr, curr_slot.max_addr()],
            }
            .fail(),
            Ok(index) => {
                self.slots.insert(index, slot);
                // TODO add some compiler hint to eliminate bound check?
                Ok(&mut self.slots[index].backend)
            }
        }
    }

    pub fn remove(&mut self, addr: u64) -> Result<B> {
        match self.slots.binary_search_by_key(&addr, |s| s.addr) {
            Ok(index) => Ok(self.slots.remove(index).backend),
            Err(_) => error::NotMapped { addr }.fail(),
        }
    }

    pub fn search(&self, addr: u64) -> Option<(u64, &B)> {
        match self.slots.binary_search_by_key(&addr, |s| s.addr) {
            Ok(index) => Some((self.slots[index].addr, &self.slots[index].backend)),
            Err(0) => None,
            Err(index) => {
                let candidate = &self.slots[index - 1];
                if addr <= candidate.max_addr() {
                    Some((candidate.addr, &candidate.backend))
                } else {
                    None
                }
            }
        }
    }

    pub fn search_next(&self, addr: u64) -> Option<(u64, &B)> {
        match self.slots.binary_search_by_key(&addr, |s| s.addr) {
            Ok(index) => Some((self.slots[index].addr, &self.slots[index].backend)),
            Err(0) => None,
            Err(index) => {
                let candidate = &self.slots[index - 1];
                if addr <= candidate.max_addr() {
                    Some((candidate.addr, &candidate.backend))
                } else {
                    self.slots.get(index).map(|slot| (slot.addr, &slot.backend))
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "addressable_test.rs"]
mod tests;
