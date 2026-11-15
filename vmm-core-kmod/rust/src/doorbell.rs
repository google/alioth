// SPDX-License-Identifier: GPL-2.0
// Fast-path Ring-0 PIO/MMIO Virtio doorbell matcher (0 Wasm transitions).

use alloc::vec::Vec;

use vmm_core::host::{DoorbellSpec, HvError, HvResult, IoSpace};

use crate::kapi::SpinLock;

pub struct DoorbellTable {
    entries: SpinLock<Vec<DoorbellSpec>>,
}

impl Default for DoorbellTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DoorbellTable {
    pub const fn new() -> Self {
        Self {
            entries: SpinLock::new(Vec::new()),
        }
    }

    pub fn register(&self, spec: DoorbellSpec) -> HvResult<()> {
        if !matches!(spec.size, 1 | 2 | 4 | 8) {
            return Err(HvError::InvalidParam);
        }
        let mut entries = self.entries.lock();
        let pos =
            entries.partition_point(|e| (e.space as u8, e.addr) < (spec.space as u8, spec.addr));
        entries.insert(pos, spec);
        Ok(())
    }

    pub fn unregister(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()> {
        let mut entries = self.entries.lock();
        entries.retain(|e| !(e.space == space && e.addr == addr && e.size == size));
        Ok(())
    }

    pub fn match_pio(&self, port: u16, size: u8, val: u64) -> Option<(u32, u16)> {
        self.match_write(IoSpace::Pio, port as u64, size, Some(val))
    }

    pub fn match_write(
        &self,
        space: IoSpace,
        addr: u64,
        size: u8,
        val: Option<u64>,
    ) -> Option<(u32, u16)> {
        let entries = self.entries.lock();
        let idx = entries.partition_point(|e| (e.space as u8, e.addr) < (space as u8, addr));
        let mask = match size {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffff_ffff,
            _ => u64::MAX,
        };
        for e in &entries[idx..] {
            if e.space != space || e.addr != addr {
                break;
            }
            if e.size != size {
                continue;
            }
            match (e.datamatch, val) {
                (None, _) => return Some((e.dev_id, e.queue_idx)),
                (Some(expected), Some(actual)) if (actual & mask) == (expected & mask) => {
                    return Some((e.dev_id, e.queue_idx));
                }
                _ => {}
            }
        }
        None
    }
}
