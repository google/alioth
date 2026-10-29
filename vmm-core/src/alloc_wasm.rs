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

//! Spinlock-guarded, coalescing free-list global allocator for `#![no_std]` shared-memory Wasm.
//!
//! Every block address and block size managed by [`FreeListArena`] is a multiple of `MIN_BLOCK`
//! (16 bytes). For any power-of-two alignment `> 16` (e.g., 64-byte `VcpuCommPage` or 4 KiB
//! stacks), aligning a 16-byte-aligned block start produces a prefix that is either 0 bytes or
//! `>= 16` bytes, so split prefixes and suffixes always form valid `FreeNode`s with zero per-block
//! metadata overhead.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

#[cfg(target_arch = "wasm32")]
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use crate::sync::Mutex;

const MIN_BLOCK: usize = 16;
const WASM_PAGE_SIZE: usize = 65536;

#[repr(C)]
struct FreeNode {
    size: usize,
    next: *mut FreeNode,
}

const _: () = assert!(core::mem::size_of::<FreeNode>() <= MIN_BLOCK);
const _: () = assert!(core::mem::align_of::<FreeNode>() <= MIN_BLOCK);

#[inline]
const fn round_up(val: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    match val.checked_add(mask) {
        Some(v) => Some(v & !mask),
        None => None,
    }
}

pub(crate) struct FreeListArena {
    head: *mut FreeNode,
}

// Safety: Protected by `Mutex<FreeListArena>`.
unsafe impl Send for FreeListArena {}

impl FreeListArena {
    pub(crate) const fn new() -> Self {
        Self { head: null_mut() }
    }

    /// Add a raw `[addr .. addr + size)` region (both 16-byte aligned, `size >= 16`) into the
    /// address-ordered free list, coalescing with adjacent neighbors.
    pub(crate) unsafe fn insert_region(&mut self, addr: usize, size: usize) {
        debug_assert_eq!(addr & (MIN_BLOCK - 1), 0);
        debug_assert_eq!(size & (MIN_BLOCK - 1), 0);
        debug_assert!(size >= MIN_BLOCK);

        let mut prev: *mut FreeNode = null_mut();
        let mut curr = self.head;
        while !curr.is_null() && (curr as usize) < addr {
            prev = curr;
            curr = unsafe { (*curr).next };
        }

        let node = addr as *mut FreeNode;
        unsafe {
            (*node).size = size;
            (*node).next = curr;
        }

        // Coalesce with `curr` if `node` immediately precedes `curr`.
        if !curr.is_null() && addr + size == (curr as usize) {
            unsafe {
                (*node).size += (*curr).size;
                (*node).next = (*curr).next;
            }
        }

        // Link after `prev`, coalescing if `prev` immediately precedes `node`.
        if !prev.is_null() {
            let prev_end = (prev as usize) + unsafe { (*prev).size };
            if prev_end == addr {
                unsafe {
                    (*prev).size += (*node).size;
                    (*prev).next = (*node).next;
                }
            } else {
                unsafe {
                    (*prev).next = node;
                }
            }
        } else {
            self.head = node;
        }
    }

    pub(crate) unsafe fn alloc_from_list(&mut self, size: usize, align: usize) -> *mut u8 {
        let mut prev: *mut FreeNode = null_mut();
        let mut curr = self.head;

        while !curr.is_null() {
            let block_addr = curr as usize;
            let block_size = unsafe { (*curr).size };
            let block_end = block_addr + block_size;
            let next = unsafe { (*curr).next };

            if let Some(aligned_addr) = round_up(block_addr, align)
                && let Some(alloc_end) = aligned_addr.checked_add(size)
                && alloc_end <= block_end
            {
                let prefix_size = aligned_addr - block_addr;
                let suffix_size = block_end - alloc_end;
                debug_assert!(prefix_size == 0 || prefix_size >= MIN_BLOCK);
                debug_assert!(suffix_size == 0 || suffix_size >= MIN_BLOCK);

                // Build replacement chain for `[prefix?, suffix?]` -> `next`.
                let after_alloc = if suffix_size >= MIN_BLOCK {
                    let suffix = alloc_end as *mut FreeNode;
                    unsafe {
                        (*suffix).size = suffix_size;
                        (*suffix).next = next;
                    }
                    suffix
                } else {
                    next
                };

                let replacement = if prefix_size >= MIN_BLOCK {
                    let prefix = block_addr as *mut FreeNode;
                    unsafe {
                        (*prefix).size = prefix_size;
                        (*prefix).next = after_alloc;
                    }
                    prefix
                } else {
                    after_alloc
                };

                if !prev.is_null() {
                    unsafe {
                        (*prev).next = replacement;
                    }
                } else {
                    self.head = replacement;
                }

                return aligned_addr as *mut u8;
            }

            prev = curr;
            curr = next;
        }

        null_mut()
    }
}

pub struct WasmGlobalAllocator {
    arena: Mutex<FreeListArena>,
}

impl WasmGlobalAllocator {
    pub const fn new() -> Self {
        Self {
            arena: Mutex::new(FreeListArena::new()),
        }
    }
}

impl Default for WasmGlobalAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "wasm32")]
unsafe impl GlobalAlloc for WasmGlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(MIN_BLOCK);
        let Some(size) = round_up(layout.size().max(MIN_BLOCK), MIN_BLOCK) else {
            return null_mut();
        };

        let mut arena = self.arena.lock();
        let ptr = unsafe { arena.alloc_from_list(size, align) };
        if !ptr.is_null() {
            return ptr;
        }

        let Some(needed) = size.checked_add(align - MIN_BLOCK) else {
            return null_mut();
        };
        let pages = needed.div_ceil(WASM_PAGE_SIZE).max(1);
        let prev_pages = core::arch::wasm32::memory_grow(0, pages);
        if prev_pages == usize::MAX {
            return null_mut();
        }
        let region_addr = prev_pages * WASM_PAGE_SIZE;
        let region_size = pages * WASM_PAGE_SIZE;
        unsafe {
            arena.insert_region(region_addr, region_size);
            arena.alloc_from_list(size, align)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let Some(size) = round_up(layout.size().max(MIN_BLOCK), MIN_BLOCK) else {
            return;
        };
        let mut arena = self.arena.lock();
        unsafe {
            arena.insert_region(ptr as usize, size);
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static GLOBAL_ALLOCATOR: WasmGlobalAllocator = WasmGlobalAllocator::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_list_arena_split_align_and_coalesce() {
        #[repr(align(4096))]
        struct Backing([u8; 16384]);

        let mut backing = alloc::boxed::Box::new(Backing([0u8; 16384]));
        let base = backing.0.as_mut_ptr() as usize;
        let mut arena = FreeListArena::new();

        unsafe {
            arena.insert_region(base, 16384);

            // 1. Small 24B (rounds to 32B) allocation
            let p1 = arena.alloc_from_list(32, 16);
            assert_eq!(p1 as usize, base);

            // 2. 64-byte aligned 320B allocation (`VcpuCommPage` shape)
            let p2 = arena.alloc_from_list(320, 64);
            assert!(!p2.is_null());
            assert_eq!((p2 as usize) & 63, 0);

            // 3. 4096-byte aligned 4096B allocation
            let p3 = arena.alloc_from_list(4096, 4096);
            assert_eq!(p3 as usize, base + 4096);

            // Free all three out of order and verify full coalescing allows 16384B allocation!
            arena.insert_region(p2 as usize, 320);
            arena.insert_region(p1 as usize, 32);
            arena.insert_region(p3 as usize, 4096);

            let full = arena.alloc_from_list(16384, 4096);
            assert_eq!(full as usize, base);
            assert!(arena.alloc_from_list(16, 16).is_null());
        }
    }
}
