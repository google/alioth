// SPDX-License-Identifier: GPL-2.0
// Stage-2 Nested Page Tables (4 KiB + automatic 2 MiB NPT PDEs) and Guest RAM object table
// for Linux Ring-0 `airlock.ko`.

use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use vmm_core::host::abi::{spin_lock, spin_unlock, BridgeShm, ShmGuestRamSlot, MAX_RAM_SLOTS};
use vmm_core::host::{HvError, HvResult, MemObjId, MemProt};

use crate::kapi::{
    airlock_kapi_alloc_contig_pages, airlock_kapi_free_contig_pages, airlock_kapi_phys_to_virt,
    PinnedUserMem, SpinLock, PAGE_SIZE_4K,
};

const MAX_MEM_OBJS: usize = 64;
const PTE_COUNT: usize = 512;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const ADDR_MASK_2M: u64 = 0x000f_ffff_ffe0_0000;
const PAGE_SIZE_2M: u64 = 2 << 20;

// AMD NPT requires bit 2 (`USER`) on all directory and leaf entries because
// guest physical walks are treated as user-mode accesses in the nested table.
const NPT_PRESENT: u64 = 1 << 0;
const NPT_WRITABLE: u64 = 1 << 1;
const NPT_USER: u64 = 1 << 2;
const NPT_PWT: u64 = 1 << 3;
const NPT_PCD: u64 = 1 << 4;
const NPT_ACCESSED: u64 = 1 << 5;
const NPT_DIRTY: u64 = 1 << 6;
const NPT_PS: u64 = 1 << 7;
const NPT_NX: u64 = 1 << 63;

const NPT_DIR_FLAGS: u64 = NPT_PRESENT | NPT_WRITABLE | NPT_USER | NPT_ACCESSED;

/// Optional per-VM IOMMU DMA-mapping ops wired by `pci_host.rs` when PCI passthrough is active.
pub trait Stage2IommuOps: Send + Sync {
    fn map_dma(&self, gpa: u64, hpa: u64, size: u64, prot: MemProt) -> HvResult<()>;
    fn unmap_dma(&self, gpa: u64, size: u64);
}

#[repr(C, align(4096))]
struct NptTable {
    entries: [u64; PTE_COUNT],
}

impl NptTable {
    fn alloc() -> HvResult<u64> {
        let mut phys = 0u64;
        let mut virt = null_mut();
        let rc = unsafe { airlock_kapi_alloc_contig_pages(0, -1, &mut phys, &mut virt) };
        if rc < 0 || phys == 0 {
            return Err(HvError::NoMemory);
        }
        Ok(phys)
    }

    unsafe fn from_phys_mut(phys: u64) -> &'static mut Self {
        unsafe { &mut *(airlock_kapi_phys_to_virt(phys) as *mut Self) }
    }

    unsafe fn from_phys(phys: u64) -> &'static Self {
        unsafe { &*(airlock_kapi_phys_to_virt(phys) as *const Self) }
    }
}

enum MemObjBacking {
    SharedArena { start_page: usize, num_pages: usize },
    KernelOwned { pages: Vec<u64> },
    PciBarMmio { phys_base: u64, num_pages: usize },
}

struct MemObj {
    backing: MemObjBacking,
    shm_offset: Option<u64>,
    len: u64,
}

#[derive(Clone, Copy)]
struct FreePageRange {
    start_page: usize,
    num_pages: usize,
}

#[derive(Clone, Copy)]
pub struct SlotMapping {
    pub gpa: u64,
    pub size: u64,
    pub obj: MemObjId,
    pub offset: u64,
    pub prot: MemProt,
    pub is_ram: bool,
    in_shm_slots: bool,
}

struct Stage2Inner {
    l5_phys: u64,
    l4_phys: u64,
    free_shared: Vec<FreePageRange>,
    next_shared_page: usize,
    objs: Vec<Option<MemObj>>,
    slots: Vec<Option<SlotMapping>>,
    iommu_ops: Option<alloc::sync::Arc<dyn Stage2IommuOps>>,
}

#[inline]
fn host_cr4_la57() -> bool {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    (cr4 & (1 << 12)) != 0
}

pub struct Stage2Mmu {
    shared_ram: PinnedUserMem,
    inner: SpinLock<Stage2Inner>,
    tlb_gen: AtomicU64,
    shm_ptr: usize,
}

impl Stage2Mmu {
    pub fn new(shared_ram: PinnedUserMem, shm_ptr: usize) -> HvResult<Self> {
        let l4_phys = NptTable::alloc()?;
        let l5_phys = if host_cr4_la57() {
            match NptTable::alloc() {
                Ok(p5) => {
                    let l5 = unsafe { NptTable::from_phys_mut(p5) };
                    l5.entries[0] = l4_phys | NPT_DIR_FLAGS;
                    p5
                }
                Err(e) => {
                    unsafe { airlock_kapi_free_contig_pages(l4_phys, 0) };
                    return Err(e);
                }
            }
        } else {
            0
        };
        let mut objs = Vec::with_capacity(MAX_MEM_OBJS);
        objs.resize_with(MAX_MEM_OBJS, || None);
        let mut slots = Vec::with_capacity(MAX_RAM_SLOTS);
        slots.resize_with(MAX_RAM_SLOTS, || None);
        Ok(Self {
            shared_ram,
            inner: SpinLock::new(Stage2Inner {
                l5_phys,
                l4_phys,
                free_shared: Vec::new(),
                next_shared_page: 0,
                objs,
                slots,
                iommu_ops: None,
            }),
            tlb_gen: AtomicU64::new(1),
            shm_ptr,
        })
    }

    pub fn root_phys(&self) -> u64 {
        let inner = self.inner.lock();
        if inner.l5_phys != 0 {
            inner.l5_phys
        } else {
            inner.l4_phys
        }
    }

    pub fn tlb_gen(&self) -> u64 {
        self.tlb_gen.load(Ordering::Acquire)
    }

    fn obj_page_phys(&self, inner: &Stage2Inner, obj: MemObjId, page_idx: usize) -> Option<u64> {
        let mem_obj = inner.objs.get(obj as usize)?.as_ref()?;
        match &mem_obj.backing {
            MemObjBacking::SharedArena {
                start_page,
                num_pages,
            } => {
                if page_idx >= *num_pages {
                    return None;
                }
                self.shared_ram.page_phys(*start_page + page_idx)
            }
            MemObjBacking::KernelOwned { pages } => pages.get(page_idx).copied(),
            MemObjBacking::PciBarMmio {
                phys_base,
                num_pages,
            } => {
                if page_idx >= *num_pages {
                    return None;
                }
                Some(*phys_base + ((page_idx as u64) << 12))
            }
        }
    }

    #[allow(dead_code)]
    pub fn register_pci_bar_obj(&self, phys_base: u64, size: u64) -> HvResult<MemObjId> {
        if size == 0 || (phys_base & 0xfff) != 0 || (size & 0xfff) != 0 {
            return Err(HvError::InvalidParam);
        }
        let num_pages = (size >> 12) as usize;
        let mut inner = self.inner.lock();
        let Some(id) = inner.objs.iter().position(Option::is_none) else {
            return Err(HvError::NoMemory);
        };
        inner.objs[id] = Some(MemObj {
            backing: MemObjBacking::PciBarMmio {
                phys_base,
                num_pages,
            },
            shm_offset: None,
            len: size,
        });
        Ok(id as MemObjId)
    }

    #[allow(dead_code)]
    pub fn unregister_pci_bar_obj(&self, obj: MemObjId) {
        let idx = obj as usize;
        if idx >= MAX_MEM_OBJS {
            return;
        }
        let mut inner = self.inner.lock();
        if matches!(
            inner.objs[idx].as_ref().map(|o| &o.backing),
            Some(MemObjBacking::PciBarMmio { .. })
        ) {
            inner.objs[idx] = None;
        }
    }

    #[allow(dead_code)]
    pub fn bind_iommu_and_replay(&self, ops: alloc::sync::Arc<dyn Stage2IommuOps>) -> HvResult<()> {
        let mut inner = self.inner.lock();
        if inner.iommu_ops.is_some() {
            return Ok(());
        }
        let mut mapped_so_far: Vec<(u64, u64)> = Vec::new();
        for slot in inner.slots.iter().flatten() {
            if !slot.is_ram {
                continue;
            }
            if let Err(e) = self.map_slot_in_iommu(
                &inner,
                ops.as_ref(),
                slot.gpa,
                slot.size,
                slot.obj,
                slot.offset,
                slot.prot,
            ) {
                for (mgpa, msz) in mapped_so_far {
                    ops.unmap_dma(mgpa, msz);
                }
                return Err(e);
            }
            mapped_so_far.push((slot.gpa, slot.size));
        }
        inner.iommu_ops = Some(ops);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn clear_iommu_ops(&self) {
        self.inner.lock().iommu_ops = None;
    }

    #[allow(clippy::too_many_arguments)]
    fn map_slot_in_iommu(
        &self,
        inner: &Stage2Inner,
        iommu: &dyn Stage2IommuOps,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()> {
        let num_pages = (size >> 12) as usize;
        if num_pages == 0 {
            return Ok(());
        }
        let first_page_idx = (offset >> 12) as usize;
        let mut run_gpa = gpa;
        let mut run_hpa = self
            .obj_page_phys(inner, obj, first_page_idx)
            .ok_or(HvError::InvalidParam)?;
        let mut run_len = PAGE_SIZE_4K;

        for i in 1..num_pages {
            let cur_gpa = gpa + ((i as u64) << 12);
            let hpa = self
                .obj_page_phys(inner, obj, first_page_idx + i)
                .ok_or(HvError::InvalidParam)?;
            if hpa == run_hpa + run_len {
                run_len += PAGE_SIZE_4K;
            } else {
                if let Err(e) = iommu.map_dma(run_gpa, run_hpa, run_len, prot) {
                    if run_gpa > gpa {
                        iommu.unmap_dma(gpa, run_gpa - gpa);
                    }
                    return Err(e);
                }
                run_gpa = cur_gpa;
                run_hpa = hpa;
                run_len = PAGE_SIZE_4K;
            }
        }
        if let Err(e) = iommu.map_dma(run_gpa, run_hpa, run_len, prot) {
            if run_gpa > gpa {
                iommu.unmap_dma(gpa, run_gpa - gpa);
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
        if size == 0 {
            return Err(HvError::InvalidParam);
        }
        let aligned = size.checked_add(4095).ok_or(HvError::InvalidParam)? & !4095;
        let num_pages = (aligned >> 12) as usize;

        let mut inner = self.inner.lock();
        let Some(id) = inner.objs.iter().position(Option::is_none) else {
            return Err(HvError::NoMemory);
        };

        let total_shared = self.shared_ram.num_pages();
        let shared_alloc = if let Some(pos) = inner
            .free_shared
            .iter()
            .position(|r| r.num_pages >= num_pages)
        {
            let r = &mut inner.free_shared[pos];
            let start = r.start_page;
            if r.num_pages == num_pages {
                inner.free_shared.remove(pos);
            } else {
                r.start_page += num_pages;
                r.num_pages -= num_pages;
            }
            Some((start, true))
        } else if inner.next_shared_page + num_pages <= total_shared {
            let start = inner.next_shared_page;
            inner.next_shared_page += num_pages;
            Some((start, false))
        } else {
            None
        };

        if let Some((start_page, reused)) = shared_alloc {
            if reused {
                for p in start_page..start_page + num_pages {
                    if let Some(pa) = self.shared_ram.page_phys(p) {
                        unsafe {
                            core::ptr::write_bytes(airlock_kapi_phys_to_virt(pa), 0, 4096);
                        }
                    }
                }
            }
            inner.objs[id] = Some(MemObj {
                backing: MemObjBacking::SharedArena {
                    start_page,
                    num_pages,
                },
                shm_offset: Some((start_page as u64) << 12),
                len: aligned,
            });
            return Ok(id as MemObjId);
        }

        let mut pages = Vec::new();
        if pages.try_reserve_exact(num_pages).is_err() {
            return Err(HvError::NoMemory);
        }
        for _ in 0..num_pages {
            let mut phys = 0u64;
            let mut virt = null_mut();
            let rc = unsafe { airlock_kapi_alloc_contig_pages(0, -1, &mut phys, &mut virt) };
            if rc < 0 || phys == 0 {
                for pa in pages {
                    unsafe { airlock_kapi_free_contig_pages(pa, 0) };
                }
                return Err(HvError::NoMemory);
            }
            pages.push(phys);
        }
        inner.objs[id] = Some(MemObj {
            backing: MemObjBacking::KernelOwned { pages },
            shm_offset: None,
            len: aligned,
        });
        Ok(id as MemObjId)
    }

    pub fn mem_free(&self, obj: MemObjId) -> HvResult<()> {
        let idx = obj as usize;
        let mut inner = self.inner.lock();
        if idx >= MAX_MEM_OBJS {
            return Err(HvError::InvalidParam);
        }
        let Some(mem_obj) = inner.objs[idx].as_ref() else {
            return Err(HvError::InvalidParam);
        };
        if matches!(mem_obj.backing, MemObjBacking::PciBarMmio { .. }) {
            return Ok(());
        }
        let mem_obj = inner.objs[idx].take().unwrap();
        match mem_obj.backing {
            MemObjBacking::SharedArena {
                start_page,
                num_pages,
            } => {
                let pos = inner
                    .free_shared
                    .partition_point(|r| r.start_page < start_page);
                inner.free_shared.insert(
                    pos,
                    FreePageRange {
                        start_page,
                        num_pages,
                    },
                );
                let mut merged: Vec<FreePageRange> = Vec::with_capacity(inner.free_shared.len());
                for r in inner.free_shared.drain(..) {
                    match merged.last_mut() {
                        Some(last) if last.start_page + last.num_pages == r.start_page => {
                            last.num_pages += r.num_pages;
                        }
                        _ => merged.push(r),
                    }
                }
                if let Some(last) = merged.last() {
                    if last.start_page + last.num_pages == inner.next_shared_page {
                        inner.next_shared_page = last.start_page;
                        merged.pop();
                    }
                }
                inner.free_shared = merged;
            }
            MemObjBacking::KernelOwned { pages } => {
                for pa in pages {
                    unsafe { airlock_kapi_free_contig_pages(pa, 0) };
                }
            }
            MemObjBacking::PciBarMmio { .. } => unreachable!(),
        }
        Ok(())
    }

    pub fn mem_read(&self, obj: MemObjId, mut offset: u64, mut dst: &mut [u8]) -> HvResult<()> {
        let inner = self.inner.lock();
        let Some(mem_obj) = inner.objs.get(obj as usize).and_then(Option::as_ref) else {
            return Err(HvError::InvalidParam);
        };
        if matches!(mem_obj.backing, MemObjBacking::PciBarMmio { .. }) {
            return Err(HvError::Unsupported);
        }
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(HvError::InvalidParam)?;
        if end > mem_obj.len {
            return Err(HvError::InvalidParam);
        }
        while !dst.is_empty() {
            let page_idx = (offset >> 12) as usize;
            let page_off = (offset & 0xfff) as usize;
            let chunk = (4096 - page_off).min(dst.len());
            let phys = self
                .obj_page_phys(&inner, obj, page_idx)
                .ok_or(HvError::InvalidParam)?;
            let src_ptr = unsafe { airlock_kapi_phys_to_virt(phys).add(page_off) as *const u8 };
            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr, dst.as_mut_ptr(), chunk);
            }
            offset += chunk as u64;
            dst = &mut dst[chunk..];
        }
        Ok(())
    }

    pub fn mem_write(&self, obj: MemObjId, mut offset: u64, mut src: &[u8]) -> HvResult<()> {
        let inner = self.inner.lock();
        let Some(mem_obj) = inner.objs.get(obj as usize).and_then(Option::as_ref) else {
            return Err(HvError::InvalidParam);
        };
        if matches!(mem_obj.backing, MemObjBacking::PciBarMmio { .. }) {
            return Err(HvError::Unsupported);
        }
        let end = offset
            .checked_add(src.len() as u64)
            .ok_or(HvError::InvalidParam)?;
        if end > mem_obj.len {
            return Err(HvError::InvalidParam);
        }
        while !src.is_empty() {
            let page_idx = (offset >> 12) as usize;
            let page_off = (offset & 0xfff) as usize;
            let chunk = (4096 - page_off).min(src.len());
            let phys = self
                .obj_page_phys(&inner, obj, page_idx)
                .ok_or(HvError::InvalidParam)?;
            let dst_ptr = unsafe { airlock_kapi_phys_to_virt(phys).add(page_off) };
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr, chunk);
            }
            offset += chunk as u64;
            src = &src[chunk..];
        }
        Ok(())
    }

    pub fn gpa_map(
        &self,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()> {
        if size == 0 || (gpa & 0xfff) != 0 || (size & 0xfff) != 0 || (offset & 0xfff) != 0 {
            return Err(HvError::InvalidParam);
        }
        if !prot.contains(MemProt::READ) {
            return Err(HvError::Unsupported);
        }
        let gpa_end = gpa.checked_add(size).ok_or(HvError::InvalidParam)?;
        if gpa_end > (1u64 << 48) {
            return Err(HvError::InvalidParam);
        }

        let mut leaf_flags = NPT_PRESENT | NPT_USER | NPT_ACCESSED | NPT_DIRTY;
        if prot.contains(MemProt::WRITE) {
            leaf_flags |= NPT_WRITABLE;
        }
        if !prot.contains(MemProt::EXEC) {
            leaf_flags |= NPT_NX;
        }

        let mut inner = self.inner.lock();
        let (shm_off, is_ram) = {
            let Some(mem_obj) = inner.objs.get(obj as usize).and_then(Option::as_ref) else {
                return Err(HvError::InvalidParam);
            };
            let end = offset.checked_add(size).ok_or(HvError::InvalidParam)?;
            if end > mem_obj.len {
                return Err(HvError::InvalidParam);
            }
            let is_mmio = matches!(mem_obj.backing, MemObjBacking::PciBarMmio { .. });
            (mem_obj.shm_offset.map(|base| base + offset), !is_mmio)
        };
        if !is_ram {
            leaf_flags |= NPT_PCD | NPT_PWT | NPT_NX;
        }

        for existing in inner.slots.iter().flatten() {
            let ex_end = existing.gpa + existing.size;
            if gpa < ex_end && existing.gpa < gpa_end {
                return Err(HvError::InvalidParam);
            }
        }
        let slot_idx = inner
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(HvError::NoMemory)?;

        let num_pages = (size >> 12) as usize;
        let first_page_idx = (offset >> 12) as usize;
        let l4_phys = inner.l4_phys;

        let mut i = 0usize;
        while i < num_pages {
            let cur_gpa = gpa + ((i as u64) << 12);
            let Some(hpa0) = self.obj_page_phys(&inner, obj, first_page_idx + i) else {
                Self::unmap_npt_range(l4_phys, gpa, (i as u64) << 12);
                return Err(HvError::InvalidParam);
            };

            let mut use_2m = is_ram
                && (cur_gpa & (PAGE_SIZE_2M - 1)) == 0
                && (hpa0 & (PAGE_SIZE_2M - 1)) == 0
                && (num_pages - i) >= PTE_COUNT;
            if use_2m {
                for k in 1..PTE_COUNT {
                    if self.obj_page_phys(&inner, obj, first_page_idx + i + k)
                        != Some(hpa0 + ((k as u64) << 12))
                    {
                        use_2m = false;
                        break;
                    }
                }
            }

            if use_2m {
                match Self::try_map_npt_2m(l4_phys, cur_gpa, hpa0, leaf_flags) {
                    Ok(true) => {
                        i += PTE_COUNT;
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        Self::unmap_npt_range(l4_phys, gpa, (i as u64) << 12);
                        return Err(e);
                    }
                }
            }

            if let Err(e) = Self::map_npt_4k(l4_phys, cur_gpa, hpa0, leaf_flags) {
                Self::unmap_npt_range(l4_phys, gpa, (i as u64) << 12);
                return Err(e);
            }
            i += 1;
        }

        if is_ram {
            if let Some(iommu) = inner.iommu_ops.clone() {
                if let Err(e) = self.map_slot_in_iommu(
                    &inner,
                    iommu.as_ref(),
                    gpa,
                    size,
                    obj,
                    offset,
                    prot,
                ) {
                    Self::unmap_npt_range(l4_phys, gpa, size);
                    return Err(e);
                }
            }
        }

        let in_shm_slots = shm_off.is_some();
        inner.slots[slot_idx] = Some(SlotMapping {
            gpa,
            size,
            obj,
            offset,
            prot,
            is_ram,
            in_shm_slots,
        });
        drop(inner);

        if let Some(shm_offset) = shm_off {
            let shm = self.shm_ptr as *mut BridgeShm;
            let lock = unsafe { &(*shm).ram_slots_lock };
            spin_lock(lock);
            unsafe {
                (*shm).ram_slots[slot_idx] = ShmGuestRamSlot {
                    gpa,
                    size,
                    shm_offset,
                    active: 1,
                    _pad: 0,
                };
            }
            spin_unlock(lock);
        }

        self.tlb_gen.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    pub fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()> {
        let mut inner = self.inner.lock();
        let slot_idx = inner
            .slots
            .iter()
            .position(|s| matches!(s, Some(m) if m.gpa == gpa && m.size == size))
            .ok_or(HvError::InvalidParam)?;
        let mapping = inner.slots[slot_idx].take().unwrap();
        if mapping.is_ram {
            if let Some(iommu) = inner.iommu_ops.as_ref() {
                iommu.unmap_dma(gpa, size);
            }
        }
        Self::unmap_npt_range(inner.l4_phys, gpa, size);
        drop(inner);

        if mapping.in_shm_slots {
            let shm = self.shm_ptr as *mut BridgeShm;
            let lock = unsafe { &(*shm).ram_slots_lock };
            spin_lock(lock);
            unsafe {
                (*shm).ram_slots[slot_idx].active = 0;
            }
            spin_unlock(lock);
        }

        self.tlb_gen.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Translates `gpa` through Stage-2 NPT to a host physical address (`hpa`).
    pub fn gpa_to_hpa(&self, gpa: u64, require_write: bool) -> Option<u64> {
        let inner = self.inner.lock();
        let l4 = unsafe { NptTable::from_phys(inner.l4_phys) };
        let e4 = l4.entries[((gpa >> 39) & 0x1ff) as usize];
        if (e4 & NPT_PRESENT) == 0 {
            return None;
        }
        let l3 = unsafe { NptTable::from_phys(e4 & ADDR_MASK) };
        let e3 = l3.entries[((gpa >> 30) & 0x1ff) as usize];
        if (e3 & NPT_PRESENT) == 0 {
            return None;
        }
        let l2 = unsafe { NptTable::from_phys(e3 & ADDR_MASK) };
        let e2 = l2.entries[((gpa >> 21) & 0x1ff) as usize];
        if (e2 & NPT_PRESENT) == 0 {
            return None;
        }
        if (e2 & NPT_PS) != 0 {
            if require_write && (e2 & NPT_WRITABLE) == 0 {
                return None;
            }
            return Some((e2 & ADDR_MASK_2M) | (gpa & (PAGE_SIZE_2M - 1)));
        }
        let l1 = unsafe { NptTable::from_phys(e2 & ADDR_MASK) };
        let e1 = l1.entries[((gpa >> 12) & 0x1ff) as usize];
        if (e1 & NPT_PRESENT) == 0 {
            return None;
        }
        if require_write && (e1 & NPT_WRITABLE) == 0 {
            return None;
        }
        Some((e1 & ADDR_MASK) | (gpa & (PAGE_SIZE_4K - 1)))
    }

    fn try_map_npt_2m(l4_phys: u64, gpa: u64, hpa: u64, leaf_flags: u64) -> HvResult<bool> {
        let i4 = ((gpa >> 39) & 0x1ff) as usize;
        let i3 = ((gpa >> 30) & 0x1ff) as usize;
        let i2 = ((gpa >> 21) & 0x1ff) as usize;

        let l4 = unsafe { NptTable::from_phys_mut(l4_phys) };
        let l3_phys = if (l4.entries[i4] & NPT_PRESENT) != 0 {
            l4.entries[i4] & ADDR_MASK
        } else {
            let p = NptTable::alloc()?;
            l4.entries[i4] = p | NPT_DIR_FLAGS;
            p
        };

        let l3 = unsafe { NptTable::from_phys_mut(l3_phys) };
        let l2_phys = if (l3.entries[i3] & NPT_PRESENT) != 0 {
            l3.entries[i3] & ADDR_MASK
        } else {
            let p = NptTable::alloc()?;
            l3.entries[i3] = p | NPT_DIR_FLAGS;
            p
        };

        let l2 = unsafe { NptTable::from_phys_mut(l2_phys) };
        if (l2.entries[i2] & NPT_PRESENT) != 0 && (l2.entries[i2] & NPT_PS) == 0 {
            return Ok(false);
        }
        l2.entries[i2] = (hpa & ADDR_MASK_2M) | leaf_flags | NPT_PS;
        Ok(true)
    }

    fn map_npt_4k(l4_phys: u64, gpa: u64, hpa: u64, leaf_flags: u64) -> HvResult<()> {
        let i4 = ((gpa >> 39) & 0x1ff) as usize;
        let i3 = ((gpa >> 30) & 0x1ff) as usize;
        let i2 = ((gpa >> 21) & 0x1ff) as usize;
        let i1 = ((gpa >> 12) & 0x1ff) as usize;

        let l4 = unsafe { NptTable::from_phys_mut(l4_phys) };
        let l3_phys = if (l4.entries[i4] & NPT_PRESENT) != 0 {
            l4.entries[i4] & ADDR_MASK
        } else {
            let p = NptTable::alloc()?;
            l4.entries[i4] = p | NPT_DIR_FLAGS;
            p
        };

        let l3 = unsafe { NptTable::from_phys_mut(l3_phys) };
        let l2_phys = if (l3.entries[i3] & NPT_PRESENT) != 0 {
            l3.entries[i3] & ADDR_MASK
        } else {
            let p = NptTable::alloc()?;
            l3.entries[i3] = p | NPT_DIR_FLAGS;
            p
        };

        let l2 = unsafe { NptTable::from_phys_mut(l2_phys) };
        let l1_phys = if (l2.entries[i2] & NPT_PRESENT) != 0 {
            if (l2.entries[i2] & NPT_PS) != 0 {
                let p = NptTable::alloc()?;
                let old = l2.entries[i2];
                let base_hpa = old & ADDR_MASK_2M;
                let flags_4k = old & !(ADDR_MASK | NPT_PS);
                let l1_new = unsafe { NptTable::from_phys_mut(p) };
                for k in 0..PTE_COUNT {
                    l1_new.entries[k] = (base_hpa + ((k as u64) << 12)) | flags_4k;
                }
                l2.entries[i2] = p | NPT_DIR_FLAGS;
                p
            } else {
                l2.entries[i2] & ADDR_MASK
            }
        } else {
            let p = NptTable::alloc()?;
            l2.entries[i2] = p | NPT_DIR_FLAGS;
            p
        };

        let l1 = unsafe { NptTable::from_phys_mut(l1_phys) };
        l1.entries[i1] = (hpa & ADDR_MASK) | leaf_flags;
        Ok(())
    }

    fn unmap_npt_range(l4_phys: u64, gpa: u64, size: u64) {
        let num_pages = (size >> 12) as usize;
        let l4 = unsafe { NptTable::from_phys_mut(l4_phys) };
        let mut i = 0usize;
        while i < num_pages {
            let cur = gpa + ((i as u64) << 12);
            let e4 = l4.entries[((cur >> 39) & 0x1ff) as usize];
            if (e4 & NPT_PRESENT) == 0 {
                i += 1;
                continue;
            }
            let l3 = unsafe { NptTable::from_phys_mut(e4 & ADDR_MASK) };
            let e3 = l3.entries[((cur >> 30) & 0x1ff) as usize];
            if (e3 & NPT_PRESENT) == 0 {
                i += 1;
                continue;
            }
            let l2 = unsafe { NptTable::from_phys_mut(e3 & ADDR_MASK) };
            let i2 = ((cur >> 21) & 0x1ff) as usize;
            let e2 = l2.entries[i2];
            if (e2 & NPT_PRESENT) == 0 {
                i += 1;
                continue;
            }
            if (e2 & NPT_PS) != 0 {
                if (cur & (PAGE_SIZE_2M - 1)) == 0 && (num_pages - i) >= PTE_COUNT {
                    l2.entries[i2] = 0;
                    i += PTE_COUNT;
                    continue;
                }
                if let Ok(p) = NptTable::alloc() {
                    let base_hpa = e2 & ADDR_MASK_2M;
                    let flags_4k = e2 & !(ADDR_MASK | NPT_PS);
                    let l1_new = unsafe { NptTable::from_phys_mut(p) };
                    for k in 0..PTE_COUNT {
                        l1_new.entries[k] = (base_hpa + ((k as u64) << 12)) | flags_4k;
                    }
                    l2.entries[i2] = p | NPT_DIR_FLAGS;
                } else {
                    l2.entries[i2] = 0;
                    i += 1;
                    continue;
                }
            }
            let l1 = unsafe { NptTable::from_phys_mut(l2.entries[i2] & ADDR_MASK) };
            l1.entries[((cur >> 12) & 0x1ff) as usize] = 0;
            i += 1;
        }
    }

    fn free_npt_tree(phys: u64, level: u8) {
        if phys == 0 {
            return;
        }
        if level > 1 {
            let table = unsafe { NptTable::from_phys(phys) };
            for &entry in &table.entries {
                if (entry & NPT_PRESENT) != 0 && !(level == 2 && (entry & NPT_PS) != 0) {
                    Self::free_npt_tree(entry & ADDR_MASK, level - 1);
                }
            }
        }
        unsafe { airlock_kapi_free_contig_pages(phys, 0) };
    }
}

impl Drop for Stage2Mmu {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        inner.iommu_ops = None;
        for obj in inner.objs.iter_mut() {
            if let Some(MemObj {
                backing: MemObjBacking::KernelOwned { pages },
                ..
            }) = obj.take()
            {
                for pa in pages {
                    unsafe { airlock_kapi_free_contig_pages(pa, 0) };
                }
            }
        }
        let l5_phys = inner.l5_phys;
        let l4_phys = inner.l4_phys;
        inner.l5_phys = 0;
        inner.l4_phys = 0;
        drop(inner);
        if l5_phys != 0 {
            unsafe { airlock_kapi_free_contig_pages(l5_phys, 0) };
        }
        Self::free_npt_tree(l4_phys, 4);
    }
}
