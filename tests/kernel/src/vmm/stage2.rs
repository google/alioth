// Stage-2 Nested Page Tables (NPT) and Guest RAM object table for Ring-0 VMM.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use vmm_core::host::abi::{spin_lock, spin_unlock, ShmGuestRamSlot, MAX_RAM_SLOTS};
use vmm_core::host::{HvError, HvResult, MemObjId, MemProt};

use crate::mm::phys::{phys_allocate_frameless, phys_deallocate_frameless};
use crate::mm::user::PinnedUserPage;
use crate::mm::{zero_page, AllocationClass, PageType, PAGE_SIZE_SMALL, PAGING_DIRECT_MAP_OFFSET};
use crate::util::SpinLock;

const MAX_MEM_OBJS: usize = 64;
const PTE_COUNT: usize = 512;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

// AMD NPT requires bit 2 (`USER`) on all directory and leaf entries because
// guest physical walks are treated as user-mode accesses in the nested table.
const NPT_PRESENT: u64 = 1 << 0;
const NPT_WRITABLE: u64 = 1 << 1;
const NPT_USER: u64 = 1 << 2;
const NPT_PWT: u64 = 1 << 3;
const NPT_PCD: u64 = 1 << 4;
const NPT_ACCESSED: u64 = 1 << 5;
const NPT_DIRTY: u64 = 1 << 6;
const NPT_NX: u64 = 1 << 63;

const NPT_DIR_FLAGS: u64 = NPT_PRESENT | NPT_WRITABLE | NPT_USER | NPT_ACCESSED;

#[repr(C, align(4096))]
struct NptTable {
    entries: [u64; PTE_COUNT],
}

impl NptTable {
    fn alloc() -> HvResult<u64> {
        let phys = phys_allocate_frameless(PageType::SmallPage, AllocationClass::Kernel)
            .map_err(|_| HvError::NoMemory)?;
        zero_page(phys + PAGING_DIRECT_MAP_OFFSET, PageType::SmallPage);
        Ok(phys)
    }

    unsafe fn from_phys_mut(phys: u64) -> &'static mut Self {
        unsafe { &mut *((phys + PAGING_DIRECT_MAP_OFFSET) as *mut Self) }
    }

    unsafe fn from_phys(phys: u64) -> &'static Self {
        unsafe { &*((phys + PAGING_DIRECT_MAP_OFFSET) as *const Self) }
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
struct SlotMapping {
    gpa: u64,
    size: u64,
    obj: MemObjId,
    offset: u64,
    prot: MemProt,
    is_ram: bool,
    in_shm_slots: bool,
}

struct Stage2Inner {
    l4_phys: u64,
    free_shared: Vec<FreePageRange>,
    next_shared_page: usize,
    objs: Vec<Option<MemObj>>,
    slots: Vec<Option<SlotMapping>>,
    iommu_domain: Option<u32>,
    iommu_endpoint_count: u32,
}

pub struct Stage2Mmu {
    shared_ram_pages: Vec<PinnedUserPage>,
    inner: SpinLock<Stage2Inner>,
    tlb_gen: AtomicU64,
    shm_ptr: u64,
}

impl Stage2Mmu {
    pub fn new(shared_ram_pages: Vec<PinnedUserPage>, shm_ptr: u64) -> HvResult<Self> {
        let l4_phys = NptTable::alloc()?;
        let mut objs = Vec::with_capacity(MAX_MEM_OBJS);
        objs.resize_with(MAX_MEM_OBJS, || None);
        let mut slots = Vec::with_capacity(MAX_RAM_SLOTS);
        slots.resize_with(MAX_RAM_SLOTS, || None);
        Ok(Self {
            shared_ram_pages,
            inner: SpinLock::new(Stage2Inner {
                l4_phys,
                free_shared: Vec::new(),
                next_shared_page: 0,
                objs,
                slots,
                iommu_domain: None,
                iommu_endpoint_count: 0,
            }),
            tlb_gen: AtomicU64::new(1),
            shm_ptr,
        })
    }

    pub fn root_phys(&self) -> u64 {
        self.inner.lock(line!()).l4_phys
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
                Some(self.shared_ram_pages[*start_page + page_idx].phys_addr())
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

    pub fn register_pci_bar_obj(&self, phys_base: u64, size: u64) -> HvResult<MemObjId> {
        if size == 0 || (phys_base & 0xfff) != 0 || (size & 0xfff) != 0 {
            return Err(HvError::InvalidParam);
        }
        let num_pages = (size >> 12) as usize;
        let mut inner = self.inner.lock(line!());
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

    pub fn unregister_pci_bar_obj(&self, obj: MemObjId) {
        let idx = obj as usize;
        if idx >= MAX_MEM_OBJS {
            return;
        }
        let mut inner = self.inner.lock(line!());
        if matches!(
            inner.objs[idx].as_ref().map(|o| &o.backing),
            Some(MemObjBacking::PciBarMmio { .. })
        ) {
            inner.objs[idx] = None;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn map_slot_in_iommu(
        &self,
        inner: &Stage2Inner,
        iommu: &dyn super::iommu::IommuProvider,
        dom: u32,
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
        let mut run_len = 4096u64;

        for i in 1..num_pages {
            let cur_gpa = gpa + ((i as u64) << 12);
            let hpa = self
                .obj_page_phys(inner, obj, first_page_idx + i)
                .ok_or(HvError::InvalidParam)?;
            if hpa == run_hpa + run_len {
                run_len += 4096;
            } else {
                if let Err(e) = iommu.map_dma(dom, run_gpa, run_hpa, run_len, prot) {
                    if run_gpa > gpa {
                        let _ = iommu.unmap_dma(dom, gpa, run_gpa - gpa);
                    }
                    return Err(e);
                }
                run_gpa = cur_gpa;
                run_hpa = hpa;
                run_len = 4096;
            }
        }
        if let Err(e) = iommu.map_dma(dom, run_gpa, run_hpa, run_len, prot) {
            if run_gpa > gpa {
                let _ = iommu.unmap_dma(dom, gpa, run_gpa - gpa);
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn attach_iommu_endpoint(&self, host_bdf: u16) -> HvResult<()> {
        let Some(iommu) = super::iommu::system_iommu() else {
            return Err(HvError::Unsupported);
        };
        let mut inner = self.inner.lock(line!());
        let dom = match inner.iommu_domain {
            Some(d) => d,
            None => {
                let d = iommu.alloc_domain()?;
                inner.iommu_domain = Some(d);
                d
            }
        };
        if let Err(e) = iommu.attach_endpoint(dom, host_bdf) {
            if inner.iommu_endpoint_count == 0 {
                inner.iommu_domain = None;
                iommu.free_domain(dom);
            }
            return Err(e);
        }
        inner.iommu_endpoint_count += 1;
        if inner.iommu_endpoint_count == 1 {
            // Replay any already-mapped Guest RAM slots into the newly created IOMMU domain.
            let mut mapped_so_far: Vec<(u64, u64)> = Vec::new();
            for slot in inner.slots.iter().flatten() {
                if !slot.is_ram {
                    continue;
                }
                if let Err(e) = self.map_slot_in_iommu(
                    &inner,
                    iommu,
                    dom,
                    slot.gpa,
                    slot.size,
                    slot.obj,
                    slot.offset,
                    slot.prot,
                ) {
                    for (mgpa, msz) in mapped_so_far {
                        let _ = iommu.unmap_dma(dom, mgpa, msz);
                    }
                    inner.iommu_endpoint_count = 0;
                    let _ = iommu.detach_to_blocked(host_bdf);
                    inner.iommu_domain = None;
                    iommu.free_domain(dom);
                    return Err(e);
                }
                mapped_so_far.push((slot.gpa, slot.size));
            }
        }
        Ok(())
    }

    pub fn detach_iommu_endpoint(&self, host_bdf: u16) {
        let Some(iommu) = super::iommu::system_iommu() else {
            return;
        };
        let mut inner = self.inner.lock(line!());
        let _ = iommu.detach_to_blocked(host_bdf);
        inner.iommu_endpoint_count = inner.iommu_endpoint_count.saturating_sub(1);
        if inner.iommu_endpoint_count == 0 {
            if let Some(dom) = inner.iommu_domain.take() {
                iommu.free_domain(dom);
            }
        }
    }

    pub fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
        if size == 0 {
            return Err(HvError::InvalidParam);
        }
        let aligned = size.checked_add(4095).ok_or(HvError::InvalidParam)? & !4095;
        let num_pages = (aligned >> 12) as usize;

        let mut inner = self.inner.lock(line!());
        let Some(id) = inner.objs.iter().position(Option::is_none) else {
            return Err(HvError::NoMemory);
        };

        let total_shared = self.shared_ram_pages.len();
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
                    zero_page(self.shared_ram_pages[p].kernel_addr(), PageType::SmallPage);
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
            match phys_allocate_frameless(PageType::SmallPage, AllocationClass::Kernel) {
                Ok(phys) => {
                    zero_page(phys + PAGING_DIRECT_MAP_OFFSET, PageType::SmallPage);
                    pages.push(phys);
                }
                Err(_) => {
                    for phys in pages {
                        phys_deallocate_frameless(phys, PageType::SmallPage);
                    }
                    return Err(HvError::NoMemory);
                }
            }
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
        let mut inner = self.inner.lock(line!());
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
                for phys in pages {
                    phys_deallocate_frameless(phys, PageType::SmallPage);
                }
            }
            MemObjBacking::PciBarMmio { .. } => unreachable!(),
        }
        Ok(())
    }

    pub fn mem_read(&self, obj: MemObjId, mut offset: u64, mut dst: &mut [u8]) -> HvResult<()> {
        let inner = self.inner.lock(line!());
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
            let src_ptr = (phys + PAGING_DIRECT_MAP_OFFSET + page_off as u64) as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr, dst.as_mut_ptr(), chunk);
            }
            offset += chunk as u64;
            dst = &mut dst[chunk..];
        }
        Ok(())
    }

    pub fn mem_write(&self, obj: MemObjId, mut offset: u64, mut src: &[u8]) -> HvResult<()> {
        let inner = self.inner.lock(line!());
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
            let dst_ptr = (phys + PAGING_DIRECT_MAP_OFFSET + page_off as u64) as *mut u8;
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

        let mut inner = self.inner.lock(line!());
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

        for i in 0..num_pages {
            let cur_gpa = gpa + ((i as u64) << 12);
            let Some(hpa) = self.obj_page_phys(&inner, obj, first_page_idx + i) else {
                Self::unmap_npt_range(l4_phys, gpa, (i as u64) << 12);
                return Err(HvError::InvalidParam);
            };
            if let Err(e) = Self::map_npt_4k(l4_phys, cur_gpa, hpa, leaf_flags) {
                Self::unmap_npt_range(l4_phys, gpa, (i as u64) << 12);
                return Err(e);
            }
        }

        if is_ram && inner.iommu_endpoint_count > 0 {
            if let Some(dom) = inner.iommu_domain {
                if let Some(iommu) = super::iommu::system_iommu() {
                    if let Err(e) =
                        self.map_slot_in_iommu(&inner, iommu, dom, gpa, size, obj, offset, prot)
                    {
                        Self::unmap_npt_range(l4_phys, gpa, size);
                        return Err(e);
                    }
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
            let shm = self.shm_ptr as usize as *mut vmm_core::host::abi::BridgeShm;
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
        let mut inner = self.inner.lock(line!());
        let slot_idx = inner
            .slots
            .iter()
            .position(|s| matches!(s, Some(m) if m.gpa == gpa && m.size == size))
            .ok_or(HvError::InvalidParam)?;
        let mapping = inner.slots[slot_idx].take().unwrap();
        if mapping.is_ram && inner.iommu_endpoint_count > 0 {
            if let Some(dom) = inner.iommu_domain {
                if let Some(iommu) = super::iommu::system_iommu() {
                    let _ = iommu.unmap_dma(dom, gpa, size);
                }
            }
        }
        Self::unmap_npt_range(inner.l4_phys, gpa, size);
        drop(inner);

        if mapping.in_shm_slots {
            let shm = self.shm_ptr as usize as *mut vmm_core::host::abi::BridgeShm;
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
        let inner = self.inner.lock(line!());
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
        let l1 = unsafe { NptTable::from_phys(e2 & ADDR_MASK) };
        let e1 = l1.entries[((gpa >> 12) & 0x1ff) as usize];
        if (e1 & NPT_PRESENT) == 0 {
            return None;
        }
        if require_write && (e1 & NPT_WRITABLE) == 0 {
            return None;
        }
        Some((e1 & ADDR_MASK) | (gpa & (PAGE_SIZE_SMALL - 1)))
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
            l2.entries[i2] & ADDR_MASK
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
        for i in 0..num_pages {
            let cur = gpa + ((i as u64) << 12);
            let e4 = l4.entries[((cur >> 39) & 0x1ff) as usize];
            if (e4 & NPT_PRESENT) == 0 {
                continue;
            }
            let l3 = unsafe { NptTable::from_phys_mut(e4 & ADDR_MASK) };
            let e3 = l3.entries[((cur >> 30) & 0x1ff) as usize];
            if (e3 & NPT_PRESENT) == 0 {
                continue;
            }
            let l2 = unsafe { NptTable::from_phys_mut(e3 & ADDR_MASK) };
            let e2 = l2.entries[((cur >> 21) & 0x1ff) as usize];
            if (e2 & NPT_PRESENT) == 0 {
                continue;
            }
            let l1 = unsafe { NptTable::from_phys_mut(e2 & ADDR_MASK) };
            l1.entries[((cur >> 12) & 0x1ff) as usize] = 0;
        }
    }

    fn free_npt_tree(phys: u64, level: u8) {
        if phys == 0 {
            return;
        }
        if level > 1 {
            let table = unsafe { NptTable::from_phys(phys) };
            for &entry in &table.entries {
                if (entry & NPT_PRESENT) != 0 {
                    Self::free_npt_tree(entry & ADDR_MASK, level - 1);
                }
            }
        }
        phys_deallocate_frameless(phys, PageType::SmallPage);
    }
}

impl Drop for Stage2Mmu {
    fn drop(&mut self) {
        let mut inner = self.inner.lock(line!());
        for obj in inner.objs.iter_mut() {
            if let Some(MemObj {
                backing: MemObjBacking::KernelOwned { pages },
                ..
            }) = obj.take()
            {
                for phys in pages {
                    phys_deallocate_frameless(phys, PageType::SmallPage);
                }
            }
        }
        let l4_phys = inner.l4_phys;
        inner.l4_phys = 0;
        drop(inner);
        Self::free_npt_tree(l4_phys, 4);
    }
}
