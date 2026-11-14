// Ring-0 implementations of `VmmHostCore` (`MotorHvCore`) and `VmmCoreBridge` (`MotorCoreBridge`),
// plus `#![no_std]` Wasmtime host-import registration with tiny (<128 B) stack frames.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use vmm_core::host::abi::{
    spin_lock, spin_unlock, BridgeShm, CoreToIoEntry, IoToCoreEntry, RawCpuid, RawDoorbellSpec,
    RawRegEntry, ShmBootInfo, ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig,
    CORE_MSG_SHUTDOWN, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS,
};
use vmm_core::host::{
    DoorbellSpec, HostCaps, HvError, HvResult, IoSpace, MemObjId, MemProt, PayloadKind, RegId,
    RegVal, VcpuId, VmmCoreBridge, VmmHostCore,
};
use wasmtime::{Caller, Linker, SharedMemory};
use zerocopy::{AsBytes, FromBytes};

use crate::mm::user::PinnedUserPage;
use crate::mm::PAGE_SIZE_SMALL;
use crate::uspace::SysObject;
use crate::util::SpinLock;

use super::arch::{ArchSharedTables, ArchVcpu};
use super::doorbell::DoorbellTable;
use super::lapic::{IpiAction, VcpuLapic};
use super::pvclock::PvClockState;
use super::stage2::Stage2Mmu;

pub const MAX_VM_VCPUS: usize = 64;

pub struct VcpuSlot {
    pub vcpu_id: u32,
    pub arch: SpinLock<ArchVcpu>,
    pub lapic: VcpuLapic,
}

impl VcpuSlot {
    pub fn new(vcpu_id: u32, shared: &ArchSharedTables, npt_root_pa: u64) -> HvResult<Self> {
        Ok(Self {
            vcpu_id,
            arch: SpinLock::new(ArchVcpu::new(shared, npt_root_pa)?),
            lapic: VcpuLapic::new(vcpu_id),
        })
    }
}

pub struct MotorHvCore {
    pub arch_tables: ArchSharedTables,
    pub stage2: Stage2Mmu,
    pub doorbells: DoorbellTable,
    pub pvclock: PvClockState,
    pub vcpus: SpinLock<Vec<Arc<VcpuSlot>>>,
    pub vm_obj: SpinLock<Weak<SysObject>>,
    pub shutting_down: AtomicBool,
}

impl MotorHvCore {
    pub fn new(shared_ram_pages: Vec<PinnedUserPage>, shm_ptr: u64) -> HvResult<Self> {
        let arch_tables = ArchSharedTables::new()?;
        let stage2 = Stage2Mmu::new(shared_ram_pages, shm_ptr)?;
        Ok(Self {
            arch_tables,
            stage2,
            doorbells: DoorbellTable::new(),
            pvclock: PvClockState::new(),
            vcpus: SpinLock::new(Vec::new()),
            vm_obj: SpinLock::new(Weak::new()),
            shutting_down: AtomicBool::new(false),
        })
    }

    pub fn set_vm_obj(&self, obj: &Arc<SysObject>) {
        *self.vm_obj.lock(line!()) = Arc::downgrade(obj);
    }

    pub fn wake_vm_obj(&self) {
        let weak = self.vm_obj.lock(line!()).clone();
        if let Some(obj) = weak.upgrade() {
            obj.wake(false);
        }
    }

    pub fn get_or_create_vcpu(&self, id: VcpuId) -> HvResult<Arc<VcpuSlot>> {
        let idx = id as usize;
        if idx >= MAX_VM_VCPUS {
            return Err(HvError::InvalidParam);
        }
        let npt_root = self.stage2.root_phys();
        let mut vcpus = self.vcpus.lock(line!());
        while vcpus.len() <= idx {
            let next_id = vcpus.len() as u32;
            let slot = Arc::new(VcpuSlot::new(next_id, &self.arch_tables, npt_root)?);
            vcpus.push(slot);
        }
        Ok(vcpus[idx].clone())
    }

    pub fn get_vcpu(&self, id: VcpuId) -> Option<Arc<VcpuSlot>> {
        self.vcpus.lock(line!()).get(id as usize).cloned()
    }

    pub fn dispatch_ipi(&self, sender_id: u32, action: IpiAction) {
        if matches!(action, IpiAction::None) {
            return;
        }
        let vcpus: Vec<Arc<VcpuSlot>> = self.vcpus.lock(line!()).clone();
        let targets = |target_id: u32, dest: u32, shorthand: u8| -> bool {
            match shorthand {
                0b00 => dest == 0xffff_ffff || dest == target_id,
                0b01 => target_id == sender_id,
                0b10 => true,
                0b11 => target_id != sender_id,
                _ => false,
            }
        };

        match action {
            IpiAction::None => {}
            IpiAction::Fixed {
                dest,
                shorthand,
                vector,
            } => {
                for slot in &vcpus {
                    if targets(slot.vcpu_id, dest, shorthand) {
                        slot.lapic.set_irr(vector);
                    }
                }
            }
            IpiAction::Init { dest, shorthand } => {
                for slot in &vcpus {
                    if targets(slot.vcpu_id, dest, shorthand) {
                        slot.lapic.receive_init();
                    }
                }
            }
            IpiAction::Sipi {
                dest,
                shorthand,
                start_page,
            } => {
                for slot in &vcpus {
                    if targets(slot.vcpu_id, dest, shorthand) {
                        slot.lapic.receive_sipi(start_page);
                    }
                }
            }
        }
    }

    pub fn signal_shutdown(&self) {
        if !self.shutting_down.swap(true, Ordering::AcqRel) {
            let vcpus: Vec<Arc<VcpuSlot>> = self.vcpus.lock(line!()).clone();
            for slot in &vcpus {
                slot.lapic.kick();
            }
            self.wake_vm_obj();
        }
    }
}

fn push_cpuid(
    out: &mut Vec<RawCpuid>,
    func: u32,
    index: Option<u32>,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
) {
    out.push(RawCpuid {
        func,
        has_index: u32::from(index.is_some()),
        index: index.unwrap_or(0),
        eax,
        ebx,
        ecx,
        edx,
    });
}

impl VmmHostCore for MotorHvCore {
    fn caps(&self) -> HostCaps {
        HostCaps::DOORBELLS
    }

    fn supported_cpuids(&self, dst: &mut [RawCpuid]) -> HvResult<usize> {
        let mut leaves = Vec::with_capacity(32);

        let l0 = core::arch::x86_64::__cpuid(0x0);
        push_cpuid(
            &mut leaves,
            0x0,
            None,
            l0.eax.min(0xd),
            l0.ebx,
            l0.ecx,
            l0.edx,
        );

        let l1 = core::arch::x86_64::__cpuid(0x1);
        // Mask out VMX (5), SMX (6), MONITOR (3), PDCM (15), PCID (17), DCA (18);
        // advertise X2APIC (21), TSC_DEADLINE (24), XSAVE (26), OSXSAVE (27), HYPERVISOR (31).
        let ecx1_keep = (l1.ecx
            & !((1 << 3) | (1 << 5) | (1 << 6) | (1 << 15) | (1 << 17) | (1 << 18)))
            | (1 << 21)
            | (1 << 24)
            | (1 << 31);
        let edx1_keep = l1.edx & !((1 << 7) | (1 << 14) | (1 << 21) | (1 << 22));
        push_cpuid(&mut leaves, 0x1, None, l1.eax, l1.ebx, ecx1_keep, edx1_keep);

        for basic in [0x2u32, 0x4, 0x6] {
            if l0.eax >= basic {
                if basic == 0x4 {
                    for sub in 0..8u32 {
                        let r = core::arch::x86_64::__cpuid_count(0x4, sub);
                        if sub > 0 && (r.eax & 0x1f) == 0 {
                            break;
                        }
                        push_cpuid(&mut leaves, 0x4, Some(sub), r.eax, r.ebx, r.ecx, r.edx);
                    }
                } else {
                    let r = core::arch::x86_64::__cpuid_count(basic, 0);
                    push_cpuid(&mut leaves, basic, None, r.eax, r.ebx, r.ecx, r.edx);
                }
            }
        }

        if l0.eax >= 0x7 {
            let l7 = core::arch::x86_64::__cpuid_count(0x7, 0);
            // Keep FSGSBASE (0), BMI1 (3), AVX2 (5), SMEP (7), BMI2 (8), ERMS (9),
            // RDSEED (18), ADX (19), SMAP (20), CLFLUSHOPT (23), CLWB (24), SHA (29).
            // Omit INVPCID (10) to match PCID masked out in leaf 0x1 ECX.
            let ebx7_allow = (1 << 0)
                | (1 << 3)
                | (1 << 5)
                | (1 << 7)
                | (1 << 8)
                | (1 << 9)
                | (1 << 18)
                | (1 << 19)
                | (1 << 20)
                | (1 << 23)
                | (1 << 24)
                | (1 << 29);
            push_cpuid(&mut leaves, 0x7, Some(0), 0, l7.ebx & ebx7_allow, 0, 0);
        }

        // Topology leaf 0xb (subleaves 0 and 1)
        push_cpuid(&mut leaves, 0xb, Some(0), 1, 1, 0x0100, 0);
        push_cpuid(&mut leaves, 0xb, Some(1), 4, 2, 0x0201, 0);

        // XSAVE leaf 0xd clamped to X87 | SSE | AVX (0x7, 832 bytes) matching Motor OS XCR0
        if l0.eax >= 0xd {
            let d0 = core::arch::x86_64::__cpuid_count(0xd, 0);
            let xcr0_mask = d0.eax & 0x7;
            let max_sz = if (xcr0_mask & 0x4) != 0 { 832 } else { 576 };
            push_cpuid(&mut leaves, 0xd, Some(0), xcr0_mask, max_sz, max_sz, 0);
            let d1 = core::arch::x86_64::__cpuid_count(0xd, 1);
            // Keep XSAVEOPT (0) + XSAVE_COMPACT (1), mask XSAVES (3)
            push_cpuid(&mut leaves, 0xd, Some(1), d1.eax & 0x3, max_sz, 0, 0);
            if (xcr0_mask & 0x4) != 0 {
                let d2 = core::arch::x86_64::__cpuid_count(0xd, 2);
                push_cpuid(&mut leaves, 0xd, Some(2), d2.eax, d2.ebx, d2.ecx, d2.edx);
            }
        }

        // KVM paravirtual clock & timing leaves (`"KVMKVMKVM\0\0\0"`, max leaf `0x4000_0010`)
        push_cpuid(
            &mut leaves,
            0x4000_0000,
            None,
            0x4000_0010,
            0x4b4d_564b,
            0x564b_4d56,
            0x0000_004d,
        );
        // KVM_FEATURE_CLOCKSOURCE (0) | KVM_FEATURE_NOP_IO_DELAY (1)
        // | KVM_FEATURE_CLOCKSOURCE2 (3) | KVM_FEATURE_CLOCKSOURCE_STABLE_BIT (24)
        push_cpuid(
            &mut leaves,
            0x4000_0001,
            None,
            (1 << 0) | (1 << 1) | (1 << 3) | (1 << 24),
            0,
            0,
            0,
        );
        // Paravirtual TSC kHz (EAX) & 1 GHz virtual LAPIC bus kHz (EBX = 1_000_000)
        push_cpuid(
            &mut leaves,
            0x4000_0010,
            None,
            crate::arch::time::tsc_khz(),
            1_000_000,
            0,
            0,
        );

        let ext0 = core::arch::x86_64::__cpuid(0x8000_0000);
        let max_ext = ext0.eax.min(0x8000_0008);
        push_cpuid(
            &mut leaves,
            0x8000_0000,
            None,
            max_ext,
            ext0.ebx,
            ext0.ecx,
            ext0.edx,
        );

        if max_ext >= 0x8000_0001 {
            let e1 = core::arch::x86_64::__cpuid(0x8000_0001);
            // Whitelist safe architectural extended ISA bits (LAHF_LM, ABM/LZCNT, SSE4A,
            // MisAlignSse, 3DNowPrefetch, XOP, FMA4, TBM) while masking SVM, SKINIT, WDT,
            // OSVW, TOPOEXT, PerfCtrExt*, and MWAITX.
            let ecx_e1_allow = (1 << 0)
                | (1 << 5)
                | (1 << 6)
                | (1 << 7)
                | (1 << 8)
                | (1 << 11)
                | (1 << 16)
                | (1 << 21);
            let ecx_e1 = e1.ecx & ecx_e1_allow;
            // Mask MCE (7) and MCA (14) consistently with leaf 0x1 EDX.
            let edx_e1 = e1.edx & !((1 << 7) | (1 << 14));
            push_cpuid(
                &mut leaves,
                0x8000_0001,
                None,
                e1.eax,
                e1.ebx,
                ecx_e1,
                edx_e1,
            );
        }
        for brand in 0x8000_0002..=0x8000_0004 {
            if max_ext >= brand {
                let b = core::arch::x86_64::__cpuid(brand);
                push_cpuid(&mut leaves, brand, None, b.eax, b.ebx, b.ecx, b.edx);
            }
        }
        if max_ext >= 0x8000_0007 {
            let e7 = core::arch::x86_64::__cpuid(0x8000_0007);
            // Keep Invariant TSC (bit 8)
            push_cpuid(&mut leaves, 0x8000_0007, None, 0, 0, 0, e7.edx & (1 << 8));
        }
        if max_ext >= 0x8000_0008 {
            let e8 = core::arch::x86_64::__cpuid(0x8000_0008);
            push_cpuid(&mut leaves, 0x8000_0008, None, e8.eax & 0xffff, 0, 0, 0);
        }

        let n = leaves.len().min(dst.len());
        dst[..n].copy_from_slice(&leaves[..n]);
        Ok(n)
    }

    fn vcpu_configure(&self, vcpu: VcpuId, cpuids: &[RawCpuid]) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        let mut arch = slot.arch.lock(line!());
        arch.configure_cpuids(cpuids)
    }

    fn vcpu_get_regs(&self, vcpu: VcpuId, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        let arch = slot.arch.lock(line!());
        arch.get_regs(&slot.lapic, ids, out)
    }

    fn vcpu_set_regs(&self, vcpu: VcpuId, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        let mut arch = slot.arch.lock(line!());
        arch.set_regs(&slot.lapic, regs)
    }

    fn vcpu_kick(&self, vcpu: VcpuId) -> HvResult<()> {
        if let Some(slot) = self.get_vcpu(vcpu) {
            slot.lapic.kick();
        }
        Ok(())
    }

    fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
        self.stage2.mem_alloc(size)
    }

    fn mem_free(&self, obj: MemObjId) -> HvResult<()> {
        self.stage2.mem_free(obj)
    }

    fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()> {
        self.stage2.mem_read(obj, offset, dst)
    }

    fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()> {
        self.stage2.mem_write(obj, offset, src)
    }

    fn gpa_map(
        &self,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()> {
        self.stage2.gpa_map(gpa, size, obj, offset, prot)
    }

    fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()> {
        self.stage2.gpa_unmap(gpa, size)
    }

    fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()> {
        let vector = (data & 0xff) as u8;
        if vector < 16 {
            return Ok(());
        }
        let dest_mode_logical = ((addr >> 2) & 1) != 0;
        let dest = (((addr >> 32) as u32) << 8) | (((addr >> 12) & 0xff) as u32);

        let vcpus: Vec<Arc<VcpuSlot>> = self.vcpus.lock(line!()).clone();
        for slot in &vcpus {
            let id = slot.vcpu_id;
            let matched = if !dest_mode_logical {
                dest == 0xff || dest == 0xffff_ffff || dest == id
            } else {
                let cluster = dest >> 16;
                let logical_mask = dest & 0xffff;
                if cluster == 0 && (dest & !0xff) == 0 {
                    // Flat logical or x2APIC cluster 0
                    (logical_mask & (1u32 << (id & 0xf))) != 0
                } else {
                    cluster == (id >> 4) && (logical_mask & (1u32 << (id & 0xf))) != 0
                }
            };
            if matched {
                slot.lapic.set_irr(vector);
            }
        }
        Ok(())
    }

    fn set_gsi_level(&self, _gsi: u32, _active: bool) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()> {
        self.doorbells.register(spec)
    }

    fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()> {
        self.doorbells.unregister(space, addr, size)
    }
}

pub struct MotorCoreBridge {
    pub shm_ptr: u64,
    payload_pages: Vec<PinnedUserPage>,
    payload_len: u64,
    ctrl_rx: SpinLock<VecDeque<IoToCoreEntry>>,
    hv: Arc<MotorHvCore>,
}

impl MotorCoreBridge {
    pub fn new(
        shm_ptr: u64,
        payload_pages: Vec<PinnedUserPage>,
        payload_len: u64,
        hv: Arc<MotorHvCore>,
    ) -> Self {
        Self {
            shm_ptr,
            payload_pages,
            payload_len,
            ctrl_rx: SpinLock::new(VecDeque::new()),
            hv,
        }
    }

    pub fn push_ctrl_rx(&self, entry: IoToCoreEntry) {
        self.ctrl_rx.lock(line!()).push_back(entry);
    }
}

impl VmmCoreBridge for MotorCoreBridge {
    fn boot_info(
        &self,
        out_info: &mut ShmBootInfo,
        out_devs: &mut [ShmVirtioDeviceSpec],
    ) -> HvResult<usize> {
        let shm = unsafe { &*(self.shm_ptr as usize as *const BridgeShm) };
        if shm.config_ready.load(Ordering::Acquire) == 0 {
            return Err(HvError::WouldBlock);
        }
        *out_info = shm.boot_info;
        let total = (out_info.num_virtio_devs as usize).min(MAX_VIRTIO_DEVS);
        let count = total.min(out_devs.len());
        out_devs[..count].copy_from_slice(&shm.virtio_devs[..count]);
        Ok(count)
    }

    fn read_payload(&self, kind: PayloadKind, offset: u64, mut dst: &mut [u8]) -> HvResult<usize> {
        let shm = unsafe { &*(self.shm_ptr as usize as *const BridgeShm) };
        let kernel_size = shm.boot_info.kernel_size;
        let initramfs_size = shm.boot_info.initramfs_size;
        let (base_off, kind_len) = match kind {
            PayloadKind::Kernel => (0u64, kernel_size),
            PayloadKind::Initramfs => (kernel_size, initramfs_size),
        };
        if offset >= kind_len || dst.is_empty() {
            return Ok(0);
        }
        let avail = (kind_len - offset).min(dst.len() as u64) as usize;
        let mut cur = base_off.checked_add(offset).ok_or(HvError::InvalidParam)?;
        if cur
            .checked_add(avail as u64)
            .is_none_or(|end| end > self.payload_len)
        {
            return Err(HvError::InvalidParam);
        }

        dst = &mut dst[..avail];
        let mut total_read = 0usize;
        while !dst.is_empty() {
            let page_idx = (cur >> 12) as usize;
            let page_off = (cur & (PAGE_SIZE_SMALL - 1)) as usize;
            let chunk = ((PAGE_SIZE_SMALL as usize) - page_off).min(dst.len());
            let Some(page) = self.payload_pages.get(page_idx) else {
                return Err(HvError::InvalidParam);
            };
            let src = (page.kernel_addr() as usize + page_off) as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), chunk);
            }
            cur += chunk as u64;
            total_read += chunk;
            dst = &mut dst[chunk..];
        }
        Ok(total_read)
    }

    fn configure_device_queues(&self, dev: u32, queues: &[ShmVirtioQueueConfig]) -> HvResult<()> {
        let dev_idx = dev as usize;
        if dev_idx >= MAX_VIRTIO_DEVS || queues.len() > MAX_QUEUES_PER_DEV {
            return Err(HvError::InvalidParam);
        }
        let shm = self.shm_ptr as usize as *mut BridgeShm;
        unsafe {
            for (i, slot) in (*shm).device_queues[dev_idx].iter_mut().enumerate() {
                *slot = queues.get(i).copied().unwrap_or_default();
            }
        }
        Ok(())
    }

    fn update_irq_route(&self, dev: u32, routing: &ShmDeviceMsixRouting) -> HvResult<()> {
        let dev_idx = dev as usize;
        if dev_idx >= MAX_VIRTIO_DEVS {
            return Err(HvError::InvalidParam);
        }
        let shm = self.shm_ptr as usize as *mut BridgeShm;
        let lock = unsafe { &(*shm).msix_lock };
        spin_lock(lock);
        unsafe {
            (*shm).msix_routing[dev_idx] = *routing;
        }
        spin_unlock(lock);
        Ok(())
    }

    fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()> {
        let shm = self.shm_ptr as usize as *mut BridgeShm;
        if entry.msg_type == CORE_MSG_SHUTDOWN {
            unsafe {
                (*shm).shutdown_requested.store(1, Ordering::Release);
                let _ = BridgeShm::push_core_to_io(shm, *entry);
            }
            self.hv.signal_shutdown();
            return Ok(());
        }
        if unsafe { BridgeShm::push_core_to_io(shm, *entry) } {
            self.hv.wake_vm_obj();
        }
        Ok(())
    }

    fn recv_io_cmd(&self, out: &mut IoToCoreEntry) -> HvResult<bool> {
        if let Some(entry) = self.ctrl_rx.lock(line!()).pop_front() {
            *out = entry;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ============================================================================
// `#![no_std]` Wasmtime Import Wrappers (Heap-Allocated Scratch for Small Stack)
// ============================================================================

pub struct CoreHvWasmCtx<H: VmmHostCore + ?Sized> {
    pub host: Arc<H>,
    pub memory: SharedMemory,
}

impl<H: VmmHostCore + ?Sized> CoreHvWasmCtx<H> {
    pub fn new(host: Arc<H>, memory: SharedMemory) -> Self {
        Self { host, memory }
    }
}

pub struct CoreBridgeWasmCtx<B: VmmCoreBridge + ?Sized> {
    pub bridge: Arc<B>,
    pub memory: SharedMemory,
}

impl<B: VmmCoreBridge + ?Sized> CoreBridgeWasmCtx<B> {
    pub fn new(bridge: Arc<B>, memory: SharedMemory) -> Self {
        Self { bridge, memory }
    }
}

#[inline]
fn check_bounds(mem: &SharedMemory, ptr: u32, len: usize) -> HvResult<usize> {
    let start = ptr as usize;
    let end = start.checked_add(len).ok_or(HvError::InvalidParam)?;
    if end > mem.data().len() {
        return Err(HvError::InvalidParam);
    }
    Ok(start)
}

#[inline]
fn read_bytes(mem: &SharedMemory, ptr: u32, dst: &mut [u8]) -> HvResult<()> {
    let start = check_bounds(mem, ptr, dst.len())?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            mem.data().as_ptr().add(start) as *const u8,
            dst.as_mut_ptr(),
            dst.len(),
        );
    }
    Ok(())
}

#[inline]
fn write_bytes(mem: &SharedMemory, ptr: u32, src: &[u8]) -> HvResult<()> {
    let start = check_bounds(mem, ptr, src.len())?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            src.as_ptr(),
            mem.data().as_ptr().add(start) as *mut u8,
            src.len(),
        );
    }
    Ok(())
}

#[inline]
fn read_struct<T: FromBytes + AsBytes + Copy>(mem: &SharedMemory, ptr: u32) -> HvResult<T> {
    let mut val = unsafe { core::mem::zeroed::<T>() };
    read_bytes(mem, ptr, val.as_bytes_mut())?;
    Ok(val)
}

#[inline]
fn write_struct<T: AsBytes>(mem: &SharedMemory, ptr: u32, val: &T) -> HvResult<()> {
    write_bytes(mem, ptr, val.as_bytes())
}

#[inline]
fn read_slice<T: FromBytes + AsBytes + Copy>(
    mem: &SharedMemory,
    ptr: u32,
    dst: &mut [T],
) -> HvResult<()> {
    read_bytes(mem, ptr, dst.as_bytes_mut())
}

#[inline]
fn write_slice<T: AsBytes>(mem: &SharedMemory, ptr: u32, src: &[T]) -> HvResult<()> {
    write_bytes(mem, ptr, src.as_bytes())
}

#[inline]
fn unit_rc(res: HvResult<()>) -> i32 {
    match res {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

pub fn register_core_imports<T, H>(
    linker: &mut Linker<T>,
    get_ctx: impl Fn(&mut T) -> &mut CoreHvWasmCtx<H> + Copy + Send + Sync + 'static,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    H: VmmHostCore + ?Sized,
{
    linker.func_wrap("vmm", "hv_caps", move |mut caller: Caller<'_, T>| -> u32 {
        get_ctx(caller.data_mut()).host.caps().bits()
    })?;

    linker.func_wrap(
        "vmm",
        "hv_supported_cpuids",
        move |mut caller: Caller<'_, T>, dst_ptr: u32, max_entries: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let cap = (max_entries as usize).min(256);
            let mut buf = vec![RawCpuid::default(); cap];
            let count = match ctx.host.supported_cpuids(&mut buf) {
                Ok(n) => n.min(cap),
                Err(e) => return e.code(),
            };
            if let Err(e) = write_slice(&ctx.memory, dst_ptr, &buf[..count]) {
                return e.code();
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_configure",
        move |mut caller: Caller<'_, T>, vcpu: u32, cpuids_ptr: u32, cpuids_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let n = cpuids_len as usize;
            if n > 256 {
                return HvError::InvalidParam.code();
            }
            let mut buf = vec![RawCpuid::default(); n];
            if let Err(e) = read_slice(&ctx.memory, cpuids_ptr, &mut buf) {
                return e.code();
            }
            unit_rc(ctx.host.vcpu_configure(vcpu, &buf))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_regs",
        move |mut caller: Caller<'_, T>, vcpu: u32, regs_ptr: u32, regs_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let n = regs_len as usize;
            if n > 64 {
                return HvError::InvalidParam.code();
            }
            let mut raw = vec![RawRegEntry::default(); n];
            if let Err(e) = read_slice(&ctx.memory, regs_ptr, &mut raw) {
                return e.code();
            }
            let mut ids = vec![RegId::MpState; n];
            let mut vals = vec![RegVal::Scalar(0); n];
            for i in 0..n {
                ids[i] = match raw[i].to_id() {
                    Ok(id) => id,
                    Err(e) => return e.code(),
                };
            }
            if let Err(e) = ctx.host.vcpu_get_regs(vcpu, &ids, &mut vals) {
                return e.code();
            }
            for i in 0..n {
                raw[i].set_val(vals[i]);
            }
            unit_rc(write_slice(&ctx.memory, regs_ptr, &raw))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_regs",
        move |mut caller: Caller<'_, T>, vcpu: u32, regs_ptr: u32, regs_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let n = regs_len as usize;
            if n > 64 {
                return HvError::InvalidParam.code();
            }
            let mut raw = vec![RawRegEntry::default(); n];
            if let Err(e) = read_slice(&ctx.memory, regs_ptr, &mut raw) {
                return e.code();
            }
            let mut pairs = Vec::with_capacity(n);
            for r in &raw {
                match r.to_pair() {
                    Ok(p) => pairs.push(p),
                    Err(e) => return e.code(),
                }
            }
            unit_rc(ctx.host.vcpu_set_regs(vcpu, &pairs))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_kick",
        move |mut caller: Caller<'_, T>, vcpu: u32| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.vcpu_kick(vcpu))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_alloc",
        move |mut caller: Caller<'_, T>, size: u64| -> i32 {
            match get_ctx(caller.data_mut()).host.mem_alloc(size) {
                Ok(id) => id as i32,
                Err(e) => e.code(),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_free",
        move |mut caller: Caller<'_, T>, obj: u32| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.mem_free(obj))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_read",
        move |mut caller: Caller<'_, T>, obj: u32, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            let dst = unsafe {
                core::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            unit_rc(ctx.host.mem_read(obj, offset, dst))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_write",
        move |mut caller: Caller<'_, T>, obj: u32, offset: u64, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            let src = unsafe {
                core::slice::from_raw_parts(
                    ctx.memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            unit_rc(ctx.host.mem_write(obj, offset, src))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "gpa_map",
        move |mut caller: Caller<'_, T>,
              gpa: u64,
              size: u64,
              obj: u32,
              offset: u64,
              prot: u32|
              -> i32 {
            let prot = MemProt::from_bits_retain(prot);
            unit_rc(
                get_ctx(caller.data_mut())
                    .host
                    .gpa_map(gpa, size, obj, offset, prot),
            )
        },
    )?;

    linker.func_wrap(
        "vmm",
        "gpa_unmap",
        move |mut caller: Caller<'_, T>, gpa: u64, size: u64| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.gpa_unmap(gpa, size))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "inject_msi",
        move |mut caller: Caller<'_, T>, addr: u64, data: u32| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.inject_msi(addr, data))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "set_gsi_level",
        move |mut caller: Caller<'_, T>, gsi: u32, active: u32| -> i32 {
            unit_rc(
                get_ctx(caller.data_mut())
                    .host
                    .set_gsi_level(gsi, active != 0),
            )
        },
    )?;

    linker.func_wrap(
        "vmm",
        "register_doorbell",
        move |mut caller: Caller<'_, T>, spec_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw = match read_struct::<RawDoorbellSpec>(&ctx.memory, spec_ptr) {
                Ok(r) => r,
                Err(e) => return e.code(),
            };
            let spec = match raw.to_spec() {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            unit_rc(ctx.host.register_doorbell(spec))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "unregister_doorbell",
        move |mut caller: Caller<'_, T>, space: u32, addr: u64, size: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let io_space = match IoSpace::from_u32(space) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            if size > u8::MAX as u32 {
                return HvError::InvalidParam.code();
            }
            unit_rc(ctx.host.unregister_doorbell(io_space, addr, size as u8))
        },
    )?;

    Ok(())
}

pub fn register_bridge_imports<T, B>(
    linker: &mut Linker<T>,
    get_ctx: impl Fn(&mut T) -> &mut CoreBridgeWasmCtx<B> + Copy + Send + Sync + 'static,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    B: VmmCoreBridge + ?Sized,
{
    linker.func_wrap(
        "vmm_bridge",
        "bridge_boot_info",
        move |mut caller: Caller<'_, T>,
              boot_info_out_ptr: u32,
              devs_out_ptr: u32,
              max_devs: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut info = alloc::boxed::Box::new(ShmBootInfo::default());
            let cap = (max_devs as usize).min(MAX_VIRTIO_DEVS);
            let mut devs = vec![ShmVirtioDeviceSpec::default(); cap];
            let count = match ctx.bridge.boot_info(&mut info, &mut devs) {
                Ok(n) => n.min(cap),
                Err(e) => return e.code(),
            };
            if let Err(e) = write_struct(&ctx.memory, boot_info_out_ptr, &*info) {
                return e.code();
            }
            if count > 0 {
                let elem_bytes = size_of::<ShmVirtioDeviceSpec>() * count;
                if let Err(e) = check_bounds(&ctx.memory, devs_out_ptr, elem_bytes) {
                    return e.code();
                }
                if let Err(e) = write_slice(&ctx.memory, devs_out_ptr, &devs[..count]) {
                    return e.code();
                }
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_read_payload",
        move |mut caller: Caller<'_, T>, kind: u32, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let pkind = match PayloadKind::from_u32(kind) {
                Ok(k) => k,
                Err(e) => return e.code(),
            };
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            let dst = unsafe {
                core::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            match ctx.bridge.read_payload(pkind, offset, dst) {
                Ok(n) => n as i32,
                Err(e) => e.code(),
            }
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_configure_queues",
        move |mut caller: Caller<'_, T>, dev: u32, queues_ptr: u32, num_queues: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let n = num_queues as usize;
            if n > MAX_QUEUES_PER_DEV {
                return HvError::InvalidParam.code();
            }
            let mut queues = vec![ShmVirtioQueueConfig::default(); n];
            if let Err(e) = read_slice(&ctx.memory, queues_ptr, &mut queues) {
                return e.code();
            }
            unit_rc(ctx.bridge.configure_device_queues(dev, &queues))
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_update_irq_route",
        move |mut caller: Caller<'_, T>, dev: u32, routing_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut routing = alloc::boxed::Box::new(ShmDeviceMsixRouting::default());
            if let Err(e) = read_bytes(&ctx.memory, routing_ptr, routing.as_bytes_mut()) {
                return e.code();
            }
            unit_rc(ctx.bridge.update_irq_route(dev, &routing))
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_send_cmd",
        move |mut caller: Caller<'_, T>, entry_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let entry = match read_struct::<CoreToIoEntry>(&ctx.memory, entry_ptr) {
                Ok(e) => e,
                Err(e) => return e.code(),
            };
            unit_rc(ctx.bridge.send_io_cmd(&entry))
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_recv_cmd",
        move |mut caller: Caller<'_, T>, entry_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut out = IoToCoreEntry::default();
            let got = match ctx.bridge.recv_io_cmd(&mut out) {
                Ok(g) => g,
                Err(e) => return e.code(),
            };
            if got {
                if let Err(e) = write_struct(&ctx.memory, entry_out_ptr, &out) {
                    return e.code();
                }
            }
            i32::from(got)
        },
    )?;

    Ok(())
}
