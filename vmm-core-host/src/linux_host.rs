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

use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, SIGRTMIN, c_void, eventfd};
use parking_lot::{Mutex, RwLock};
use vmm_core::host::abi::{
    MAX_RAM_SLOTS, RawCpuid, ShmGuestRamSlot, VcpuCommPage, spin_lock, spin_unlock,
};
use vmm_core::host::{
    DoorbellSpec, HostCaps, HvError, HvResult, IoSpace, MemObjId, MemProt, RegId, RegVal, VcpuId,
    VmmHostCore,
};

use crate::ffi;
use crate::kvm::bindings::{
    KVM_API_VERSION, KVM_CAP_EXIT_ON_EMULATION_FAILURE, KVM_CAP_SIGNAL_MSI, KVM_CAP_SPLIT_IRQCHIP,
    KVM_CAP_SYNC_REGS, KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES, KVM_MAX_CPUID_ENTRIES,
    KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmEnableCap, KvmIoEventFd, KvmIoEventFdFlag,
    KvmMemFlag, KvmMsi, KvmUserspaceMemoryRegion, kvm_check_extension, kvm_create_vcpu,
    kvm_create_vm, kvm_enable_cap, kvm_get_api_version, kvm_get_supported_cpuid,
    kvm_get_vcpu_mmap_size, kvm_ioeventfd, kvm_set_identity_map_addr, kvm_set_tss_addr,
    kvm_set_user_memory_region, kvm_signal_msi,
};
use crate::kvm::vcpu::{KvmRunBlock, KvmVcpu, io_to_hv_err};
use crate::kvm::{
    CoreBridgeFds, DoorbellRegistry, KvmDoorbellEntry, SharedCoreBridge, spawn_i2c_listener,
};

pub const MAX_VCPUS: usize = 64;
pub const MAX_MEM_OBJS: usize = 64;

extern "C" fn sigrtmin_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut c_void) {}

struct KvmVcpuSlot {
    vcpu: Mutex<KvmVcpu>,
    immediate_exit: *mut AtomicU8,
    runner_tid: AtomicU64,
}

unsafe impl Send for KvmVcpuSlot {}
unsafe impl Sync for KvmVcpuSlot {}

struct KvmMemObj {
    addr: NonNull<c_void>,
    shm_offset: u64,
    len: u64,
}

unsafe impl Send for KvmMemObj {}
unsafe impl Sync for KvmMemObj {}

#[derive(Debug, Clone, Copy)]
struct KvmSlotMapping {
    gpa: u64,
    size: u64,
}

/// Single-VM Linux/KVM partition implementing [`VmmHostCore`].
pub struct KvmCoreHost {
    kvm_fd: OwnedFd,
    vm_fd: Arc<OwnedFd>,
    vcpu_mmap_size: usize,
    sync_regs_cap: u64,
    bridge: Arc<SharedCoreBridge>,
    doorbells: Arc<DoorbellRegistry>,
    vcpus: RwLock<[Option<Arc<KvmVcpuSlot>>; MAX_VCPUS]>,
    mem_objs: RwLock<[Option<KvmMemObj>; MAX_MEM_OBJS]>,
    memslots: Mutex<[Option<KvmSlotMapping>; MAX_RAM_SLOTS]>,
}

impl KvmCoreHost {
    pub fn new(fds: CoreBridgeFds) -> std::io::Result<Self> {
        let bridge = SharedCoreBridge::from_fds(fds)?;
        let doorbells = DoorbellRegistry::new()?;

        let kvm_file = File::open("/dev/kvm")?;
        let kvm_fd = OwnedFd::from(kvm_file);
        let version = unsafe { kvm_get_api_version(&kvm_fd) }?;
        if version != KVM_API_VERSION {
            return Err(std::io::Error::other(format!(
                "unsupported KVM API version {version}, expected {KVM_API_VERSION}"
            )));
        }

        let mut action: libc::sigaction = unsafe { transmute([0u8; size_of::<libc::sigaction>()]) };
        action.sa_flags = libc::SA_SIGINFO;
        action.sa_sigaction = sigrtmin_handler as *const () as _;
        ffi!(unsafe { libc::sigfillset(&mut action.sa_mask) })?;
        ffi!(unsafe { libc::sigaction(SIGRTMIN(), &action, null_mut()) })?;

        let vcpu_mmap_size = unsafe { kvm_get_vcpu_mmap_size(&kvm_fd) }? as usize;
        let sync_regs_raw = unsafe { kvm_check_extension(&kvm_fd, KVM_CAP_SYNC_REGS) }.unwrap_or(0);
        let sync_regs_cap = sync_regs_raw.max(0) as u64;

        let raw_vm_fd = unsafe { kvm_create_vm(&kvm_fd, 0) }?;
        let vm_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw_vm_fd) });

        if unsafe { kvm_check_extension(&vm_fd, KVM_CAP_SIGNAL_MSI) }? != 1 {
            return Err(std::io::Error::other("KVM lacks KVM_CAP_SIGNAL_MSI"));
        }
        if unsafe { kvm_check_extension(&vm_fd, KVM_CAP_SPLIT_IRQCHIP) }? <= 0 {
            return Err(std::io::Error::other("KVM lacks KVM_CAP_SPLIT_IRQCHIP"));
        }

        let split_cap = KvmEnableCap {
            cap: KVM_CAP_SPLIT_IRQCHIP as u32,
            flags: 0,
            args: [24, 0, 0, 0],
            pad: [0; 64],
        };
        unsafe { kvm_enable_cap(&vm_fd, &split_cap) }?;

        if let Ok(emul_flags) =
            unsafe { kvm_check_extension(&vm_fd, KVM_CAP_EXIT_ON_EMULATION_FAILURE) }
            && emul_flags > 0
        {
            let emul_cap = KvmEnableCap {
                cap: KVM_CAP_EXIT_ON_EMULATION_FAILURE as u32,
                flags: 0,
                args: [
                    (emul_flags as u64) & KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES,
                    0,
                    0,
                    0,
                ],
                pad: [0; 64],
            };
            let _ = unsafe { kvm_enable_cap(&vm_fd, &emul_cap) };
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_tss_addr(&vm_fd, 0xf000_0000) }?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_identity_map_addr(&vm_fd, &0xf000_3000) }?;

        spawn_i2c_listener(vm_fd.clone(), bridge.clone(), doorbells.clone());

        Ok(Self {
            kvm_fd,
            vm_fd,
            vcpu_mmap_size,
            sync_regs_cap,
            bridge,
            doorbells,
            vcpus: RwLock::new([const { None }; MAX_VCPUS]),
            mem_objs: RwLock::new([const { None }; MAX_MEM_OBJS]),
            memslots: Mutex::new([None; MAX_RAM_SLOTS]),
        })
    }

    pub fn bridge(&self) -> Arc<SharedCoreBridge> {
        self.bridge.clone()
    }

    fn get_or_create_vcpu(&self, id: VcpuId) -> HvResult<Arc<KvmVcpuSlot>> {
        let idx = id as usize;
        if idx >= MAX_VCPUS {
            return Err(HvError::InvalidParam);
        }
        if let Some(slot) = self.vcpus.read()[idx].clone() {
            return Ok(slot);
        }

        let mut vcpus = self.vcpus.write();
        if let Some(slot) = vcpus[idx].clone() {
            return Ok(slot);
        }

        let raw_vcpu_fd = unsafe { kvm_create_vcpu(&self.vm_fd, id) }.map_err(io_to_hv_err)?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_vcpu_fd) };
        let kvm_run = unsafe { KvmRunBlock::new(raw_vcpu_fd, self.vcpu_mmap_size) }?;
        let mut kvm_vcpu = KvmVcpu {
            kvm_run,
            fd,
            sync_regs_cap: self.sync_regs_cap,
            sync_regs_valid: false,
        };
        let immediate_exit = kvm_vcpu.immediate_exit_ptr();
        let slot = Arc::new(KvmVcpuSlot {
            vcpu: Mutex::new(kvm_vcpu),
            immediate_exit,
            runner_tid: AtomicU64::new(0),
        });
        vcpus[idx] = Some(slot.clone());
        Ok(slot)
    }
}

impl VmmHostCore for KvmCoreHost {
    fn caps(&self) -> HostCaps {
        HostCaps::DECODED_MMIO | HostCaps::DOORBELLS
    }

    fn supported_cpuids(&self, dst: &mut [RawCpuid]) -> HvResult<usize> {
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: KVM_MAX_CPUID_ENTRIES as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        unsafe { kvm_get_supported_cpuid(&self.kvm_fd, &mut kvm_cpuid2) }.map_err(io_to_hv_err)?;
        let total = (kvm_cpuid2.nent as usize).min(KVM_MAX_CPUID_ENTRIES);
        let count = total.min(dst.len());
        for (src, out) in kvm_cpuid2.entries[..count].iter().zip(dst[..count].iter_mut()) {
            *out = RawCpuid {
                func: src.function,
                has_index: u32::from(src.flags.contains(KvmCpuid2Flag::SIGNIFCANT_INDEX)),
                index: src.index,
                eax: src.eax,
                ebx: src.ebx,
                ecx: src.ecx,
                edx: src.edx,
            };
        }
        Ok(count)
    }

    fn vcpu_configure(&self, vcpu: VcpuId, cpuids: &[RawCpuid]) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        slot.vcpu.lock().configure_cpuids(cpuids)
    }

    fn vcpu_get_regs(&self, vcpu: VcpuId, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        slot.vcpu.lock().get_regs_batch(ids, out)
    }

    fn vcpu_set_regs(&self, vcpu: VcpuId, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        slot.vcpu.lock().set_regs_batch(regs)
    }

    fn vcpu_kick(&self, vcpu: VcpuId) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        unsafe { (*slot.immediate_exit).store(1, Ordering::SeqCst) };
        let tid = slot.runner_tid.load(Ordering::Acquire);
        if tid != 0 {
            let rc = unsafe { libc::pthread_kill(tid as libc::pthread_t, SIGRTMIN()) };
            if rc != 0 && rc != libc::ESRCH {
                return Err(HvError::HardwareFault);
            }
        }
        Ok(())
    }

    fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
        let (addr, shm_offset, len) = self.bridge.alloc_shared_ram(size)?;
        let mut objs = self.mem_objs.write();
        let Some(id) = objs.iter().position(Option::is_none) else {
            self.bridge.free_shared_ram(shm_offset, len);
            return Err(HvError::NoMemory);
        };
        objs[id] = Some(KvmMemObj {
            addr,
            shm_offset,
            len,
        });
        Ok(id as MemObjId)
    }

    fn mem_free(&self, obj: MemObjId) -> HvResult<()> {
        let idx = obj as usize;
        if idx >= MAX_MEM_OBJS {
            return Err(HvError::InvalidParam);
        }
        let Some(mem_obj) = self.mem_objs.write()[idx].take() else {
            return Err(HvError::InvalidParam);
        };
        self.bridge.free_shared_ram(mem_obj.shm_offset, mem_obj.len);
        Ok(())
    }

    fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()> {
        let idx = obj as usize;
        let objs = self.mem_objs.read();
        let Some(mem_obj) = objs.get(idx).and_then(Option::as_ref) else {
            return Err(HvError::InvalidParam);
        };
        let end = offset
            .checked_add(dst.len() as u64)
            .ok_or(HvError::InvalidParam)?;
        if end > mem_obj.len {
            return Err(HvError::InvalidParam);
        }
        let src = unsafe {
            std::slice::from_raw_parts(
                (mem_obj.addr.as_ptr() as *const u8).add(offset as usize),
                dst.len(),
            )
        };
        dst.copy_from_slice(src);
        Ok(())
    }

    fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()> {
        let idx = obj as usize;
        let objs = self.mem_objs.read();
        let Some(mem_obj) = objs.get(idx).and_then(Option::as_ref) else {
            return Err(HvError::InvalidParam);
        };
        let end = offset
            .checked_add(src.len() as u64)
            .ok_or(HvError::InvalidParam)?;
        if end > mem_obj.len {
            return Err(HvError::InvalidParam);
        }
        let dst = unsafe {
            std::slice::from_raw_parts_mut(
                (mem_obj.addr.as_ptr() as *mut u8).add(offset as usize),
                src.len(),
            )
        };
        dst.copy_from_slice(src);
        Ok(())
    }

    fn gpa_map(
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
        if !prot.contains(MemProt::READ) || !prot.contains(MemProt::EXEC) {
            return Err(HvError::Unsupported);
        }
        let gpa_end = gpa.checked_add(size).ok_or(HvError::InvalidParam)?;

        let (hva, shm_offset) = {
            let objs = self.mem_objs.read();
            let Some(mem_obj) = objs.get(obj as usize).and_then(Option::as_ref) else {
                return Err(HvError::InvalidParam);
            };
            let end = offset.checked_add(size).ok_or(HvError::InvalidParam)?;
            if end > mem_obj.len {
                return Err(HvError::InvalidParam);
            }
            let hva = (mem_obj.addr.as_ptr() as usize as u64) + offset;
            (hva, mem_obj.shm_offset + offset)
        };

        let mut flags = KvmMemFlag::empty();
        if !prot.contains(MemProt::WRITE) {
            flags |= KvmMemFlag::READONLY;
        }
        if prot.contains(MemProt::LOG_DIRTY) {
            flags |= KvmMemFlag::LOG_DIRTY_PAGES;
        }

        let mut slots = self.memslots.lock();
        for existing in slots.iter().flatten() {
            let ex_end = existing.gpa + existing.size;
            if gpa < ex_end && existing.gpa < gpa_end {
                return Err(HvError::InvalidParam);
            }
        }
        let slot_idx = slots
            .iter()
            .position(Option::is_none)
            .ok_or(HvError::NoMemory)?;

        let region = KvmUserspaceMemoryRegion {
            slot: slot_idx as u32,
            flags,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: hva,
        };
        unsafe { kvm_set_user_memory_region(&self.vm_fd, &region) }.map_err(io_to_hv_err)?;
        slots[slot_idx] = Some(KvmSlotMapping { gpa, size });

        let shm = self.bridge.shm;
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

        Ok(())
    }

    fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()> {
        let mut slots = self.memslots.lock();
        let slot_idx = slots
            .iter()
            .position(|s| matches!(s, Some(m) if m.gpa == gpa && m.size == size))
            .ok_or(HvError::InvalidParam)?;

        let region = KvmUserspaceMemoryRegion {
            slot: slot_idx as u32,
            flags: KvmMemFlag::empty(),
            guest_phys_addr: gpa,
            memory_size: 0,
            userspace_addr: 0,
        };
        unsafe { kvm_set_user_memory_region(&self.vm_fd, &region) }.map_err(io_to_hv_err)?;
        slots[slot_idx] = None;

        let shm = self.bridge.shm;
        let lock = unsafe { &(*shm).ram_slots_lock };
        spin_lock(lock);
        unsafe {
            (*shm).ram_slots[slot_idx].active = 0;
        }
        spin_unlock(lock);

        Ok(())
    }

    fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()> {
        let kvm_msi = KvmMsi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            ..Default::default()
        };
        unsafe { kvm_signal_msi(&self.vm_fd, &kvm_msi) }.map_err(io_to_hv_err)?;
        Ok(())
    }

    fn set_gsi_level(&self, _gsi: u32, _active: bool) -> HvResult<()> {
        Err(HvError::Unsupported)
    }

    fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()> {
        if !matches!(spec.size, 1 | 2 | 4 | 8) {
            return Err(HvError::InvalidParam);
        }
        let raw_fd =
            ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) }).map_err(io_to_hv_err)?;
        let evt_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw_fd) });

        let mut flags = KvmIoEventFdFlag::empty();
        if spec.space == IoSpace::Pio {
            flags |= KvmIoEventFdFlag::PIO;
        }
        if spec.datamatch.is_some() {
            flags |= KvmIoEventFdFlag::DATA_MATCH;
        }
        let req = KvmIoEventFd {
            datamatch: spec.datamatch.unwrap_or(0),
            addr: spec.addr,
            len: spec.size as u32,
            fd: evt_fd.as_raw_fd(),
            flags,
            pad: [0; 36],
        };
        unsafe { kvm_ioeventfd(&self.vm_fd, &req) }.map_err(io_to_hv_err)?;

        self.doorbells.entries.lock().push(KvmDoorbellEntry {
            space: spec.space,
            addr: spec.addr,
            size: spec.size,
            datamatch: spec.datamatch,
            dev_id: spec.dev_id,
            queue_idx: spec.queue_idx,
            evt_fd,
        });
        self.doorbells.wake();
        Ok(())
    }

    fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()> {
        let mut removed = Vec::new();
        {
            let mut entries = self.doorbells.entries.lock();
            let mut i = 0;
            while i < entries.len() {
                if entries[i].space == space && entries[i].addr == addr && entries[i].size == size {
                    removed.push(entries.swap_remove(i));
                } else {
                    i += 1;
                }
            }
        }
        if removed.is_empty() {
            return Ok(());
        }
        for db in &removed {
            let mut flags = KvmIoEventFdFlag::DEASSIGN;
            if db.space == IoSpace::Pio {
                flags |= KvmIoEventFdFlag::PIO;
            }
            if db.datamatch.is_some() {
                flags |= KvmIoEventFdFlag::DATA_MATCH;
            }
            let req = KvmIoEventFd {
                datamatch: db.datamatch.unwrap_or(0),
                addr: db.addr,
                len: db.size as u32,
                fd: db.evt_fd.as_raw_fd(),
                flags,
                pad: [0; 36],
            };
            let _ = unsafe { kvm_ioeventfd(&self.vm_fd, &req) };
        }
        self.doorbells.wake();
        Ok(())
    }
}

impl crate::wasm_host::VmmHostRunner for KvmCoreHost {
    fn enter_guest(&self, vcpu: VcpuId, comm: &mut VcpuCommPage) -> HvResult<()> {
        let slot = self.get_or_create_vcpu(vcpu)?;
        slot.runner_tid
            .store(unsafe { libc::pthread_self() } as u64, Ordering::Release);
        let mut guard = slot.vcpu.lock();
        guard.run(comm)
    }

    fn wait_bridge_rx(&self) -> bool {
        self.bridge.wait_ctrl_rx()
    }

    fn wake_bridge_rx(&self) {
        self.bridge.wake_ctrl_rx();
    }
}
