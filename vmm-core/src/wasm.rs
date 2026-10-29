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

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::host::abi::{
    CoreToIoEntry, IoToCoreEntry, RawCpuid, RawDoorbellSpec, RawRegEntry, ShmBootInfo,
    ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig, VcpuCommPage,
};
use crate::host::{
    DoorbellSpec, HostCaps, HvError, HvResult, IoSpace, MemObjId, MemProt, PayloadKind, RegId,
    RegVal, VcpuId, VmmCoreBridge, VmmHostCore,
};
use crate::hw::Board;

#[link(wasm_import_module = "vmm")]
unsafe extern "C" {
    fn hv_caps() -> u32;
    fn hv_supported_cpuids(dst_ptr: u32, max_entries: u32) -> i32;

    fn vcpu_configure(vcpu: u32, cpuids_ptr: u32, cpuids_len: u32) -> i32;
    fn vcpu_get_regs(vcpu: u32, regs_ptr: u32, regs_len: u32) -> i32;
    fn vcpu_set_regs(vcpu: u32, regs_ptr: u32, regs_len: u32) -> i32;
    fn vcpu_kick(vcpu: u32) -> i32;

    fn mem_alloc(size: u64) -> i32;
    fn mem_free(obj: u32) -> i32;
    fn mem_read(obj: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn mem_write(obj: u32, offset: u64, src_ptr: u32, len: u32) -> i32;
    fn gpa_map(gpa: u64, size: u64, obj: u32, offset: u64, prot: u32) -> i32;
    fn gpa_unmap(gpa: u64, size: u64) -> i32;

    fn inject_msi(addr: u64, data: u32) -> i32;
    fn set_gsi_level(gsi: u32, active: u32) -> i32;
    fn register_doorbell(spec_ptr: u32) -> i32;
    fn unregister_doorbell(space: u32, addr: u64, size: u32) -> i32;
}

#[link(wasm_import_module = "vmm_bridge")]
unsafe extern "C" {
    fn bridge_boot_info(boot_info_out_ptr: u32, devs_out_ptr: u32, max_devs: u32) -> i32;
    fn bridge_read_payload(kind: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn bridge_configure_queues(dev: u32, queues_ptr: u32, num_queues: u32) -> i32;
    fn bridge_update_irq_route(dev: u32, routing_ptr: u32) -> i32;
    fn bridge_send_cmd(entry_ptr: u32) -> i32;
    fn bridge_recv_cmd(entry_out_ptr: u32) -> i32;
}

#[inline]
fn check_rc(rc: i32) -> HvResult<u32> {
    if rc < 0 {
        Err(HvError::from_code(rc))
    } else {
        Ok(rc as u32)
    }
}

#[inline]
fn check_unit(rc: i32) -> HvResult<()> {
    check_rc(rc).map(|_| ())
}

#[derive(Debug, Default, Copy, Clone)]
pub struct WasmHost;

impl VmmHostCore for WasmHost {
    fn caps(&self) -> HostCaps {
        HostCaps::from_bits_retain(unsafe { hv_caps() })
    }

    fn supported_cpuids(&self, dst: &mut [RawCpuid]) -> HvResult<usize> {
        let n = check_rc(unsafe {
            hv_supported_cpuids(dst.as_mut_ptr() as u32, dst.len() as u32)
        })?;
        Ok(n as usize)
    }

    fn vcpu_configure(&self, vcpu: VcpuId, cpuids: &[RawCpuid]) -> HvResult<()> {
        check_unit(unsafe {
            vcpu_configure(vcpu, cpuids.as_ptr() as u32, cpuids.len() as u32)
        })
    }

    fn vcpu_get_regs(&self, vcpu: VcpuId, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        if ids.len() != out.len() {
            return Err(HvError::InvalidParam);
        }
        const CHUNK: usize = 32;
        let mut raw = [RawRegEntry::default(); CHUNK];
        let mut offset = 0;
        while offset < ids.len() {
            let n = (ids.len() - offset).min(CHUNK);
            for i in 0..n {
                raw[i] = RawRegEntry::from_id(ids[offset + i]);
            }
            check_unit(unsafe { vcpu_get_regs(vcpu, raw.as_mut_ptr() as u32, n as u32) })?;
            for i in 0..n {
                out[offset + i] = raw[i].to_val()?;
            }
            offset += n;
        }
        Ok(())
    }

    fn vcpu_set_regs(&self, vcpu: VcpuId, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        const CHUNK: usize = 32;
        let mut raw = [RawRegEntry::default(); CHUNK];
        for chunk in regs.chunks(CHUNK) {
            for (i, &(id, val)) in chunk.iter().enumerate() {
                raw[i] = RawRegEntry::from_pair(id, val);
            }
            check_unit(unsafe { vcpu_set_regs(vcpu, raw.as_ptr() as u32, chunk.len() as u32) })?;
        }
        Ok(())
    }

    fn vcpu_kick(&self, vcpu: VcpuId) -> HvResult<()> {
        check_unit(unsafe { vcpu_kick(vcpu) })
    }

    fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
        check_rc(unsafe { mem_alloc(size) })
    }

    fn mem_free(&self, obj: MemObjId) -> HvResult<()> {
        check_unit(unsafe { mem_free(obj) })
    }

    fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()> {
        check_unit(unsafe { mem_read(obj, offset, dst.as_mut_ptr() as u32, dst.len() as u32) })
    }

    fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()> {
        check_unit(unsafe { mem_write(obj, offset, src.as_ptr() as u32, src.len() as u32) })
    }

    fn gpa_map(
        &self,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()> {
        check_unit(unsafe { gpa_map(gpa, size, obj, offset, prot.bits()) })
    }

    fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()> {
        check_unit(unsafe { gpa_unmap(gpa, size) })
    }

    fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()> {
        check_unit(unsafe { inject_msi(addr, data) })
    }

    fn set_gsi_level(&self, gsi: u32, active: bool) -> HvResult<()> {
        check_unit(unsafe { set_gsi_level(gsi, u32::from(active)) })
    }

    fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()> {
        let raw = RawDoorbellSpec::from(spec);
        check_unit(unsafe { register_doorbell(&raw as *const RawDoorbellSpec as u32) })
    }

    fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()> {
        check_unit(unsafe { unregister_doorbell(space as u32, addr, size as u32) })
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct WasmBridge;

impl VmmCoreBridge for WasmBridge {
    fn boot_info(
        &self,
        out_info: &mut ShmBootInfo,
        out_devs: &mut [ShmVirtioDeviceSpec],
    ) -> HvResult<usize> {
        let n = check_rc(unsafe {
            bridge_boot_info(
                out_info as *mut ShmBootInfo as u32,
                out_devs.as_mut_ptr() as u32,
                out_devs.len() as u32,
            )
        })?;
        Ok(n as usize)
    }

    fn read_payload(&self, kind: PayloadKind, offset: u64, dst: &mut [u8]) -> HvResult<usize> {
        let n = check_rc(unsafe {
            bridge_read_payload(kind as u32, offset, dst.as_mut_ptr() as u32, dst.len() as u32)
        })?;
        Ok(n as usize)
    }

    fn configure_device_queues(
        &self,
        dev: u32,
        queues: &[ShmVirtioQueueConfig],
    ) -> HvResult<()> {
        check_unit(unsafe {
            bridge_configure_queues(dev, queues.as_ptr() as u32, queues.len() as u32)
        })
    }

    fn update_irq_route(&self, dev: u32, routing: &ShmDeviceMsixRouting) -> HvResult<()> {
        check_unit(unsafe {
            bridge_update_irq_route(dev, routing as *const ShmDeviceMsixRouting as u32)
        })
    }

    fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()> {
        check_unit(unsafe { bridge_send_cmd(entry as *const CoreToIoEntry as u32) })
    }

    fn recv_io_cmd(&self, out: &mut IoToCoreEntry) -> HvResult<bool> {
        let rc = check_rc(unsafe { bridge_recv_cmd(out as *mut IoToCoreEntry as u32) })?;
        Ok(rc != 0)
    }
}

// ============================================================================
// Host-Driven Wasm Exports (`vmm-core` -> Host)
// ============================================================================

static GLOBAL_BOARD: AtomicPtr<Board> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn global_board() -> Option<&'static Board> {
    let ptr = GLOBAL_BOARD.load(Ordering::Acquire);
    unsafe { ptr.as_ref() }
}

fn hw_err_to_code(e: &crate::hw::Error) -> i32 {
    match e {
        crate::hw::Error::Hv(h)
        | crate::hw::Error::Memory(crate::mem::Error::Hv(h))
        | crate::hw::Error::Loader(crate::loader::Error::Hv(h))
        | crate::hw::Error::Virtio(crate::virtio::Error::Hv(h)) => h.code(),
        crate::hw::Error::MemoryTooSmall
        | crate::hw::Error::Memory(crate::mem::Error::CanotAllocate) => HvError::NoMemory.code(),
        _ => HvError::InvalidParam.code(),
    }
}

fn vm_err_to_code(e: &crate::vm::Error) -> i32 {
    match e {
        crate::vm::Error::Hv(h) => h.code(),
        crate::vm::Error::Board(b) => hw_err_to_code(b),
        crate::vm::Error::Memory(crate::mem::Error::Hv(h))
        | crate::vm::Error::Loader(crate::loader::Error::Hv(h))
        | crate::vm::Error::Virtio(crate::virtio::Error::Hv(h)) => h.code(),
        _ => HvError::InvalidParam.code(),
    }
}

/// Initialize the VM board, allocate & map Guest RAM, load kernel/ACPI, configure BSP/AP
/// initial states, and return the Wasm linear memory offset of `[VcpuCommPage; num_cpus]`
/// (or a negative [`HvError`] code on failure).
#[unsafe(no_mangle)]
pub extern "C" fn vmm_init() -> i32 {
    let hv = Arc::new(WasmHost);
    let bridge = Arc::new(WasmBridge);
    let vm = match crate::init_machine(hv, bridge) {
        Ok(vm) => vm,
        Err(e) => return vm_err_to_code(&e),
    };
    let comm_ptr = vm.board.comm_pages_ptr() as usize;
    let raw = Arc::into_raw(vm.board) as *mut Board;
    let prev = GLOBAL_BOARD.swap(raw, Ordering::AcqRel);
    if !prev.is_null() {
        unsafe { drop(Arc::from_raw(prev)) };
    }
    comm_ptr as i32
}

/// Return the number of configured guest vCPUs (`0` if `vmm_init` has not completed).
#[unsafe(no_mangle)]
pub extern "C" fn vmm_num_cpus() -> u32 {
    global_board().map_or(0, |b| b.config.num_cpu)
}

/// Return the 16-byte-aligned disjoint Wasm linear memory stack top for worker `slot_id`
/// (`0..num_cpus` for vCPUs, `num_cpus` for the bridge RX worker), or `0` if out of range.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_stack_top(slot_id: u32) -> u32 {
    global_board()
        .and_then(|b| b.worker_stack_top(slot_id))
        .unwrap_or(0) as u32
}

/// One-time per-vCPU binding hook called on worker `Instance[vcpu_id]` after its
/// `__stack_pointer` global has been set to `stack_top`.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_bind_vcpu(vcpu_id: u32, stack_top: u32) {
    let Some(board) = global_board() else {
        core::arch::wasm32::unreachable();
    };
    if vcpu_id >= board.config.num_cpu || stack_top == 0 || (stack_top & 15) != 0 {
        core::arch::wasm32::unreachable();
    }
    let comm = unsafe { board.comm_page_mut(vcpu_id) };
    *comm = VcpuCommPage::default();
}

/// Handle one synchronous slow-path VM exit for `vcpu_id` via `comm_page[vcpu_id]`.
/// Strictly non-blocking; returns [`crate::host::VmAction`] (`0` = Continue, `1` = Shutdown,
/// `2` = Reboot) or a negative [`HvError`] code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_on_vcpu_exit(vcpu_id: u32) -> i32 {
    let Some(board) = global_board() else {
        return HvError::InvalidParam.code();
    };
    match board.on_vcpu_exit(vcpu_id) {
        Ok(action) => action as i32,
        Err(e) => hw_err_to_code(&e),
    }
}

/// Drain pending control messages from `vmm-io` (`SerialRx`, `RequestShutdown`).
/// Strictly non-blocking; returns [`crate::host::VmAction`] (`0` = Continue, `1` = Shutdown)
/// or a negative [`HvError`] code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_on_bridge_rx() -> i32 {
    let Some(board) = global_board() else {
        return HvError::InvalidParam.code();
    };
    match board.on_bridge_rx() {
        Ok(action) => action as i32,
        Err(e) => hw_err_to_code(&e),
    }
}

/// Reset all hardware and Guest RAM/payload state for a guest reboot cycle.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_reset() -> i32 {
    let Some(board) = global_board() else {
        return HvError::InvalidParam.code();
    };
    match board.reset_vm() {
        Ok(()) => 0,
        Err(e) => hw_err_to_code(&e),
    }
}

// Keep `.data` > 128 bytes (256B) so Cranelift lowers passive `memory.init` to a host
// libcall instead of emitting inline 128-bit `%xmm` stores on Ring-0 targets.
#[used]
static mut DATA_PAD: [u64; 32] = [1; 32];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vmm_memset(mut dst: *mut u8, val: u32, mut n: usize) {
    if n == 0 {
        return;
    }
    let byte = (val & 0xff) as u8;
    let word = (byte as u64).wrapping_mul(0x0101_0101_0101_0101);
    while core::hint::black_box(n) >= 8 {
        unsafe {
            core::ptr::write_unaligned(dst as *mut u64, word);
            dst = dst.add(8);
        }
        n -= 8;
    }
    while core::hint::black_box(n) > 0 {
        unsafe {
            *dst = byte;
            dst = dst.add(1);
        }
        n -= 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vmm_memcpy(mut dst: *mut u8, mut src: *const u8, mut n: usize) {
    if n == usize::MAX {
        unsafe {
            let v = core::ptr::read_volatile(&raw const DATA_PAD[0]);
            core::ptr::write_volatile(&raw mut DATA_PAD[0], v);
        }
    }
    if dst as usize == src as usize || n == 0 {
        return;
    }
    if (dst as usize) < (src as usize) || (dst as usize) >= (src as usize).wrapping_add(n) {
        while core::hint::black_box(n) >= 8 {
            unsafe {
                let v = core::ptr::read_unaligned(src as *const u64);
                core::ptr::write_unaligned(dst as *mut u64, v);
                src = src.add(8);
                dst = dst.add(8);
            }
            n -= 8;
        }
        while core::hint::black_box(n) > 0 {
            unsafe {
                *dst = *src;
                src = src.add(1);
                dst = dst.add(1);
            }
            n -= 1;
        }
    } else {
        unsafe {
            src = src.add(n);
            dst = dst.add(n);
        }
        while core::hint::black_box(n) >= 8 {
            n -= 8;
            unsafe {
                src = src.sub(8);
                dst = dst.sub(8);
                let v = core::ptr::read_unaligned(src as *const u64);
                core::ptr::write_unaligned(dst as *mut u64, v);
            }
        }
        while core::hint::black_box(n) > 0 {
            n -= 1;
            unsafe {
                src = src.sub(1);
                dst = dst.sub(1);
                *dst = *src;
            }
        }
    }
}
