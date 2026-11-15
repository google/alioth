// Ring-0 Airlock VMM host (`SysObj::create("vmm:...")`, `SysCpu::wake`, `SysObj::put`).

pub mod arch;
pub mod doorbell;
pub mod host_impl;
pub mod iommu;
pub mod lapic;
pub mod pci_cfg;
pub mod pci_host;
pub mod pvclock;
pub mod stage2;
pub mod vcpu_thread;
pub mod verify_no_fp;
pub mod virtio_iommu;
pub mod wasm_runtime;

/// Early Ring-0 initialization invoked on BSP before PID 2 (`sys-io`) starts:
/// parses `pci_passthrough=...` and brings up `virtio-iommu` if present.
pub fn init_early() {
    let cmdline = crate::config::get().cmdline.as_slice();
    pci_cfg::init_from_cmdline(cmdline);
    virtio_iommu::init_early();
}

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::Ordering;

use moto_sys::caps::CAP_VMM;
use moto_sys::{ErrorCode, SysHandle};
use vmm_core::host::abi::{
    spin_lock, spin_unlock, BridgeShm, ShmMsiEntry, IO_MSG_REQUEST_SHUTDOWN, IO_MSG_SERIAL_RX,
    IO_MSG_VIRTIO_IRQ, IRQ_KIND_CONFIG, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS,
};
use vmm_core::host::{VmAction, VmmHostCore};

use crate::mm::user::{PinnedUserPage, UserAddressSpace};
use crate::mm::virt::{vmem_map_phys_pages_rw, vmem_unmap_phys_pages};
use crate::mm::{
    align_up, AllocationFailure, MemorySegment, PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2,
};
use crate::uspace::process::Thread;
use crate::uspace::sysobject::object_from_sysobject;
use crate::uspace::SysObject;

use host_impl::{MotorCoreBridge, MotorHvCore};
use vcpu_thread::VcpuRunner;
use wasm_runtime::{CwasmCodeBacking, MotorWasmRuntime, RxWasmWorker};

struct ShmKernelMapping {
    seg: MemorySegment,
    phys_addrs: Vec<u64>,
    _pinned_pages: Vec<PinnedUserPage>,
}

impl ShmKernelMapping {
    fn map_from_user(space: &UserAddressSpace, user_addr: u64) -> Result<Self, AllocationFailure> {
        if (user_addr & (PAGE_SIZE_SMALL - 1)) != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT.into());
        }
        let shm_bytes = align_up(size_of::<BridgeShm>() as u64, PAGE_SIZE_SMALL);
        let num_pages = (shm_bytes >> PAGE_SIZE_SMALL_LOG2) as usize;
        let mut pinned_pages = Vec::with_capacity(num_pages);
        let mut phys_addrs = Vec::with_capacity(num_pages);
        for i in 0..num_pages {
            let page_vaddr = user_addr
                .checked_add((i as u64) << PAGE_SIZE_SMALL_LOG2)
                .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
            let pinned = space.pin_or_fault_user_page(page_vaddr, true)?;
            phys_addrs.push(pinned.phys_addr());
            pinned_pages.push(pinned);
        }
        let seg = vmem_map_phys_pages_rw(&phys_addrs)?;
        Ok(Self {
            seg,
            phys_addrs,
            _pinned_pages: pinned_pages,
        })
    }

    fn ptr(&self) -> u64 {
        self.seg.start
    }
}

impl Drop for ShmKernelMapping {
    fn drop(&mut self) {
        vmem_unmap_phys_pages(self.seg, &self.phys_addrs);
    }
}

/// Top-level Ring-0 VM partition owned by the `vmm:...` `SysObject`.
/// Field order ensures `wasm` and `hv` drop before `_shm_mapping` unmaps `BridgeShm`.
pub struct VmInstance {
    pub wasm: Arc<MotorWasmRuntime<MotorHvCore, MotorCoreBridge>>,
    pub bridge: Arc<MotorCoreBridge>,
    pub hv: Arc<MotorHvCore>,
    _shm_mapping: ShmKernelMapping,
}

fn parse_u64_arg(s: &str) -> Result<u64, AllocationFailure> {
    let val = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    val.map_err(|_| moto_rt::E_INVALID_ARGUMENT.into())
}

fn pin_user_range(
    space: &UserAddressSpace,
    base_addr: u64,
    byte_len: u64,
    writable: bool,
) -> Result<Vec<PinnedUserPage>, AllocationFailure> {
    if byte_len == 0 || (base_addr & (PAGE_SIZE_SMALL - 1)) != 0 {
        return Err(moto_rt::E_INVALID_ARGUMENT.into());
    }
    let aligned = align_up(byte_len, PAGE_SIZE_SMALL);
    let num_pages = (aligned >> PAGE_SIZE_SMALL_LOG2) as usize;
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(num_pages)
        .map_err(|_| AllocationFailure::Code(moto_rt::E_OUT_OF_MEMORY))?;
    for i in 0..num_pages {
        let vaddr = base_addr
            .checked_add((i as u64) << PAGE_SIZE_SMALL_LOG2)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        pages.push(space.pin_or_fault_user_page(vaddr, writable)?);
    }
    Ok(pages)
}

/// Handles `SysObj::create(SysHandle::KERNEL, 0, "vmm:...")`.
pub(crate) fn create_vm(
    thread: &Thread,
    parent: SysHandle,
    args: &str,
) -> Result<SysHandle, AllocationFailure> {
    if parent != SysHandle::KERNEL {
        return Err(moto_rt::E_INVALID_ARGUMENT.into());
    }
    if (thread.capabilities() & CAP_VMM) == 0 {
        return Err(moto_rt::E_NOT_ALLOWED.into());
    }

    let mut shm_addr = None;
    let mut ram_addr = None;
    let mut ram_size = None;
    let mut payload_addr = None;
    let mut payload_size = None;
    let mut cwasm_addr = None;
    let mut cwasm_size = None;

    for part in args.split(';') {
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            return Err(moto_rt::E_INVALID_ARGUMENT.into());
        };
        let num = parse_u64_arg(v)?;
        match k {
            "shm_addr" => shm_addr = Some(num),
            "ram_addr" => ram_addr = Some(num),
            "ram_size" => ram_size = Some(num),
            "payload_addr" => payload_addr = Some(num),
            "payload_size" => payload_size = Some(num),
            "cwasm_addr" => cwasm_addr = Some(num),
            "cwasm_size" => cwasm_size = Some(num),
            _ => return Err(moto_rt::E_INVALID_ARGUMENT.into()),
        }
    }

    let (
        Some(shm_addr),
        Some(ram_addr),
        Some(ram_size),
        Some(payload_addr),
        Some(payload_size),
        Some(cwasm_addr),
        Some(cwasm_size),
    ) = (
        shm_addr,
        ram_addr,
        ram_size,
        payload_addr,
        payload_size,
        cwasm_addr,
        cwasm_size,
    )
    else {
        return Err(moto_rt::E_INVALID_ARGUMENT.into());
    };

    if (ram_size & (PAGE_SIZE_SMALL - 1)) != 0
        || !((4 << 20)..=(2 << 30)).contains(&ram_size)
        || cwasm_size > (16 << 20)
    {
        return Err(moto_rt::E_INVALID_ARGUMENT.into());
    }

    let owner = thread.owner();
    let space = owner.address_space();

    // Copy `.cwasm` into private kernel pages BEFORE running `validate_cwasm_no_fp` so
    // Ring 3 cannot mutate machine code after validation (zero TOCTOU window).
    let code_backing = {
        let cwasm_pages = pin_user_range(space, cwasm_addr, cwasm_size, false)?;
        CwasmCodeBacking::from_pinned_pages(&cwasm_pages, cwasm_size as usize).map_err(|err| {
            log::error!("create_vm: .cwasm load failed: {err}");
            AllocationFailure::Code(moto_rt::E_INVALID_ARGUMENT)
        })?
    };

    let shm_mapping = ShmKernelMapping::map_from_user(space, shm_addr)?;
    let ram_pages = pin_user_range(space, ram_addr, ram_size, true)?;
    let payload_pages = pin_user_range(space, payload_addr, payload_size, false)?;

    let hv = Arc::new(
        MotorHvCore::new(ram_pages, shm_mapping.ptr()).map_err(|err| {
            log::error!("create_vm: MotorHvCore::new failed: {err:?}");
            AllocationFailure::Code(moto_rt::E_NOT_ALLOWED)
        })?,
    );
    hv.pci.set_self_hv(&hv);
    let bridge = Arc::new(MotorCoreBridge::new(
        shm_mapping.ptr(),
        payload_pages,
        payload_size,
        hv.clone(),
    ));

    let (wasm, vcpu_workers) =
        MotorWasmRuntime::instantiate(code_backing, hv.clone(), bridge.clone()).map_err(|err| {
            log::error!("create_vm: MotorWasmRuntime::instantiate failed: {err}");
            AllocationFailure::Code(moto_rt::E_INVALID_ARGUMENT)
        })?;

    let vm_instance = Arc::new(VmInstance {
        wasm: wasm.clone(),
        bridge: bridge.clone(),
        hv: hv.clone(),
        _shm_mapping: shm_mapping,
    });

    let sys_obj = SysObject::new_owned(
        Arc::new(format!("vmm:{}", owner.pid().as_u64())),
        vm_instance,
        Arc::downgrade(&owner),
    );
    hv.set_vm_obj(&sys_obj);

    for (idx, worker) in vcpu_workers.into_iter().enumerate() {
        let vcpu_id = idx as u32;
        let Some(slot) = hv.get_vcpu(vcpu_id) else {
            hv.signal_shutdown();
            return Err(moto_rt::E_INTERNAL_ERROR.into());
        };
        let runner = Arc::new(VcpuRunner::new(
            vcpu_id,
            slot,
            hv.clone(),
            bridge.clone(),
            worker,
            wasm.clone(),
        ));
        let name = format!("vcpu_{vcpu_id}");
        if let Err(err) = owner.spawn_vcpu_thread(runner, &name) {
            hv.signal_shutdown();
            return Err(err);
        }
    }

    Ok(owner.add_object(sys_obj))
}

/// Services `SysCpu::wake(vm_handle)` from Ring-3 `vmm-io-host`: drains `i2c_entries`,
/// injecting MSI-X IRQs directly in Ring 0 (`0` Wasm transitions) and forwarding control
/// messages (`SerialRx`, `RequestShutdown`) to `vmm_on_bridge_rx()`.
pub fn try_wake(sys_obj: &Arc<SysObject>) -> Result<(), ErrorCode> {
    let Some(vm) = object_from_sysobject::<VmInstance>(sys_obj) else {
        return Err(moto_rt::E_BAD_HANDLE);
    };

    let shm = vm.bridge.shm_ptr as usize as *mut BridgeShm;
    let mut has_ctrl = false;

    while let Some(entry) = unsafe { BridgeShm::pop_io_to_core(shm) } {
        match entry.msg_type {
            IO_MSG_VIRTIO_IRQ => {
                let dev = entry.dev as usize;
                if dev < MAX_VIRTIO_DEVS {
                    let lock = unsafe { &(*shm).msix_lock };
                    spin_lock(lock);
                    let msi: ShmMsiEntry = unsafe {
                        let routing = &(*shm).msix_routing[dev];
                        if entry.irq_kind as u32 == IRQ_KIND_CONFIG {
                            routing.config_msi
                        } else if (entry.queue_index as usize) < MAX_QUEUES_PER_DEV {
                            routing.queue_msis[entry.queue_index as usize]
                        } else {
                            ShmMsiEntry::default()
                        }
                    };
                    spin_unlock(lock);

                    if msi.enabled != 0 && msi.addr != 0 {
                        let _ = vm.hv.inject_msi(msi.addr, msi.data);
                    }
                }
            }
            IO_MSG_SERIAL_RX => {
                let len = (entry.queue_index as usize).min(entry.data.len());
                if len > 0 {
                    vm.bridge.push_ctrl_rx(entry);
                    has_ctrl = true;
                }
            }
            IO_MSG_REQUEST_SHUTDOWN => {
                unsafe {
                    (*shm).shutdown_requested.store(1, Ordering::Release);
                }
                vm.bridge.push_ctrl_rx(entry);
                has_ctrl = true;
            }
            _ => {}
        }
    }

    if has_ctrl {
        let mut rx = vm.wasm.rx_worker.lock(line!());
        let RxWasmWorker {
            store,
            on_bridge_rx,
            ..
        } = &mut *rx;
        let res = on_bridge_rx.call(store, ());
        drop(rx);
        match res {
            Ok(rc) if rc == VmAction::Continue as i32 => {}
            Ok(rc) if rc == VmAction::Shutdown as i32 => vm.hv.signal_shutdown(),
            Ok(rc) => {
                log::error!("vmm_on_bridge_rx returned error {rc}");
                vm.hv.signal_shutdown();
            }
            Err(trap) => {
                log::error!("vmm_on_bridge_rx trapped: {trap}");
                vm.hv.signal_shutdown();
            }
        }
    }

    Ok(())
}

/// Triggered when the owning process closes its last `vm_handle` or exits.
pub fn on_drop(sys_obj: &SysObject) {
    if let Some(vm) = sys_obj.owner().downcast_ref::<VmInstance>() {
        vm.hv.pci.teardown_all(&vm.hv.stage2);
        vm.hv.signal_shutdown();
    }
}
