// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod arch;
pub mod doorbell;
pub mod host_impl;
pub mod kapi;
pub mod lapic;
pub mod pci_host;
pub mod pvclock;
pub mod stage2;
pub mod vcpu_thread;
pub mod verify_no_fp;
pub mod wasm_runtime;

use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use vmm_core::host::abi::BridgeShm;

use host_impl::{LinuxCoreBridge, LinuxHvCore};
use kapi::{
    airlock_kapi_kthread_spawn, airlock_kapi_kthread_stop, AirlockCreateVmReq, AirlockKthread,
    EventfdBinding, PinnedUserMem, WaitQueue, AIRLOCK_CAP_NPT, AIRLOCK_CAP_SVM, PAGE_SIZE_4K,
};
use vcpu_thread::{
    on_i2c_eventfd_wakeup, rx_kthread_main, vcpu_kthread_main, RxRouterCtx, VcpuRunner,
};
use wasm_runtime::{CwasmCodeBacking, LinuxWasmRuntime};

const MIN_RAM_BYTES: u64 = 4 << 20;
const MAX_RAM_BYTES: u64 = 64 << 30;
const MAX_CWASM_BYTES: u64 = 16 << 20;

static DETECTED_CAPS: AtomicU32 = AtomicU32::new(0);
static NEXT_VM_ID: AtomicU32 = AtomicU32::new(1);

fn verify_wasmtime_engine_boot() -> Result<(), alloc::string::String> {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_threads(true);
    cfg.shared_memory(true);
    cfg.wasm_simd(false);
    cfg.wasm_relaxed_simd(false);
    cfg.signals_based_traps(false);
    cfg.memory_init_cow(false);
    cfg.memory_guard_size(0);
    cfg.memory_reservation(0);
    unsafe {
        cfg.x86_float_abi_ok(true);
    }
    let _engine =
        wasmtime::Engine::new(&cfg).map_err(|e| format!("Wasmtime Engine::new failed: {e}"))?;
    Ok(())
}

/// Active Ring-0 Airlock VM owned by an `anon_inode` `airlock-vm` file descriptor.
/// Field declaration order matches clean reverse-dependency drop after `stop_workers()` runs.
struct VmInstance {
    i2c_efd: Option<EventfdBinding>,
    vcpu_kthreads: Vec<*mut AirlockKthread>,
    rx_kthread: *mut AirlockKthread,
    vcpu_runners: Vec<Arc<VcpuRunner>>,
    rx_ctx: Option<Arc<RxRouterCtx>>,
    wasm: Option<Arc<LinuxWasmRuntime<LinuxHvCore, LinuxCoreBridge>>>,
    _bridge: Arc<LinuxCoreBridge>,
    hv: Arc<LinuxHvCore>,
}

unsafe impl Send for VmInstance {}
unsafe impl Sync for VmInstance {}

impl VmInstance {
    fn create(req: &AirlockCreateVmReq) -> Result<Box<Self>, i32> {
        let min_shm = ((size_of::<BridgeShm>() as u64) + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1);
        if (req.shm_uaddr & (PAGE_SIZE_4K - 1)) != 0 || req.shm_size < min_shm {
            kerr!(
                "invalid shm range uaddr={:#x} size={:#x} (min {min_shm:#x})",
                req.shm_uaddr,
                req.shm_size
            );
            return Err(-22); // -EINVAL
        }
        if (req.ram_uaddr & (PAGE_SIZE_4K - 1)) != 0
            || (req.ram_size & (PAGE_SIZE_4K - 1)) != 0
            || !(MIN_RAM_BYTES..=MAX_RAM_BYTES).contains(&req.ram_size)
        {
            kerr!(
                "invalid ram range uaddr={:#x} size={:#x}",
                req.ram_uaddr,
                req.ram_size
            );
            return Err(-22);
        }
        if req.payload_size > 0 && (req.payload_uaddr & (PAGE_SIZE_4K - 1)) != 0 {
            kerr!("unaligned payload_uaddr={:#x}", req.payload_uaddr);
            return Err(-22);
        }
        if req.cwasm_size == 0 || req.cwasm_size > MAX_CWASM_BYTES {
            kerr!("invalid cwasm_size={:#x}", req.cwasm_size);
            return Err(-22);
        }

        let shm_mem = PinnedUserMem::pin(req.shm_uaddr, req.shm_size, true, true)?;
        let shm_ptr = shm_mem.kva() as usize;
        let ram_mem = PinnedUserMem::pin(req.ram_uaddr, req.ram_size, true, false)?;
        let payload_mem = if req.payload_size > 0 {
            Some(PinnedUserMem::pin(
                req.payload_uaddr,
                req.payload_size,
                false,
                false,
            )?)
        } else {
            None
        };

        let cwasm_backing = CwasmCodeBacking::from_user(req.cwasm_uaddr, req.cwasm_size as usize)
            .map_err(|e| {
            kerr!("failed loading .cwasm: {e}");
            -22
        })?;

        let rx_wq = Arc::new(WaitQueue::new()?);
        let c2i_efd = EventfdBinding::bind(req.c2i_eventfd, None, null_mut())?;

        let hv = LinuxHvCore::new(ram_mem, shm_ptr, c2i_efd, rx_wq.clone()).map_err(|e| {
            kerr!("LinuxHvCore::new failed: {e:?}");
            -12
        })?;
        let hv = Arc::new(hv);
        let bridge = Arc::new(LinuxCoreBridge::new(shm_mem, payload_mem, hv.clone()));

        let (wasm, vcpu_workers) =
            LinuxWasmRuntime::instantiate(cwasm_backing, hv.clone(), bridge.clone()).map_err(
                |e| {
                    kerr!("LinuxWasmRuntime::instantiate failed: {e}");
                    -22
                },
            )?;

        let num_cpus = wasm.num_cpus;
        let vm_id = NEXT_VM_ID.fetch_add(1, Ordering::Relaxed);

        let rx_ctx = Arc::new(RxRouterCtx {
            hv: hv.clone(),
            bridge: bridge.clone(),
            wasm: wasm.clone(),
            rx_wq,
            rx_pending: AtomicBool::new(false),
        });

        let mut vm = Box::new(Self {
            i2c_efd: None,
            vcpu_kthreads: Vec::with_capacity(num_cpus as usize),
            rx_kthread: null_mut(),
            vcpu_runners: Vec::with_capacity(num_cpus as usize),
            rx_ctx: Some(rx_ctx.clone()),
            wasm: Some(wasm.clone()),
            _bridge: bridge.clone(),
            hv: hv.clone(),
        });

        for (idx, worker) in vcpu_workers.into_iter().enumerate() {
            let vcpu_id = idx as u32;
            let slot = hv.get_or_create_vcpu(vcpu_id).map_err(|_| -12)?;
            let runner = Arc::new(VcpuRunner::new(
                vcpu_id,
                slot,
                hv.clone(),
                bridge.clone(),
                worker,
                wasm.clone(),
            ));
            vm.vcpu_runners.push(runner);
        }

        let rx_name = format!("airlock-rx/{vm_id}");
        let mut rx_kt = null_mut();
        let rc = unsafe {
            airlock_kapi_kthread_spawn(
                rx_kthread_main,
                Arc::as_ptr(&rx_ctx) as *mut c_void,
                rx_name.as_ptr(),
                rx_name.len(),
                &mut rx_kt,
            )
        };
        if rc < 0 {
            kerr!("failed spawning {rx_name}: {rc}");
            return Err(rc);
        }
        vm.rx_kthread = rx_kt;

        let i2c_efd = EventfdBinding::bind(
            req.i2c_eventfd,
            Some(on_i2c_eventfd_wakeup),
            Arc::as_ptr(&rx_ctx) as *mut c_void,
        )?;
        vm.i2c_efd = Some(i2c_efd);

        for (idx, runner) in vm.vcpu_runners.iter().enumerate() {
            let name = format!("airlock-vcpu/{vm_id}-{idx}");
            let mut kt = null_mut();
            let rc = unsafe {
                airlock_kapi_kthread_spawn(
                    vcpu_kthread_main,
                    Arc::as_ptr(runner) as *mut c_void,
                    name.as_ptr(),
                    name.len(),
                    &mut kt,
                )
            };
            if rc < 0 {
                kerr!("failed spawning {name}: {rc}");
                return Err(rc);
            }
            vm.vcpu_kthreads.push(kt);
        }

        // Kick `c2i_eventfd` once in case `vmm_init` queued initial messages.
        hv.wake_c2i();

        kinfo!("created VM #{vm_id} (vcpus={num_cpus}, ram_bytes={:#x})", req.ram_size);
        Ok(vm)
    }

    fn stop_workers(&mut self) {
        self.hv.signal_shutdown();

        // 1. Detach `i2c_eventfd` waitqueue observer before freeing `rx_ctx`.
        self.i2c_efd = None;

        // 2. Stop all vCPU kthreads and the RX kthread synchronously (`kthread_stop`).
        for kt in self.vcpu_kthreads.drain(..) {
            if !kt.is_null() {
                unsafe { airlock_kapi_kthread_stop(kt) };
            }
        }
        if !self.rx_kthread.is_null() {
            let kt = self.rx_kthread;
            self.rx_kthread = null_mut();
            unsafe { airlock_kapi_kthread_stop(kt) };
        }

        // 3. Drop per-vCPU Wasm `Store`s BEFORE dropping `LinuxWasmRuntime` (`Module` + `.cwasm`).
        self.vcpu_runners.clear();
        self.rx_ctx = None;
        self.wasm = None;
    }
}

impl Drop for VmInstance {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_init() -> i32 {
    if !arch::svm::is_supported() {
        kerr!("AMD SVM with NPT is required by airlock.ko");
        return -95; // -EOPNOTSUPP
    }

    if let Err(e) = verify_wasmtime_engine_boot() {
        kerr!("{e}");
        return -5; // -EIO
    }

    let caps = AIRLOCK_CAP_SVM | AIRLOCK_CAP_NPT;
    DETECTED_CAPS.store(caps, Ordering::Release);
    let cpus = unsafe { kapi::airlock_kapi_num_possible_cpus() };
    let tsc = unsafe { kapi::airlock_kapi_tsc_khz() };
    kinfo!(
        "Rust Ring-0 core + #![no_std] Wasmtime ready (svm=1, npt=1, possible_cpus={cpus}, tsc_khz={tsc})"
    );
    0
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_exit() {
    DETECTED_CAPS.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_get_caps() -> u32 {
    DETECTED_CAPS.load(Ordering::Acquire)
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_vm_create(
    req: *const AirlockCreateVmReq,
    out_vm: *mut *mut c_void,
) -> i32 {
    if req.is_null() || out_vm.is_null() {
        return -22;
    }
    let req_ref = unsafe { &*req };
    match VmInstance::create(req_ref) {
        Ok(vm) => {
            unsafe {
                *out_vm = Box::into_raw(vm) as *mut c_void;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_vm_destroy(vm: *mut c_void) {
    if !vm.is_null() {
        let _ = unsafe { Box::from_raw(vm as *mut VmInstance) };
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kerr!("RUST PANIC in airlock.ko: {info}");
    loop {
        core::hint::spin_loop();
    }
}
