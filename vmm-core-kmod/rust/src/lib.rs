// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod kapi;

use core::ffi::c_void;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use kapi::{AIRLOCK_CAP_NPT, AIRLOCK_CAP_SVM, AirlockCreateVmReq};
use wasmtime::{Config, Engine};

const MSR_VM_CR: u32 = 0xc001_0114;
const VM_CR_SVMDIS: u64 = 1 << 4;

static DETECTED_CAPS: AtomicU32 = AtomicU32::new(0);

#[inline]
fn rdmsr_raw(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

fn detect_svm_caps() -> Result<u32, &'static str> {
    let max_ext = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if max_ext < 0x8000_000a {
        return Err("CPU does not advertise CPUID leaf 0x8000_000A (SVM)");
    }
    let ext_feat = core::arch::x86_64::__cpuid(0x8000_0001);
    if (ext_feat.ecx & (1 << 2)) == 0 {
        return Err("CPUID.8000_0001:ECX.SVM is not supported");
    }
    if (rdmsr_raw(MSR_VM_CR) & VM_CR_SVMDIS) != 0 {
        return Err("SVM disabled in BIOS/host via MSR_VM_CR.SVMDIS");
    }
    let svm_feat = core::arch::x86_64::__cpuid(0x8000_000a);
    if (svm_feat.edx & 1) == 0 {
        return Err("AMD Nested Paging (NPT) is required");
    }
    if svm_feat.ebx < 2 {
        return Err("insufficient SVM ASID count (< 2)");
    }
    Ok(AIRLOCK_CAP_SVM | AIRLOCK_CAP_NPT)
}

fn verify_wasmtime_engine_boot() -> Result<(), alloc::string::String> {
    let mut cfg = Config::new();
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
    let _engine = Engine::new(&cfg).map_err(|e| alloc::format!("Wasmtime Engine::new failed: {e}"))?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_init() -> i32 {
    let caps = match detect_svm_caps() {
        Ok(c) => c,
        Err(msg) => {
            kerr!("SVM check failed: {msg}");
            return -95; // -EOPNOTSUPP
        }
    };

    if let Err(e) = verify_wasmtime_engine_boot() {
        kerr!("{e}");
        return -5; // -EIO
    }

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
    _req: *const AirlockCreateVmReq,
    _out_vm: *mut *mut c_void,
) -> i32 {
    // Wired in sub-step (l.2) once SVM world-switch + Stage-2 NPT + VcpuWasmWorker land.
    -38 // -ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn airlock_rust_vm_destroy(_vm: *mut c_void) {}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kerr!("RUST PANIC in airlock.ko: {info}");
    loop {
        core::hint::spin_loop();
    }
}
