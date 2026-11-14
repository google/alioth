// Copyright 2026 Google LLC
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

//! Minimal PID 2 (`PID_SYS_IO`) payload for `test-guest` (leaf and nested VMM bootstrap).
//!
//! Bootstraps `rt.vdso` in-place with zero disks or NICs, logs CPU/RAM/cmdline and
//! hardware virtualization capabilities (`SVM` / `VMX`) to `COM1` via `SysRay::log`,
//! optionally boots a nested SMP `test-guest` L2 VM when `cmd == "test-guest-nested"`,
//! and exits `0` so the kernel powers off via ACPI S5 (`init_exited` -> `kernel_exit`).

#![feature(motor_ext)]

mod rt_vdso;

use core::arch::x86_64::__cpuid;
use std::sync::atomic::{AtomicBool, Ordering};

#[unsafe(no_mangle)]
pub extern "C" fn motor_has_proc_data() -> u8 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn motor_runtime_start() {
    rt_vdso::load();

    std::panic::set_hook(Box::new(|info| {
        moto_sys::SysRay::sys_panic_notify();

        static PANICKED: AtomicBool = AtomicBool::new(false);
        if PANICKED.swap(true, Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(100_000));
        }

        let msg = format!("test-init panic: {info}\n");
        let _ = moto_sys::SysRay::log(&msg);
        moto_rt::error::log_backtrace(-1);
        moto_sys::SysCpu::exit_process(0xbadc0de);
    }));
}

fn detect_hv() -> String {
    let max_ext = __cpuid(0x8000_0000).eax;
    if max_ext >= 0x8000_0001 && (__cpuid(0x8000_0001).ecx & (1 << 2)) != 0 {
        if max_ext >= 0x8000_000a {
            let svm = __cpuid(0x8000_000a);
            let npt = u8::from((svm.edx & (1 << 0)) != 0);
            let nrips = u8::from((svm.edx & (1 << 3)) != 0);
            let decode = u8::from((svm.edx & (1 << 7)) != 0);
            return format!("svm(npt={npt},nrips={nrips},decode={decode})");
        }
        return String::from("svm(npt=0,nrips=0,decode=0)");
    }

    let max_basic = __cpuid(0).eax;
    if max_basic >= 1 && (__cpuid(1).ecx & (1 << 5)) != 0 {
        return String::from("vmx");
    }

    String::from("none")
}

#[cfg(feature = "nested")]
mod nested_vmm {
    use core::mem::size_of;
    use core::sync::atomic::Ordering;
    use moto_sys::sys_mem::PAGE_SIZE_SMALL;
    use moto_sys::{SysCpu, SysHandle, SysMem, SysObj, SysRay};
    use vmm_core::host::abi::{BridgeShm, CORE_MSG_SERIAL_TX, CORE_MSG_SHUTDOWN, EXEC_TYPE_PVH};

    static L2_KLOADER: &[u8] = include_bytes!("../../../target/test-guest/kloader");
    static L2_INITRD: &[u8] = include_bytes!("../../../target/test-guest/initrd-test-guest");
    static VMM_CORE_MOTOR_CWASM: &[u8] =
        include_bytes!("../../../target/test-guest/vmm-core-motor.cwasm");

    const L2_MEM_SIZE: u64 = 64 << 20;
    const L2_NUM_CPUS: u32 = 2;
    const L2_CMDLINE: &[u8] = b"test-guest-l2";

    fn alloc_pages_for_bytes(byte_len: u64) -> u64 {
        let pages = byte_len.div_ceil(PAGE_SIZE_SMALL).max(1);
        SysMem::alloc(PAGE_SIZE_SMALL, pages)
            .unwrap_or_else(|e| panic!("SysMem::alloc({pages} pages) failed: {e}"))
    }

    fn flush_l2_line(line: &[u8]) {
        let s = String::from_utf8_lossy(line);
        let trimmed = s.trim_end_matches('\r');
        if trimmed.is_empty() {
            return;
        }
        for chunk in trimmed.as_bytes().chunks(200) {
            let part = String::from_utf8_lossy(chunk);
            let msg = format!("[L2] {part}\n");
            let _ = SysRay::log(&msg);
        }
    }

    pub fn run_nested_l2() {
        SysRay::log(
            "[L1] allocating SysMem arenas (BridgeShm, 64 MiB L2 RAM, payload, vmm-core-motor.cwasm)...\n",
        )
        .expect("SysRay::log failed");
        let shm_addr = alloc_pages_for_bytes(size_of::<BridgeShm>() as u64);
        let ram_addr = alloc_pages_for_bytes(L2_MEM_SIZE);
        let payload_size = (L2_KLOADER.len() + L2_INITRD.len()) as u64;
        let payload_addr = alloc_pages_for_bytes(payload_size);
        let cwasm_size = VMM_CORE_MOTOR_CWASM.len() as u64;
        let cwasm_addr = alloc_pages_for_bytes(cwasm_size);

        unsafe {
            core::ptr::write_bytes(shm_addr as *mut u8, 0, size_of::<BridgeShm>());
            core::ptr::copy_nonoverlapping(
                L2_KLOADER.as_ptr(),
                payload_addr as *mut u8,
                L2_KLOADER.len(),
            );
            core::ptr::copy_nonoverlapping(
                L2_INITRD.as_ptr(),
                (payload_addr as *mut u8).add(L2_KLOADER.len()),
                L2_INITRD.len(),
            );
            core::ptr::copy_nonoverlapping(
                VMM_CORE_MOTOR_CWASM.as_ptr(),
                cwasm_addr as *mut u8,
                VMM_CORE_MOTOR_CWASM.len(),
            );
        }

        let shm = shm_addr as *mut BridgeShm;
        unsafe {
            (*shm).boot_info.num_cpus = L2_NUM_CPUS;
            (*shm).boot_info.exec_type = EXEC_TYPE_PVH;
            (*shm).boot_info.mem_size = L2_MEM_SIZE;
            (*shm).boot_info.kernel_size = L2_KLOADER.len() as u64;
            (*shm).boot_info.initramfs_size = L2_INITRD.len() as u64;
            (*shm).boot_info.cmd_line_len = L2_CMDLINE.len() as u32;
            core::ptr::copy_nonoverlapping(
                L2_CMDLINE.as_ptr(),
                (&raw mut (*shm).boot_info.cmd_line).cast::<u8>(),
                L2_CMDLINE.len(),
            );
            (*shm).boot_info.num_virtio_devs = 0;
            let cfg_ready = &raw const (*shm).config_ready;
            (*cfg_ready).store(1, Ordering::Release);
        }

        let vmm_url = format!(
            "vmm:shm_addr={shm_addr:#x};ram_addr={ram_addr:#x};ram_size={L2_MEM_SIZE:#x};\
             payload_addr={payload_addr:#x};payload_size={payload_size:#x};\
             cwasm_addr={cwasm_addr:#x};cwasm_size={cwasm_size:#x}"
        );
        SysRay::log(
            "[L1] calling SysObj::create(\"vmm:...\") -> Ring-0 Wasmtime instantiate + SVM vCPU spawn...\n",
        )
        .expect("SysRay::log failed");

        let vm_handle = SysObj::create(SysHandle::KERNEL, 0, &vmm_url)
            .unwrap_or_else(|e| panic!("SysObj::create('{vmm_url}') failed: {e}"));
        let handle_msg = format!(
            "[L1] L2 VM running (handle={:#x}); streaming L2 COM1 serial output:\n",
            vm_handle.as_u64()
        );
        SysRay::log(&handle_msg).expect("SysRay::log failed");

        let mut serial_line = Vec::with_capacity(256);
        let mut l2_shutdown = false;

        while !l2_shutdown {
            while let Some(entry) = unsafe { BridgeShm::pop_core_to_io(shm) } {
                match entry.msg_type {
                    CORE_MSG_SERIAL_TX => {
                        let n = (entry.aux_u16 as usize).min(entry.data.len());
                        for &b in &entry.data[..n] {
                            if b == b'\n' {
                                flush_l2_line(&serial_line);
                                serial_line.clear();
                            } else if b != b'\r' {
                                serial_line.push(b);
                                if serial_line.len() >= 200 {
                                    flush_l2_line(&serial_line);
                                    serial_line.clear();
                                }
                            }
                        }
                    }
                    CORE_MSG_SHUTDOWN => {
                        l2_shutdown = true;
                    }
                    _ => {}
                }
            }

            let shutdown_req = unsafe {
                let req_ptr = &raw const (*shm).shutdown_requested;
                (*req_ptr).load(Ordering::Acquire) != 0
            };
            if l2_shutdown || shutdown_req {
                // Drain any final serial bytes queued right before shutdown.
                while let Some(entry) = unsafe { BridgeShm::pop_core_to_io(shm) } {
                    if entry.msg_type == CORE_MSG_SERIAL_TX {
                        let n = (entry.aux_u16 as usize).min(entry.data.len());
                        for &b in &entry.data[..n] {
                            if b == b'\n' {
                                flush_l2_line(&serial_line);
                                serial_line.clear();
                            } else if b != b'\r' {
                                serial_line.push(b);
                            }
                        }
                    }
                }
                break;
            }

            let mut handles = [vm_handle];
            SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None)
                .unwrap_or_else(|e| panic!("SysCpu::wait on vm_handle failed: {e}"));
        }

        if !serial_line.is_empty() {
            flush_l2_line(&serial_line);
        }

        SysRay::log("[L1] received L2 shutdown; closing VM handle via SysObj::put...\n")
            .expect("SysRay::log failed");
        SysObj::put(vm_handle).expect("SysObj::put(vm_handle) failed");
        SysRay::log("test-guest: nested-ok | l2_shutdown=clean (exiting PID 2 -> L1 ACPI S5)\n")
            .expect("SysRay::log failed");
    }
}

fn main() {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let ram_mib = moto_sys::SysMem::query_stats()
        .map(|stats| stats.available >> 20)
        .unwrap_or(0);

    let mut cmd_buf = [0u8; 256];
    let cmd = match moto_sys::SysRay::query_cmdline(&mut cmd_buf) {
        Ok((len, _)) => core::str::from_utf8(&cmd_buf[..len]).unwrap_or("<invalid-utf8>"),
        Err(_) => "",
    };

    let hv = detect_hv();
    let summary =
        format!("test-guest: ok | cpus={cpus} | ram_mib={ram_mib} | cmd={cmd:?} | hv={hv}\n");
    moto_sys::SysRay::log(&summary).expect("SysRay::log failed");

    #[cfg(feature = "nested")]
    if cmd == "test-guest-nested" {
        nested_vmm::run_nested_l2();
    }
}
