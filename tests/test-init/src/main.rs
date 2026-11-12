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

//! Minimal PID 2 (`PID_SYS_IO`) payload for `test-guest`.
//!
//! Bootstraps `rt.vdso` in-place with zero disks or NICs, logs CPU/RAM/cmdline and
//! hardware virtualization capabilities (`SVM` / `VMX`) to `COM1` via `SysRay::log`,
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
}
