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
        return;
    }

    if cmd.split_whitespace().any(|tok| tok == "vmm-passthrough") {
        passthrough_vmm::run_from_initrd_bundle();
    }
}

mod passthrough_vmm {
    use core::arch::asm;
    use core::mem::size_of;
    use core::sync::atomic::Ordering;
    use moto_sys::kernel_log::{
        KERNEL_LOG_RING_SIZE, KernelLogControl, KernelLogSnapshot, decode_kernel_log_frame,
        snapshot_kernel_log_ring,
    };
    use moto_sys::sys_mem::{PAGE_SIZE_MID, PAGE_SIZE_SMALL};
    use moto_sys::{SysCpu, SysHandle, SysMem, SysObj, SysRay};
    use vmm_core::host::abi::{
        BridgeShm, CORE_MSG_SERIAL_TX, CORE_MSG_SHUTDOWN, EXEC_TYPE_LINUX, EXEC_TYPE_NONE,
        EXEC_TYPE_PVH, IO_MSG_REQUEST_SHUTDOWN, IO_MSG_SERIAL_RX, IoToCoreEntry,
        MAX_PASSTHROUGH_DEVS,
    };

    const INITRD_BUNDLE_MAGIC: [u8; 8] = *b"MVMMBNDL";
    const INITRD_BUNDLE_VERSION: u32 = 1;
    const INITRD_BUNDLE_HEADER_SIZE: usize = 64;

    const COM1_DATA: u16 = 0x3f8;
    const COM1_LSR: u16 = 0x3fd;
    const LSR_RX_READY: u8 = 1 << 0;
    const LSR_TX_EMPTY: u8 = 1 << 5;
    const LSR_TX_IDLE: u8 = 1 << 6;
    const ESCAPE_BYTE: u8 = 0x02; // Ctrl-b

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InitrdBundleHeader {
        magic: [u8; 8],
        version: u32,
        _flags: u32,
        toml_len: u64,
        cwasm_len: u64,
        kernel_len: u64,
        initramfs_len: u64,
        _reserved: [u64; 2],
    }

    struct ParsedBundleVmConfig {
        exec_type: u32,
        num_cpus: u32,
        mem_size: u64,
        cmd_line: String,
        pci_devs: Vec<u16>,
    }

    fn alloc_pages_for_bytes(byte_len: u64) -> u64 {
        let pages = byte_len.div_ceil(PAGE_SIZE_SMALL).max(1);
        SysMem::alloc(PAGE_SIZE_SMALL, pages)
            .unwrap_or_else(|e| panic!("SysMem::alloc({pages} pages) failed: {e}"))
    }

    #[inline]
    unsafe fn pio_in8(port: u16) -> u8 {
        let val: u8;
        unsafe {
            asm!(
                "in al, dx",
                out("al") val,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
        }
        val
    }

    #[inline]
    unsafe fn pio_out8(port: u16, val: u8) {
        unsafe {
            asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    fn uart_write_raw_byte(b: u8) {
        unsafe {
            while (pio_in8(COM1_LSR) & LSR_TX_EMPTY) == 0 {
                core::hint::spin_loop();
            }
            pio_out8(COM1_DATA, b);
        }
    }

    fn uart_write_raw_bytes(bytes: &[u8]) {
        for &b in bytes {
            uart_write_raw_byte(b);
        }
    }

    fn uart_write_kernel_log_bytes(bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                uart_write_raw_byte(b'\r');
            }
            uart_write_raw_byte(b);
        }
    }

    fn uart_flush_tx() {
        unsafe {
            while (pio_in8(COM1_LSR) & LSR_TX_IDLE) == 0 {
                core::hint::spin_loop();
            }
        }
    }

    fn uart_try_read_byte() -> Option<u8> {
        unsafe {
            if (pio_in8(COM1_LSR) & LSR_RX_READY) != 0 {
                Some(pio_in8(COM1_DATA))
            } else {
                None
            }
        }
    }

    fn drain_kernel_logs(
        ring: &[u8],
        control: &KernelLogControl,
        previous_end: &mut u64,
        staging: &mut [u8],
    ) {
        loop {
            let Ok(snap) = snapshot_kernel_log_ring(control, *previous_end, staging, |off, dst| {
                dst.copy_from_slice(&ring[off..off + dst.len()])
            }) else {
                break;
            };
            let KernelLogSnapshot::Stable { end, len, lapped } = snap else {
                continue;
            };
            *previous_end = end;
            if lapped || len == 0 {
                break;
            }
            let mut pos = 0;
            while pos < len {
                match decode_kernel_log_frame(&staging[pos..len]) {
                    Ok(frame) => {
                        uart_write_kernel_log_bytes(frame.payload);
                        pos += frame.encoded_len;
                    }
                    Err(_) => break,
                }
            }
            break;
        }
    }

    fn strip_comment(line: &str) -> &str {
        let mut in_quotes = false;
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' if in_quotes => {
                    i += 2;
                    continue;
                }
                b'"' => in_quotes = !in_quotes,
                b'#' if !in_quotes => return &line[..i],
                _ => {}
            }
            i += 1;
        }
        line
    }

    fn parse_quoted(val: &str) -> String {
        let s = val.trim();
        if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
            s[1..s.len() - 1].to_owned()
        } else {
            panic!("InitrdBundle vm.toml: expected quoted string, got '{s}'");
        }
    }

    fn parse_bdf(raw: &str) -> u16 {
        let s = raw.trim();
        let (prefix, dev_fn) = s
            .rsplit_once(':')
            .unwrap_or_else(|| panic!("invalid PCI BDF '{s}'"));
        let bus_str = match prefix.rsplit_once(':') {
            Some((dom_str, b_str)) => {
                let dom = u16::from_str_radix(dom_str, 16)
                    .unwrap_or_else(|_| panic!("invalid PCI domain in '{s}'"));
                assert_eq!(dom, 0, "only PCI domain 0000 is supported in '{s}'");
                b_str
            }
            None => prefix,
        };
        let bus = u8::from_str_radix(bus_str, 16)
            .unwrap_or_else(|_| panic!("invalid PCI bus in '{s}'"));
        let (dev_str, fn_str) = dev_fn
            .split_once('.')
            .unwrap_or_else(|| panic!("expected bus:dev.func in '{s}'"));
        let dev = u8::from_str_radix(dev_str, 16)
            .unwrap_or_else(|_| panic!("invalid PCI dev in '{s}'"));
        let func = u8::from_str_radix(fn_str, 16)
            .unwrap_or_else(|_| panic!("invalid PCI func in '{s}'"));
        assert!(dev < 32 && func < 8, "PCI dev/func out of range in '{s}'");
        ((bus as u16) << 8) | ((dev as u16) << 3) | (func as u16)
    }

    fn parse_bundle_vm_toml(toml_str: &str) -> ParsedBundleVmConfig {
        let mut exec_type = EXEC_TYPE_NONE;
        let mut num_cpus: Option<u32> = None;
        let mut mem_size: Option<u64> = None;
        let mut cmd_line = String::new();
        let mut pci_devs = Vec::new();

        for raw_line in toml_str.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            assert!(
                !(line.starts_with('[') && line.ends_with(']')),
                "InitrdBundle passthrough mode does not support emulated sections like '{line}'"
            );
            let (raw_key, raw_val) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("InitrdBundle vm.toml: invalid line '{line}'"));
            let key = raw_key.trim();
            let val = raw_val.trim();
            match key {
                "kernel" => {
                    let _ = parse_quoted(val);
                    exec_type = EXEC_TYPE_LINUX;
                }
                "pvh" => {
                    let _ = parse_quoted(val);
                    exec_type = EXEC_TYPE_PVH;
                }
                "initramfs" | "log_file" | "log_level" => {
                    let _ = parse_quoted(val);
                }
                "iommu" => {}
                "cmd_line" => cmd_line = parse_quoted(val),
                "num_cpus" => {
                    num_cpus = Some(
                        val.parse()
                            .unwrap_or_else(|e| panic!("invalid num_cpus '{val}': {e}")),
                    );
                }
                "mem_size" => {
                    let s = parse_quoted(val);
                    let bytes = if let Some(m) = s.strip_suffix('M') {
                        m.parse::<u64>().expect("invalid mem_size M") << 20
                    } else if let Some(g) = s.strip_suffix('G') {
                        g.parse::<u64>().expect("invalid mem_size G") << 30
                    } else {
                        panic!("invalid mem_size '{s}'");
                    };
                    mem_size = Some(bytes);
                }
                "pci" => {
                    assert!(
                        val.starts_with('[') && val.ends_with(']'),
                        "expected pci = [...], got '{val}'"
                    );
                    let inner = val[1..val.len() - 1].trim();
                    if !inner.is_empty() {
                        for item in inner.split(',') {
                            let item = item.trim();
                            if !item.is_empty() {
                                pci_devs.push(parse_bdf(&parse_quoted(item)));
                            }
                        }
                    }
                }
                "blk" => {
                    let inner = val
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .trim();
                    assert!(
                        inner.is_empty(),
                        "InitrdBundle passthrough mode requires blk = [] (pass block devices via pci = [...])"
                    );
                }
                other => panic!("InitrdBundle vm.toml: unknown key '{other}'"),
            }
        }

        ParsedBundleVmConfig {
            exec_type,
            num_cpus: num_cpus.expect("missing num_cpus in InitrdBundle vm.toml"),
            mem_size: mem_size.expect("missing mem_size in InitrdBundle vm.toml"),
            cmd_line,
            pci_devs,
        }
    }

    pub fn run_from_initrd_bundle() {
        let base_ptr = (moto_sys::CUSTOM_USERSPACE_REGION_START + (1u64 << 30)) as *const u8;
        let hdr = unsafe {
            assert_eq!(size_of::<InitrdBundleHeader>(), INITRD_BUNDLE_HEADER_SIZE);
            core::ptr::read_unaligned(base_ptr as *const InitrdBundleHeader)
        };
        assert_eq!(
            hdr.magic, INITRD_BUNDLE_MAGIC,
            "missing MVMMBNDL InitrdBundle header at CUSTOM_USERSPACE_REGION_START"
        );
        assert_eq!(
            hdr.version, INITRD_BUNDLE_VERSION,
            "unsupported InitrdBundle version {}",
            hdr.version
        );

        let toml_off = INITRD_BUNDLE_HEADER_SIZE;
        let cwasm_off = toml_off + (hdr.toml_len as usize);
        let kernel_off = cwasm_off + (hdr.cwasm_len as usize);
        let initramfs_off = kernel_off + (hdr.kernel_len as usize);

        let (toml_bytes, cwasm_bytes, kernel_bytes, initramfs_bytes) = unsafe {
            (
                core::slice::from_raw_parts(base_ptr.add(toml_off), hdr.toml_len as usize),
                core::slice::from_raw_parts(base_ptr.add(cwasm_off), hdr.cwasm_len as usize),
                core::slice::from_raw_parts(base_ptr.add(kernel_off), hdr.kernel_len as usize),
                core::slice::from_raw_parts(
                    base_ptr.add(initramfs_off),
                    hdr.initramfs_len as usize,
                ),
            )
        };

        let toml_str = core::str::from_utf8(toml_bytes)
            .expect("InitrdBundle vm.toml is not valid UTF-8");
        let cfg = parse_bundle_vm_toml(toml_str);
        assert!(
            cfg.pci_devs.len() <= MAX_PASSTHROUGH_DEVS,
            "too many passthrough PCI devices ({})",
            cfg.pci_devs.len()
        );

        let ram_size = cfg
            .mem_size
            .max(4 << 20)
            .next_multiple_of(PAGE_SIZE_MID);
        let shm_addr = alloc_pages_for_bytes(size_of::<BridgeShm>() as u64);
        let ram_pages = ram_size / PAGE_SIZE_SMALL;
        let ram_addr = if !cfg.pci_devs.is_empty()
            && let Ok(addr) = SysMem::map(
                SysHandle::SELF,
                SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_CONTIGUOUS,
                u64::MAX,
                u64::MAX,
                PAGE_SIZE_SMALL,
                ram_pages,
            ) {
            addr
        } else {
            alloc_pages_for_bytes(ram_size)
        };
        let payload_len = kernel_bytes.len() + initramfs_bytes.len();
        let payload_size = (payload_len.max(PAGE_SIZE_SMALL as usize)) as u64;
        let payload_addr = alloc_pages_for_bytes(payload_size);
        let cwasm_size = cwasm_bytes.len() as u64;
        let cwasm_addr = alloc_pages_for_bytes(cwasm_size);

        unsafe {
            core::ptr::write_bytes(shm_addr as *mut u8, 0, size_of::<BridgeShm>());
            if !kernel_bytes.is_empty() {
                core::ptr::copy_nonoverlapping(
                    kernel_bytes.as_ptr(),
                    payload_addr as *mut u8,
                    kernel_bytes.len(),
                );
            }
            if !initramfs_bytes.is_empty() {
                core::ptr::copy_nonoverlapping(
                    initramfs_bytes.as_ptr(),
                    (payload_addr as *mut u8).add(kernel_bytes.len()),
                    initramfs_bytes.len(),
                );
            }
            core::ptr::copy_nonoverlapping(
                cwasm_bytes.as_ptr(),
                cwasm_addr as *mut u8,
                cwasm_bytes.len(),
            );
        }

        let shm = shm_addr as *mut BridgeShm;
        unsafe {
            (*shm).boot_info.num_cpus = cfg.num_cpus;
            (*shm).boot_info.exec_type = cfg.exec_type;
            (*shm).boot_info.mem_size = ram_size;
            (*shm).boot_info.kernel_size = kernel_bytes.len() as u64;
            (*shm).boot_info.initramfs_size = initramfs_bytes.len() as u64;
            let cmd_bytes = cfg.cmd_line.as_bytes();
            let cmd_n = cmd_bytes.len().min((*shm).boot_info.cmd_line.len());
            core::ptr::copy_nonoverlapping(
                cmd_bytes.as_ptr(),
                (&raw mut (*shm).boot_info.cmd_line).cast::<u8>(),
                cmd_n,
            );
            (*shm).boot_info.cmd_line_len = cmd_n as u32;
            (*shm).boot_info.num_virtio_devs = 0;
            (*shm).boot_info.num_pci_devs = cfg.pci_devs.len() as u32;
            for (i, &bdf) in cfg.pci_devs.iter().enumerate() {
                (*shm).boot_info.pci_devs[i] = bdf;
            }
            let cfg_ready = &raw const (*shm).config_ready;
            (*cfg_ready).store(1, Ordering::Release);
        }

        let launch_msg = format!(
            "vmm-passthrough: starting L2 VM (cpus={}, mem_mib={}, pci_devs={})\n",
            cfg.num_cpus,
            ram_size >> 20,
            cfg.pci_devs.len(),
        );
        let _ = SysRay::log(&launch_msg);

        let vmm_url = format!(
            "vmm:shm_addr={shm_addr:#x};ram_addr={ram_addr:#x};ram_size={ram_size:#x};\
             payload_addr={payload_addr:#x};payload_size={payload_size:#x};\
             cwasm_addr={cwasm_addr:#x};cwasm_size={cwasm_size:#x}"
        );
        let vm_handle = SysObj::create(SysHandle::KERNEL, 0, &vmm_url)
            .unwrap_or_else(|e| panic!("SysObj::create('{vmm_url}') failed: {e}"));

        // Claim `serial_console` so COM1 RX interrupts wake our loop instead of
        // triggering `kernel_exit()`, and forward any Ring-0 kernel logs cleanly.
        let log_ring_addr = alloc_pages_for_bytes(KERNEL_LOG_RING_SIZE as u64) as usize;
        let ctrl_page_addr = alloc_pages_for_bytes(PAGE_SIZE_SMALL) as usize;
        unsafe {
            core::ptr::write_bytes(ctrl_page_addr as *mut u8, 0, PAGE_SIZE_SMALL as usize);
        }
        let log_ring =
            unsafe { core::slice::from_raw_parts(log_ring_addr as *const u8, KERNEL_LOG_RING_SIZE) };
        let log_ctrl = unsafe { &*(ctrl_page_addr as *const KernelLogControl) };
        let console_handle = SysObj::get(
            SysHandle::KERNEL,
            0,
            &format!("serial_console:{log_ring_addr}:{ctrl_page_addr}"),
        )
        .unwrap_or_else(|e| panic!("SysObj::get('serial_console:...') failed: {e}"));

        let mut log_prev_end = 0u64;
        let mut log_staging = vec![0u8; KERNEL_LOG_RING_SIZE];
        let mut escape_pending = false;
        let mut l2_shutdown = false;

        while !l2_shutdown {
            drain_kernel_logs(log_ring, log_ctrl, &mut log_prev_end, &mut log_staging);

            // 1. Drain L2 COM1 TX & shutdown notifications from Ring 0.
            while let Some(entry) = unsafe { BridgeShm::pop_core_to_io(shm) } {
                match entry.msg_type {
                    CORE_MSG_SERIAL_TX => {
                        let n = (entry.aux_u16 as usize).min(entry.data.len());
                        uart_write_raw_bytes(&entry.data[..n]);
                    }
                    CORE_MSG_SHUTDOWN => {
                        l2_shutdown = true;
                    }
                    _ => {}
                }
            }

            // 2. Drain physical COM1 RX bytes from L0 and forward to L2 (with Ctrl-b q/x escape).
            let mut rx_batch = Vec::new();
            let mut user_requested_shutdown = false;
            while let Some(b) = uart_try_read_byte() {
                if escape_pending {
                    escape_pending = false;
                    match b {
                        b'q' | b'x' => {
                            user_requested_shutdown = true;
                            break;
                        }
                        ESCAPE_BYTE => rx_batch.push(ESCAPE_BYTE),
                        other => {
                            rx_batch.push(ESCAPE_BYTE);
                            rx_batch.push(other);
                        }
                    }
                } else if b == ESCAPE_BYTE {
                    escape_pending = true;
                } else {
                    rx_batch.push(b);
                }
            }

            if !rx_batch.is_empty() {
                let mut woke = false;
                for chunk in rx_batch.chunks(48) {
                    let mut data = [0u8; 48];
                    data[..chunk.len()].copy_from_slice(chunk);
                    let entry = IoToCoreEntry {
                        msg_type: IO_MSG_SERIAL_RX,
                        irq_kind: 0,
                        queue_index: chunk.len() as u16,
                        dev: 0,
                        data,
                    };
                    if unsafe { BridgeShm::push_io_to_core(shm, entry) } {
                        woke = true;
                    }
                }
                if woke {
                    let _ = SysCpu::wake(vm_handle);
                }
            }

            if user_requested_shutdown {
                unsafe {
                    (*shm).shutdown_requested.store(1, Ordering::Release);
                }
                let entry = IoToCoreEntry {
                    msg_type: IO_MSG_REQUEST_SHUTDOWN,
                    ..Default::default()
                };
                let _ = unsafe { BridgeShm::push_io_to_core(shm, entry) };
                let _ = SysCpu::wake(vm_handle);
                break;
            }

            let shutdown_req = unsafe { (*shm).shutdown_requested.load(Ordering::Acquire) != 0 };
            if l2_shutdown || shutdown_req {
                while let Some(entry) = unsafe { BridgeShm::pop_core_to_io(shm) } {
                    if entry.msg_type == CORE_MSG_SERIAL_TX {
                        let n = (entry.aux_u16 as usize).min(entry.data.len());
                        uart_write_raw_bytes(&entry.data[..n]);
                    }
                }
                break;
            }

            let mut handles = [vm_handle, console_handle];
            let _ = SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None);
        }

        SysObj::put(vm_handle).expect("SysObj::put(vm_handle) failed");
        drain_kernel_logs(log_ring, log_ctrl, &mut log_prev_end, &mut log_staging);
        uart_write_raw_bytes(b"\r\nvmm-passthrough: l2_shutdown=clean\r\n");
        uart_flush_tx();
    }
}
