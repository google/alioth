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

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use parking_lot::RwLock;
use vmm_io::host::abi::{
    ERR_EOF, ERR_GENERIC, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXEC_TYPE_LINUX, EXEC_TYPE_PVH,
    IO_BRIDGE_EVENT_POLL, IO_BRIDGE_EVENT_SERIAL_INPUT, IO_BRIDGE_EVENT_SERIAL_TX,
    IO_BRIDGE_EVENT_SHUTDOWN, IO_BRIDGE_EVENT_VIRTIO_NOTIFY, IO_BRIDGE_EVENT_VIRTIO_RESET,
    IO_BRIDGE_EVENT_VIRTIO_START, IRQ_KIND_CONFIG, MAX_QUEUES_PER_DEV, RawIoBootConfig,
    RawIoBridgeEvent, ShmVirtioDeviceSpec, ShmVirtioQueueConfig,
};
use vmm_io::host::{
    ExecKind, Handle, Interest, IoBootConfig, IoBridgeEvent, Token, VirtioDeviceSpec,
    VirtioIrqKind,
};
use vmm_io::virtio::dev::net::NetFeature;
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

/// Host interface trait for the I/O domain (`vmm-io-host`): TAP, block files, serial, and bridge.
///
/// All `"vmm"::*` host imports registered by [`register_io_imports`] delegate exclusively
/// to this trait, allowing alternate host implementations.
pub trait VmmHostIo: Send + Sync + 'static {
    fn tap_open(&self, if_name: Option<&str>) -> io::Result<Handle>;
    fn tap_detected_offload(&self, tap: Handle) -> NetFeature;
    fn tap_enable_offload(&self, tap: Handle, feature: NetFeature) -> io::Result<()>;
    fn tap_register(&self, tap: Handle, token: Token, interests: Interest) -> io::Result<()>;
    fn tap_deregister(&self, tap: Handle);
    fn tap_read(&self, tap: Handle, dst: &mut [u8]) -> io::Result<usize>;
    fn tap_write(&self, tap: Handle, src: &[u8]) -> io::Result<usize>;
    fn tap_close(&self, tap: Handle);

    fn blk_open(&self, path: &Path, read_only: bool) -> io::Result<(Handle, u64)>;
    fn blk_read_at(&self, blk: Handle, offset: u64, dst: &mut [u8]) -> io::Result<usize>;
    fn blk_write_at(&self, blk: Handle, offset: u64, src: &[u8]) -> io::Result<usize>;
    fn blk_flush(&self, blk: Handle) -> io::Result<()>;
    fn blk_close(&self, blk: Handle);

    fn serial_open(&self) -> io::Result<Handle>;
    fn serial_write_byte(&self, serial: Handle, byte: u8) -> io::Result<()>;
    fn serial_read_input(&self, serial: Handle, dst: &mut [u8]) -> io::Result<Option<usize>>;
    fn serial_shutdown(&self, serial: Handle) -> io::Result<()>;
    fn serial_close(&self, serial: Handle);

    fn io_register_vm_config(
        &self,
        boot_cfg: &IoBootConfig,
        virtio_devs: &[VirtioDeviceSpec],
    ) -> io::Result<()>;
    fn io_next_event(&self) -> io::Result<IoBridgeEvent>;
    fn io_request_shutdown(&self) -> io::Result<()>;
    fn io_guest_mem_read(&self, gpa: u64, dst: &mut [u8]) -> io::Result<()>;
    fn io_guest_mem_write(&self, gpa: u64, src: &[u8]) -> io::Result<()>;
    fn io_virtio_irq(&self, dev: Handle, kind: VirtioIrqKind) -> io::Result<()>;
    fn io_serial_push_rx(&self, data: &[u8]) -> io::Result<()>;
}

/// Per-Wasm-thread ABI context binding a [`VmmHostIo`] implementation to a Wasmtime store.
pub struct IoWasmCtx<H: VmmHostIo + ?Sized> {
    host: Arc<H>,
    memory: SharedMemory,
    last_error: String,
}

impl<H: VmmHostIo + ?Sized> IoWasmCtx<H> {
    pub fn new(host: Arc<H>, memory: SharedMemory) -> Self {
        Self {
            host,
            memory,
            last_error: String::new(),
        }
    }

    fn set_err(&mut self, msg: impl Into<String>) -> i32 {
        self.last_error = msg.into();
        ERR_GENERIC
    }

    fn set_err_i64(&mut self, msg: impl Into<String>) -> i64 {
        self.set_err(msg) as i64
    }

    fn set_io_err(&mut self, e: io::Error) -> i32 {
        match e.kind() {
            io::ErrorKind::WouldBlock => ERR_WOULD_BLOCK,
            io::ErrorKind::Interrupted => ERR_INTERRUPTED,
            _ => self.set_err(e.to_string()),
        }
    }

    fn set_io_err_i64(&mut self, e: io::Error) -> i64 {
        self.set_io_err(e) as i64
    }
}

fn check_bounds(mem: &SharedMemory, ptr: u32, len: usize) -> Result<usize, String> {
    let start = ptr as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "guest memory address overflow".to_string())?;
    if end > mem.data().len() {
        return Err(format!(
            "guest memory access out of bounds: {start}..{end} > {}",
            mem.data().len()
        ));
    }
    Ok(start)
}

fn read_bytes(mem: &SharedMemory, ptr: u32, dst: &mut [u8]) -> Result<(), String> {
    let start = check_bounds(mem, ptr, dst.len())?;
    unsafe {
        std::ptr::copy_nonoverlapping(
            mem.data().as_ptr().add(start) as *const u8,
            dst.as_mut_ptr(),
            dst.len(),
        );
    }
    Ok(())
}

fn write_bytes(mem: &SharedMemory, ptr: u32, src: &[u8]) -> Result<(), String> {
    let start = check_bounds(mem, ptr, src.len())?;
    unsafe {
        std::ptr::copy_nonoverlapping(
            src.as_ptr(),
            mem.data().as_ptr().add(start) as *mut u8,
            src.len(),
        );
    }
    Ok(())
}

fn read_struct<T: FromBytes + Copy>(mem: &SharedMemory, ptr: u32) -> Result<T, String> {
    let size = std::mem::size_of::<T>();
    let start = check_bounds(mem, ptr, size)?;
    let bytes =
        unsafe { std::slice::from_raw_parts(mem.data().as_ptr().add(start) as *const u8, size) };
    T::read_from(bytes).ok_or_else(|| "failed to decode struct from guest memory".to_string())
}

fn write_struct<T: AsBytes>(mem: &SharedMemory, ptr: u32, val: &T) -> Result<(), String> {
    write_bytes(mem, ptr, val.as_bytes())
}

fn read_vec<T: FromBytes + Copy>(
    mem: &SharedMemory,
    ptr: u32,
    count: u32,
) -> Result<Vec<T>, String> {
    let elem_size = std::mem::size_of::<T>();
    let _total = (count as usize)
        .checked_mul(elem_size)
        .ok_or_else(|| "slice byte length overflow".to_string())?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let item_ptr = (ptr as usize + i * elem_size) as u32;
        out.push(read_struct::<T>(mem, item_ptr)?);
    }
    Ok(out)
}

/// Register all `"vmm"::*` imports for `vmm-io` against any [`VmmHostIo`] implementation.
pub fn register_io_imports<T, H>(
    linker: &mut Linker<T>,
    get_ctx: impl Fn(&mut T) -> &mut IoWasmCtx<H> + Copy + Send + Sync + 'static,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    H: VmmHostIo + ?Sized,
{
    linker.func_wrap(
        "vmm",
        "vmm_last_error_len",
        move |mut caller: Caller<'_, T>| -> u32 { get_ctx(caller.data_mut()).last_error.len() as u32 },
    )?;

    linker.func_wrap(
        "vmm",
        "vmm_last_error_read",
        move |mut caller: Caller<'_, T>, dst_ptr: u32, dst_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let err_bytes = ctx.last_error.as_bytes();
            let n = err_bytes.len().min(dst_len as usize);
            if write_bytes(&ctx.memory, dst_ptr, &err_bytes[..n]).is_err() {
                return ERR_GENERIC;
            }
            n as i32
        },
    )?;

    // --- TAP Device Imports ---
    linker.func_wrap(
        "vmm",
        "tap_open",
        move |mut caller: Caller<'_, T>, has_name: u32, name_ptr: u32, name_len: u32| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            let if_name = if has_name != 0 {
                let mut buf = vec![0u8; name_len as usize];
                if let Err(e) = read_bytes(&ctx.memory, name_ptr, &mut buf) {
                    return ctx.set_err_i64(e);
                }
                match String::from_utf8(buf) {
                    Ok(s) => Some(s),
                    Err(e) => return ctx.set_err_i64(e.to_string()),
                }
            } else {
                None
            };
            match ctx.host.tap_open(if_name.as_deref()) {
                Ok(handle) => handle as i64,
                Err(e) => ctx.set_io_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_detected_offload",
        move |mut caller: Caller<'_, T>, tap: Handle| -> u64 {
            get_ctx(caller.data_mut())
                .host
                .tap_detected_offload(tap)
                .bits()
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_enable_offload",
        move |mut caller: Caller<'_, T>, tap: Handle, feature: u64| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx
                .host
                .tap_enable_offload(tap, NetFeature::from_bits_retain(feature))
            {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_register",
        move |mut caller: Caller<'_, T>, tap: Handle, token: u64, interests: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.tap_register(
                tap,
                Token(token),
                Interest::from_bits_retain(interests as u8),
            ) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_deregister",
        move |mut caller: Caller<'_, T>, tap: Handle| {
            get_ctx(caller.data_mut()).host.tap_deregister(tap);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_read",
        move |mut caller: Caller<'_, T>, tap: Handle, dst_ptr: u32, max_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, max_len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    max_len as usize,
                )
            };
            let res = ctx.host.tap_read(tap, dst);
            match res {
                Ok(n) => n as i32,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_write",
        move |mut caller: Caller<'_, T>, tap: Handle, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    ctx.memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            let res = ctx.host.tap_write(tap, src);
            match res {
                Ok(n) => n as i32,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_close",
        move |mut caller: Caller<'_, T>, tap: Handle| {
            get_ctx(caller.data_mut()).host.tap_close(tap);
        },
    )?;

    // --- Block Device File Imports ---
    linker.func_wrap(
        "vmm",
        "blk_open",
        move |mut caller: Caller<'_, T>,
              path_ptr: u32,
              path_len: u32,
              read_only: u32,
              size_out_ptr: u32|
              -> i64 {
            let ctx = get_ctx(caller.data_mut());
            let mut buf = vec![0u8; path_len as usize];
            if let Err(e) = read_bytes(&ctx.memory, path_ptr, &mut buf) {
                return ctx.set_err_i64(e);
            }
            let path_str = match String::from_utf8(buf) {
                Ok(s) => s,
                Err(e) => return ctx.set_err_i64(e.to_string()),
            };
            let (handle, len) = match ctx.host.blk_open(Path::new(&path_str), read_only != 0) {
                Ok(v) => v,
                Err(e) => return ctx.set_io_err_i64(e),
            };
            if let Err(e) = write_struct(&ctx.memory, size_out_ptr, &len) {
                ctx.host.blk_close(handle);
                return ctx.set_err_i64(e);
            }
            handle as i64
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_read_at",
        move |mut caller: Caller<'_, T>, blk: Handle, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            let res = ctx.host.blk_read_at(blk, offset, dst);
            match res {
                Ok(n) => n as i32,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_write_at",
        move |mut caller: Caller<'_, T>, blk: Handle, offset: u64, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    ctx.memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            let res = ctx.host.blk_write_at(blk, offset, src);
            match res {
                Ok(n) => n as i32,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_flush",
        move |mut caller: Caller<'_, T>, blk: Handle| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.blk_flush(blk) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_close",
        move |mut caller: Caller<'_, T>, blk: Handle| {
            get_ctx(caller.data_mut()).host.blk_close(blk);
        },
    )?;

    // --- Serial Console Imports ---
    linker.func_wrap(
        "vmm",
        "serial_open",
        move |mut caller: Caller<'_, T>| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.serial_open() {
                Ok(handle) => handle as i64,
                Err(e) => ctx.set_io_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_write_byte",
        move |mut caller: Caller<'_, T>, serial: Handle, byte: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.serial_write_byte(serial, byte as u8) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_read_input",
        move |mut caller: Caller<'_, T>, serial: Handle, dst_ptr: u32, max_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut buf = vec![0u8; max_len as usize];
            match ctx.host.serial_read_input(serial, &mut buf) {
                Ok(None) => ERR_EOF,
                Ok(Some(n)) => {
                    if let Err(e) = write_bytes(&ctx.memory, dst_ptr, &buf[..n]) {
                        return ctx.set_err(e);
                    }
                    n as i32
                }
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_shutdown",
        move |mut caller: Caller<'_, T>, serial: Handle| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.serial_shutdown(serial) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_close",
        move |mut caller: Caller<'_, T>, serial: Handle| {
            get_ctx(caller.data_mut()).host.serial_close(serial);
        },
    )?;

    // --- Cross-Split IO <-> Core Bridge Imports ---
    linker.func_wrap(
        "vmm",
        "io_register_vm_config",
        move |mut caller: Caller<'_, T>,
              boot_cfg_ptr: u32,
              devs_ptr: u32,
              num_devs: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw_boot = match read_struct::<RawIoBootConfig>(&ctx.memory, boot_cfg_ptr) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            let raw_devs =
                match read_vec::<ShmVirtioDeviceSpec>(&ctx.memory, devs_ptr, num_devs) {
                    Ok(d) => d,
                    Err(e) => return ctx.set_err(e),
                };

            let klen = (raw_boot.kernel_path_len as usize).min(raw_boot.kernel_path.len());
            let kernel_path = if klen > 0 {
                Some(PathBuf::from(
                    String::from_utf8_lossy(&raw_boot.kernel_path[..klen]).into_owned(),
                ))
            } else {
                None
            };
            let ilen = (raw_boot.initramfs_path_len as usize).min(raw_boot.initramfs_path.len());
            let initramfs_path = if ilen > 0 {
                Some(PathBuf::from(
                    String::from_utf8_lossy(&raw_boot.initramfs_path[..ilen]).into_owned(),
                ))
            } else {
                None
            };
            let clen = (raw_boot.cmd_line_len as usize).min(raw_boot.cmd_line.len());
            let cmd_line = if clen > 0 {
                Some(String::from_utf8_lossy(&raw_boot.cmd_line[..clen]).into_owned())
            } else {
                None
            };
            let boot_cfg = IoBootConfig {
                num_cpus: raw_boot.num_cpus,
                mem_size: raw_boot.mem_size as usize,
                exec_kind: match raw_boot.exec_type {
                    EXEC_TYPE_LINUX => Some(ExecKind::Linux),
                    EXEC_TYPE_PVH => Some(ExecKind::Pvh),
                    _ => None,
                },
                kernel_path,
                initramfs_path,
                cmd_line,
            };
            let specs: Vec<VirtioDeviceSpec> = raw_devs
                .into_iter()
                .map(|d| {
                    let nlen = (d.name_len as usize).min(d.name.len());
                    let clen = (d.config_len as usize).min(d.config_bytes.len());
                    VirtioDeviceSpec {
                        dev: d.dev,
                        name: String::from_utf8_lossy(&d.name[..nlen]).into_owned(),
                        device_id: d.device_id,
                        device_features: d.device_features,
                        num_queues: d.num_queues,
                        config_bytes: d.config_bytes[..clen].to_vec(),
                    }
                })
                .collect();

            match ctx.host.io_register_vm_config(&boot_cfg, &specs) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_next_event",
        move |mut caller: Caller<'_, T>, event_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let ev = match ctx.host.io_next_event() {
                Ok(ev) => ev,
                Err(e) => return ctx.set_io_err(e),
            };
            let raw = match ev {
                IoBridgeEvent::VirtioStart {
                    dev,
                    driver_features,
                    queues,
                } => {
                    let nq = queues.len().min(MAX_QUEUES_PER_DEV);
                    let mut raw_ev = RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_VIRTIO_START,
                        num_queues: nq as u16,
                        dev,
                        driver_features,
                        ..Default::default()
                    };
                    for (i, q) in queues.into_iter().take(nq).enumerate() {
                        raw_ev.queues[i] = ShmVirtioQueueConfig::from(q);
                    }
                    raw_ev
                }
                IoBridgeEvent::VirtioNotify { dev, queue_index } => RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_VIRTIO_NOTIFY,
                    dev,
                    queue_index,
                    ..Default::default()
                },
                IoBridgeEvent::VirtioReset { dev } => RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_VIRTIO_RESET,
                    dev,
                    ..Default::default()
                },
                IoBridgeEvent::Poll(pe) => RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_POLL,
                    token: pe.token.0,
                    is_readable: u8::from(pe.is_readable),
                    is_writable: u8::from(pe.is_writable),
                    ..Default::default()
                },
                IoBridgeEvent::SerialInput => RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_SERIAL_INPUT,
                    ..Default::default()
                },
                IoBridgeEvent::SerialTx(bytes) => {
                    let len = bytes.len().min(40);
                    let mut raw_ev = RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_SERIAL_TX,
                        tx_len: len as u8,
                        ..Default::default()
                    };
                    raw_ev.tx_bytes[..len].copy_from_slice(&bytes[..len]);
                    raw_ev
                }
                IoBridgeEvent::Shutdown => RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_SHUTDOWN,
                    ..Default::default()
                },
            };
            if let Err(e) = write_struct(&ctx.memory, event_out_ptr, &raw) {
                return ctx.set_err(e);
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_request_shutdown",
        move |mut caller: Caller<'_, T>| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.io_request_shutdown() {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_guest_mem_read",
        move |mut caller: Caller<'_, T>, gpa: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            let res = ctx.host.io_guest_mem_read(gpa, dst);
            match res {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_guest_mem_write",
        move |mut caller: Caller<'_, T>, gpa: u64, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    ctx.memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            let res = ctx.host.io_guest_mem_write(gpa, src);
            match res {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_virtio_irq",
        move |mut caller: Caller<'_, T>, dev: Handle, irq_kind: u32, queue_index: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let kind = if irq_kind == IRQ_KIND_CONFIG {
                VirtioIrqKind::Config
            } else {
                VirtioIrqKind::Queue(queue_index as u16)
            };
            match ctx.host.io_virtio_irq(dev, kind) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_serial_push_rx",
        move |mut caller: Caller<'_, T>, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut bytes = vec![0u8; len as usize];
            if let Err(e) = read_bytes(&ctx.memory, src_ptr, &mut bytes) {
                return ctx.set_err(e);
            }
            match ctx.host.io_serial_push_rx(&bytes) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    Ok(())
}

#[derive(Clone)]
struct WasiThreadConfig {
    config_filename: String,
    preopen_dirs: Vec<(PathBuf, String)>,
}

impl WasiThreadConfig {
    fn new(config_filename: &str) -> Self {
        let mut dirs: Vec<(PathBuf, String)> = Vec::new();

        let mut add_dir = |p: &Path| {
            if p.is_dir()
                && let Some(s) = p.to_str()
                && !dirs.iter().any(|(_, guest)| guest == s)
            {
                dirs.push((p.to_path_buf(), s.to_string()));
            }
        };

        if let Ok(cwd) = std::env::current_dir() {
            add_dir(&cwd);
        }

        if let Some(parent) = Path::new(config_filename)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            add_dir(parent);
        }

        add_dir(Path::new("/tmp"));

        Self {
            config_filename: config_filename.to_string(),
            preopen_dirs: dirs,
        }
    }

    fn build_p1(&self) -> wasmtime::Result<WasiP1Ctx> {
        let mut builder = WasiCtxBuilder::new();
        builder
            .allow_blocking_current_thread(true)
            .inherit_stdio()
            .args(&["vmm-io", "-c", &self.config_filename])
            .inherit_env();
        for (host_path, guest_path) in &self.preopen_dirs {
            let _ = builder.preopened_dir(host_path, guest_path, FsPerms::ReadWrite);
        }
        let _ = builder.preopened_dir(".", ".", FsPerms::ReadWrite);
        Ok(builder.build_p1())
    }
}

struct IoStoreState<H: VmmHostIo + ?Sized> {
    wasi: WasiP1Ctx,
    io: IoWasmCtx<H>,
}

/// Instantiate and execute `vmm-io` against any [`VmmHostIo`] implementation.
pub fn run_wasm_io<H: VmmHostIo + ?Sized>(
    module_path: &Path,
    config_filename: &str,
    host: Arc<H>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.wasm_threads(true);
    config.shared_memory(true);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    #[cfg(feature = "compiler")]
    config.target(env!("VMM_HOST_TARGET"))?;
    let engine = Engine::new(&config)?;

    #[cfg(feature = "compiler")]
    let module = {
        let wasm_bytes = std::fs::read(module_path)?;
        crate::verify_no_fp::validate_wasm_no_fp(&wasm_bytes)
            .map_err(|e| format!("Wasm FP/SIMD validation failed for {module_path:?}: {e}"))?;
        let module = Module::new(&engine, &wasm_bytes)?;
        let compiled_bytes = module.serialize()?;
        crate::verify_no_fp::validate_cwasm_no_fp(&compiled_bytes).map_err(|e| {
            format!("JIT machine-code FP/SIMD validation failed for {module_path:?}: {e}")
        })?;
        module
    };
    #[cfg(not(feature = "compiler"))]
    let module = {
        let cwasm_bytes = std::fs::read(module_path)?;
        crate::verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes)
            .map_err(|e| format!("cwasm FP/SIMD validation failed for {module_path:?}: {e}"))?;
        unsafe { Module::deserialize(&engine, &cwasm_bytes)? }
    };

    let memory_ty = module
        .imports()
        .find_map(|imp| {
            if imp.module() == "env"
                && imp.name() == "memory"
                && let ExternType::Memory(ty) = imp.ty()
            {
                Some(ty)
            } else {
                None
            }
        })
        .unwrap_or_else(|| MemoryType::shared(17, 16384));

    let shared_memory = SharedMemory::new(&engine, memory_ty)?;
    let wasi_config = Arc::new(WasiThreadConfig::new(config_filename));

    let mut store = Store::new(
        &engine,
        IoStoreState {
            wasi: wasi_config.build_p1()?,
            io: IoWasmCtx::new(host, shared_memory.clone()),
        },
    );

    let mut linker = Linker::<IoStoreState<H>>::new(&engine);
    linker.define(&store, "env", "memory", shared_memory)?;
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_io_imports(&mut linker, |state| &mut state.io)?;

    let next_tid = Arc::new(AtomicI32::new(1));
    let spawn_engine = engine.clone();
    let spawn_module = module.clone();
    let spawn_wasi_config = wasi_config.clone();

    let spawn_linker_slot: Arc<RwLock<Option<Linker<IoStoreState<H>>>>> =
        Arc::new(RwLock::new(None));
    let spawn_linker_ref = spawn_linker_slot.clone();

    linker.func_wrap(
        "wasi",
        "thread-spawn",
        move |caller: Caller<'_, IoStoreState<H>>, start_arg: i32| -> i32 {
            let tid = next_tid
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(if v >= 0x1fff_fffe { 1 } else { v + 1 })
                })
                .unwrap();

            let engine = spawn_engine.clone();
            let module = spawn_module.clone();
            let linker_opt = spawn_linker_ref.read().clone();
            let Some(child_linker) = linker_opt else {
                return -1;
            };
            let wasi_ctx = match spawn_wasi_config.build_p1() {
                Ok(c) => c,
                Err(_) => return -1,
            };
            let child_host = caller.data().io.host.clone();
            let memory = caller.data().io.memory.clone();

            let spawn_res = std::thread::Builder::new()
                .name(format!("io_wasm_thread_{tid}"))
                .spawn(move || {
                    let mut child_store = Store::new(
                        &engine,
                        IoStoreState {
                            wasi: wasi_ctx,
                            io: IoWasmCtx::new(child_host, memory),
                        },
                    );
                    let instance = match child_linker.instantiate(&mut child_store, &module) {
                        Ok(inst) => inst,
                        Err(e) => {
                            log::error!("failed to instantiate io module on thread {tid}: {e}");
                            return;
                        }
                    };
                    let start_fn = match instance
                        .get_typed_func::<(i32, i32), ()>(&mut child_store, "wasi_thread_start")
                    {
                        Ok(f) => f,
                        Err(e) => {
                            log::error!("missing wasi_thread_start export on thread {tid}: {e}");
                            return;
                        }
                    };
                    if let Err(e) = start_fn.call(&mut child_store, (tid, start_arg))
                        && e.downcast_ref::<I32Exit>().is_none_or(|c| c.0 != 0)
                    {
                        log::error!("wasi_thread_start on thread {tid} trapped: {e}");
                    }
                });

            match spawn_res {
                Ok(_) => tid,
                Err(_) => -1,
            }
        },
    )?;

    *spawn_linker_slot.write() = Some(linker.clone());

    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    if let Err(err) = start.call(&mut store, ()) {
        if let Some(exit) = err.downcast_ref::<I32Exit>()
            && exit.0 == 0
        {
            return Ok(());
        }
        return Err(err.into());
    }

    Ok(())
}
