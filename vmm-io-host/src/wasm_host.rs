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

use vmm_io::host::abi::{
    ERR_EOF, ERR_GENERIC, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXEC_TYPE_LINUX, EXEC_TYPE_PVH,
    IO_BRIDGE_EVENT_POLL, IO_BRIDGE_EVENT_SERIAL_INPUT, IO_BRIDGE_EVENT_SERIAL_TX,
    IO_BRIDGE_EVENT_SHUTDOWN, IO_BRIDGE_EVENT_VIRTIO_CONFIG_WRITE, IO_BRIDGE_EVENT_VIRTIO_NOTIFY,
    IO_BRIDGE_EVENT_VIRTIO_RESET, IO_BRIDGE_EVENT_VIRTIO_START, IRQ_KIND_CONFIG,
    MAX_QUEUES_PER_DEV, RawIoBootConfig, RawIoBridgeEvent, ShmVirtioDeviceSpec,
    ShmVirtioQueueConfig,
};
use vmm_io::host::{
    ExecKind, Handle, Interest, IoBootConfig, IoBridgeEvent, Token, VirtioDeviceSpec,
    VirtioIrqKind,
};
use vmm_io::virtio::dev::net::NetFeature;
use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

/// Host interface trait for the I/O domain (`vmm-io-host`): TAP, block files, serial, and bridge.
///
/// All `"vmm"::*` host imports registered by [`register_io_imports`] delegate exclusively
/// to this trait, allowing alternate host implementations (Linux KVM Ring 3, Motor OS Ring 3).
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

/// ABI context binding a [`VmmHostIo`] implementation and `vmm-io` exported `Memory` to a store.
pub struct IoWasmCtx<H: VmmHostIo + ?Sized> {
    host: Arc<H>,
    memory: Option<Memory>,
    last_error: String,
}

impl<H: VmmHostIo + ?Sized> IoWasmCtx<H> {
    pub fn new(host: Arc<H>) -> Self {
        Self {
            host,
            memory: None,
            last_error: String::new(),
        }
    }

    pub fn set_memory(&mut self, memory: Memory) {
        self.memory = Some(memory);
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

fn slice_bounds(mem_len: usize, ptr: u32, len: usize) -> Result<(usize, usize), String> {
    let start = ptr as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "guest memory address overflow".to_string())?;
    if end > mem_len {
        return Err(format!(
            "guest memory access out of bounds: {start}..{end} > {mem_len}"
        ));
    }
    Ok((start, end))
}

fn read_bytes(mem: &[u8], ptr: u32, dst: &mut [u8]) -> Result<(), String> {
    let (start, end) = slice_bounds(mem.len(), ptr, dst.len())?;
    dst.copy_from_slice(&mem[start..end]);
    Ok(())
}

fn write_bytes(mem: &mut [u8], ptr: u32, src: &[u8]) -> Result<(), String> {
    let (start, end) = slice_bounds(mem.len(), ptr, src.len())?;
    mem[start..end].copy_from_slice(src);
    Ok(())
}

fn read_struct<T: FromBytes + Copy>(mem: &[u8], ptr: u32) -> Result<T, String> {
    let size = std::mem::size_of::<T>();
    let (start, end) = slice_bounds(mem.len(), ptr, size)?;
    T::read_from(&mem[start..end])
        .ok_or_else(|| "failed to decode struct from guest memory".to_string())
}

fn write_struct<T: AsBytes>(mem: &mut [u8], ptr: u32, val: &T) -> Result<(), String> {
    write_bytes(mem, ptr, val.as_bytes())
}

fn read_vec<T: FromBytes + Copy>(mem: &[u8], ptr: u32, count: u32) -> Result<Vec<T>, String> {
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

fn mem_and_ctx<'a, T: 'static, H: VmmHostIo + ?Sized>(
    caller: &'a mut Caller<'_, T>,
    get_ctx: impl Fn(&mut T) -> &mut IoWasmCtx<H>,
) -> Option<(&'a mut [u8], &'a mut IoWasmCtx<H>)> {
    let mem = get_ctx(caller.data_mut()).memory?;
    let (data, store_data) = mem.data_and_store_mut(caller);
    Some((data, get_ctx(store_data)))
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return ERR_GENERIC;
            };
            let err_bytes = ctx.last_error.as_bytes();
            let n = err_bytes.len().min(dst_len as usize);
            if write_bytes(mem, dst_ptr, &err_bytes[..n]).is_err() {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err_i64("guest memory not initialized");
            };
            let if_name = if has_name != 0 {
                let mut buf = vec![0u8; name_len as usize];
                if let Err(e) = read_bytes(mem, name_ptr, &mut buf) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), dst_ptr, max_len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.tap_read(tap, &mut mem[start..end]) {
                Ok(n) => n as i32,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_write",
        move |mut caller: Caller<'_, T>, tap: Handle, src_ptr: u32, len: u32| -> i32 {
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), src_ptr, len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.tap_write(tap, &mem[start..end]) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err_i64("guest memory not initialized");
            };
            let mut buf = vec![0u8; path_len as usize];
            if let Err(e) = read_bytes(mem, path_ptr, &mut buf) {
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
            if let Err(e) = write_struct(mem, size_out_ptr, &len) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), dst_ptr, len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.blk_read_at(blk, offset, &mut mem[start..end]) {
                Ok(n) => n as i32,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_write_at",
        move |mut caller: Caller<'_, T>, blk: Handle, offset: u64, src_ptr: u32, len: u32| -> i32 {
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), src_ptr, len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.blk_write_at(blk, offset, &mem[start..end]) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let mut buf = vec![0u8; max_len as usize];
            match ctx.host.serial_read_input(serial, &mut buf) {
                Ok(None) => ERR_EOF,
                Ok(Some(n)) => {
                    if let Err(e) = write_bytes(mem, dst_ptr, &buf[..n]) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let raw_boot = match read_struct::<RawIoBootConfig>(mem, boot_cfg_ptr) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            let raw_devs = match read_vec::<ShmVirtioDeviceSpec>(mem, devs_ptr, num_devs) {
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
                        pci_bdf: d.pci_bdf,
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
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
                IoBridgeEvent::VirtioConfigWrite { dev, offset, data } => {
                    let len = data.len().min(40);
                    let mut raw_ev = RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_VIRTIO_CONFIG_WRITE,
                        dev,
                        queue_index: offset,
                        tx_len: len as u8,
                        ..Default::default()
                    };
                    raw_ev.tx_bytes[..len].copy_from_slice(&data[..len]);
                    raw_ev
                }
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
            if let Err(e) = write_struct(mem, event_out_ptr, &raw) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), dst_ptr, len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.io_guest_mem_read(gpa, &mut mem[start..end]) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_guest_mem_write",
        move |mut caller: Caller<'_, T>, gpa: u64, src_ptr: u32, len: u32| -> i32 {
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), src_ptr, len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.io_guest_mem_write(gpa, &mem[start..end]) {
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
            let Some((mem, ctx)) = mem_and_ctx(&mut caller, get_ctx) else {
                return get_ctx(caller.data_mut()).set_err("guest memory not initialized");
            };
            let (start, end) = match slice_bounds(mem.len(), src_ptr, len as usize) {
                Ok(b) => b,
                Err(e) => return ctx.set_err(e),
            };
            match ctx.host.io_serial_push_rx(&mem[start..end]) {
                Ok(()) => 0,
                Err(e) => ctx.set_io_err(e),
            }
        },
    )?;

    Ok(())
}

struct WasiIoConfig {
    config_filename: String,
    preopen_dirs: Vec<(PathBuf, String)>,
}

impl WasiIoConfig {
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

        for dir in ["/tmp", "/none/tmp", "/user/tmp", "/vm", "/system"] {
            add_dir(Path::new(dir));
        }

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
        #[cfg(target_os = "motor")]
        if std::env::var_os("VMM_ESCAPE_BYTE").is_none() {
            builder.env("VMM_ESCAPE_BYTE", "0x02");
        }
        for (host_path, guest_path) in &self.preopen_dirs {
            if builder
                .preopened_dir(host_path, guest_path, FsPerms::ReadWrite)
                .is_err()
            {
                let _ = builder.preopened_dir(host_path, guest_path, FsPerms::ReadOnly);
            }
        }
        if builder.preopened_dir(".", ".", FsPerms::ReadWrite).is_err() {
            let _ = builder.preopened_dir(".", ".", FsPerms::ReadOnly);
        }
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
    run_wasm_io_with_config(module_path, config_filename, host, |_| Ok(()))
}

/// Instantiate and execute `vmm-io` with an optional platform-specific [`Config`] hook.
pub fn run_wasm_io_with_config<H: VmmHostIo + ?Sized>(
    module_path: &Path,
    config_filename: &str,
    host: Arc<H>,
    configure_engine: impl FnOnce(&mut Config) -> wasmtime::Result<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    #[cfg(feature = "compiler")]
    config.target(env!("VMM_HOST_TARGET"))?;
    configure_engine(&mut config)?;
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

    let wasi_config = WasiIoConfig::new(config_filename);
    let mut store = Store::new(
        &engine,
        IoStoreState {
            wasi: wasi_config.build_p1()?,
            io: IoWasmCtx::new(host),
        },
    );

    let mut linker = Linker::<IoStoreState<H>>::new(&engine);
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_io_imports(&mut linker, |state| &mut state.io)?;

    let instance = linker.instantiate(&mut store, &module)?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or("vmm-io module does not export linear `memory`")?;
    store.data_mut().io.set_memory(memory);

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
