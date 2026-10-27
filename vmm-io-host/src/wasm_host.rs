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

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, IoSlice, IoSliceMut, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, c_void, ftruncate, mmap, read, write};
use mio::unix::SourceFd;
use parking_lot::{Mutex, RwLock};
use vmm_core::host::abi::{
    BridgeShm, CORE_MSG_SERIAL_TX, CORE_MSG_SHUTDOWN, CORE_MSG_VIRTIO_NOTIFY,
    CORE_MSG_VIRTIO_RESET, CORE_MSG_VIRTIO_START, IO_MSG_REQUEST_SHUTDOWN, IO_MSG_SERIAL_RX,
    IO_MSG_VIRTIO_IRQ, IoToCoreEntry, MAX_QUEUES_PER_DEV, MAX_RAM_SLOTS, MAX_VIRTIO_DEVS,
    ShmBootInfo, spin_lock, spin_unlock,
};
use vmm_io::host::abi::{
    ERR_EOF, ERR_GENERIC, ERR_INTERRUPTED, ERR_WOULD_BLOCK, IO_BRIDGE_EVENT_POLL,
    IO_BRIDGE_EVENT_SERIAL_INPUT, IO_BRIDGE_EVENT_SERIAL_TX, IO_BRIDGE_EVENT_SHUTDOWN,
    IO_BRIDGE_EVENT_VIRTIO_NOTIFY, IO_BRIDGE_EVENT_VIRTIO_RESET, IO_BRIDGE_EVENT_VIRTIO_START,
    IRQ_KIND_CONFIG, IRQ_KIND_QUEUE, RawIoBootConfig, RawIoBridgeEvent, ShmVirtioDeviceSpec,
    ShmVirtioQueueConfig,
};
use vmm_io::host::{
    Handle, Interest, IoBootConfig, IoBridgeEvent, PollEvent, SerialConsole, Tap, Token,
    VirtioDeviceSpec, VirtioIrqKind,
};
use vmm_io::virtio::dev::net::NetFeature;
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

use crate::serial::HostSerialConsole;
use crate::tap::HostTap;

const TOKEN_SHUTDOWN_POLLER: mio::Token = mio::Token(usize::MAX);
const TOKEN_SERIAL_STDIN: mio::Token = mio::Token(usize::MAX - 1);
const TOKEN_CORE_BRIDGE: mio::Token = mio::Token(usize::MAX - 2);

/// Host trait for the I/O domain (`vmm-io-host`): TAP, block files, serial, and bridge.
pub trait VmmHostIo: Send + Sync + 'static {
    fn last_error(&self) -> String;

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

struct ResourceTable<T: ?Sized> {
    next_id: AtomicU64,
    items: RwLock<HashMap<Handle, Arc<T>>>,
}

impl<T: ?Sized> Default for ResourceTable<T> {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            items: RwLock::new(HashMap::new()),
        }
    }
}

impl<T> ResourceTable<T> {
    fn insert(&self, val: T) -> Handle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.items.write().insert(id, Arc::new(val));
        id
    }
}

impl<T: ?Sized> ResourceTable<T> {
    fn get(&self, id: Handle) -> Result<Arc<T>, String> {
        self.items
            .read()
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("invalid resource handle {id}"))
    }

    fn remove(&self, id: Handle) {
        self.items.write().remove(&id);
    }
}

pub struct IoBridgeFds {
    pub bridge_fd: RawFd,
    pub ram_fd: RawFd,
    pub payload_fd: RawFd,
    pub c2i_fd: RawFd,
    pub i2c_fd: RawFd,
    pub cfg_fd: RawFd,
}

struct IoPoller {
    poll: mio::Poll,
    events: mio::Events,
    pending: VecDeque<RawIoBridgeEvent>,
}

pub struct SharedIoHostResources {
    pub shm: *mut BridgeShm,
    pub ram_fd: RawFd,
    pub payload_fd: RawFd,
    pub c2i_fd: RawFd,
    pub i2c_fd: RawFd,
    pub cfg_fd: RawFd,
    pub ram_base: AtomicU64,
    pub ram_len: AtomicU64,
    registry: mio::Registry,
    poll_waker: mio::Waker,
    io_shutdown: AtomicBool,
    io_poller: Mutex<IoPoller>,
    taps: ResourceTable<Mutex<Box<dyn Tap>>>,
    blocks: ResourceTable<File>,
    serials: ResourceTable<Box<dyn SerialConsole>>,
}

unsafe impl Send for SharedIoHostResources {}
unsafe impl Sync for SharedIoHostResources {}

impl SharedIoHostResources {
    pub fn new(fds: IoBridgeFds) -> io::Result<Arc<Self>> {
        let shm_size = std::mem::size_of::<BridgeShm>();
        let ptr = unsafe {
            mmap(
                null_mut(),
                shm_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fds.bridge_fd,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let poll = mio::Poll::new()?;
        let registry = poll.registry().try_clone()?;
        let poll_waker = mio::Waker::new(poll.registry(), TOKEN_SHUTDOWN_POLLER)?;

        let mut c2i_raw = fds.c2i_fd;
        registry.register(
            &mut SourceFd(&mut c2i_raw),
            TOKEN_CORE_BRIDGE,
            mio::Interest::READABLE,
        )?;

        Ok(Arc::new(Self {
            shm: ptr as *mut BridgeShm,
            ram_fd: fds.ram_fd,
            payload_fd: fds.payload_fd,
            c2i_fd: fds.c2i_fd,
            i2c_fd: fds.i2c_fd,
            cfg_fd: fds.cfg_fd,
            ram_base: AtomicU64::new(0),
            ram_len: AtomicU64::new(0),
            registry,
            poll_waker,
            io_shutdown: AtomicBool::new(false),
            io_poller: Mutex::new(IoPoller {
                poll,
                events: mio::Events::with_capacity(128),
                pending: VecDeque::new(),
            }),
            taps: ResourceTable::default(),
            blocks: ResourceTable::default(),
            serials: ResourceTable::default(),
        }))
    }

    pub fn wake_core(&self) {
        let val = 1u64;
        unsafe {
            let _ = write(self.i2c_fd, &val as *const u64 as *const c_void, 8);
        }
    }

    pub fn wake_cfg(&self) {
        let val = 1u64;
        unsafe {
            let _ = write(self.cfg_fd, &val as *const u64 as *const c_void, 8);
        }
    }

    fn drain_c2i_ring(&self, pending: &mut VecDeque<RawIoBridgeEvent>) {
        let shm = self.shm;
        while let Some(entry) = unsafe { BridgeShm::pop_core_to_io(shm) } {
            match entry.msg_type {
                CORE_MSG_VIRTIO_START => {
                    let dev_idx = entry.dev as usize;
                    let nq = (entry.aux_u16 as usize).min(MAX_QUEUES_PER_DEV);
                    let mut raw_ev = RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_VIRTIO_START,
                        num_queues: nq as u16,
                        dev: entry.dev,
                        driver_features: entry.features,
                        ..Default::default()
                    };
                    if dev_idx < MAX_VIRTIO_DEVS {
                        for i in 0..nq {
                            let q = unsafe { (*shm).device_queues[dev_idx][i] };
                            raw_ev.queues[i] = ShmVirtioQueueConfig {
                                size: q.size,
                                enabled: q.enabled,
                                _pad: 0,
                                desc_gpa: q.desc_gpa,
                                avail_gpa: q.avail_gpa,
                                used_gpa: q.used_gpa,
                            };
                        }
                    }
                    pending.push_back(raw_ev);
                }
                CORE_MSG_VIRTIO_NOTIFY => {
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_VIRTIO_NOTIFY,
                        dev: entry.dev,
                        queue_index: entry.aux_u16,
                        ..Default::default()
                    });
                }
                CORE_MSG_VIRTIO_RESET => {
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_VIRTIO_RESET,
                        dev: entry.dev,
                        ..Default::default()
                    });
                }
                CORE_MSG_SERIAL_TX => {
                    let len = (entry.aux_u16 as usize).min(entry.data.len());
                    let mut raw_ev = RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_SERIAL_TX,
                        tx_len: len as u8,
                        ..Default::default()
                    };
                    raw_ev.tx_bytes[..len].copy_from_slice(&entry.data[..len]);
                    pending.push_back(raw_ev);
                }
                CORE_MSG_SHUTDOWN => {
                    self.io_shutdown.store(true, Ordering::Release);
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_SHUTDOWN,
                        ..Default::default()
                    });
                }
                _ => {}
            }
        }
    }

    fn next_raw_event(&self) -> io::Result<RawIoBridgeEvent> {
        let mut poller = self.io_poller.lock();
        loop {
            self.drain_c2i_ring(&mut poller.pending);
            if let Some(ev) = poller.pending.pop_front() {
                return Ok(ev);
            }
            if self.io_shutdown.load(Ordering::Acquire)
                || unsafe { (*self.shm).shutdown_requested.load(Ordering::Acquire) != 0 }
            {
                return Ok(RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_SHUTDOWN,
                    ..Default::default()
                });
            }

            let IoPoller {
                poll,
                events,
                pending,
            } = &mut *poller;
            match poll.poll(events, None) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            for event in events.iter() {
                if event.token() == TOKEN_SHUTDOWN_POLLER {
                    self.io_shutdown.store(true, Ordering::Release);
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_SHUTDOWN,
                        ..Default::default()
                    });
                } else if event.token() == TOKEN_CORE_BRIDGE {
                    let mut val = 0u64;
                    let _ = unsafe { read(self.c2i_fd, &mut val as *mut u64 as *mut c_void, 8) };
                    self.drain_c2i_ring(pending);
                } else if event.token() == TOKEN_SERIAL_STDIN {
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_SERIAL_INPUT,
                        ..Default::default()
                    });
                } else {
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_POLL,
                        token: event.token().0 as u64,
                        is_readable: u8::from(event.is_readable()),
                        is_writable: u8::from(event.is_writable()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn translate_gpa_chunk(&self, gpa: u64, max_len: usize) -> Result<(*mut u8, usize), String> {
        let rbase = self.ram_base.load(Ordering::Acquire) as usize;
        let rlen = self.ram_len.load(Ordering::Acquire) as usize;
        if rbase == 0 {
            return Err("guest RAM not yet mapped in vmm-io-host".to_string());
        }
        let shm = self.shm;
        let lock = unsafe { &(*shm).ram_slots_lock };
        spin_lock(lock);
        let slots = unsafe { (*shm).ram_slots };
        spin_unlock(lock);

        for slot in slots.iter().take(MAX_RAM_SLOTS) {
            if slot.active != 0 && gpa >= slot.gpa && gpa < slot.gpa + slot.size {
                let off_in_slot = (gpa - slot.gpa) as usize;
                let avail_in_slot = (slot.size as usize) - off_in_slot;
                let chunk_len = max_len.min(avail_in_slot);
                let shm_off = (slot.shm_offset as usize) + off_in_slot;
                if shm_off.checked_add(chunk_len).map_or(true, |end| end > rlen) {
                    return Err(format!("GPA {gpa:#x} exceeds shared RAM arena"));
                }
                return Ok(((rbase + shm_off) as *mut u8, chunk_len));
            }
        }
        Err(format!("unmapped guest physical address {gpa:#x}"))
    }

    fn read_guest_mem(&self, mut gpa: u64, mut dst: &mut [u8]) -> Result<(), String> {
        while !dst.is_empty() {
            let (src_ptr, chunk) = self.translate_gpa_chunk(gpa, dst.len())?;
            unsafe {
                std::ptr::copy_nonoverlapping(src_ptr as *const u8, dst.as_mut_ptr(), chunk);
            }
            gpa += chunk as u64;
            dst = &mut dst[chunk..];
        }
        Ok(())
    }

    fn write_guest_mem(&self, mut gpa: u64, mut src: &[u8]) -> Result<(), String> {
        while !src.is_empty() {
            let (dst_ptr, chunk) = self.translate_gpa_chunk(gpa, src.len())?;
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr, chunk);
            }
            gpa += chunk as u64;
            src = &src[chunk..];
        }
        Ok(())
    }
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

pub struct ThreadHostState {
    wasi: WasiP1Ctx,
    shared: Arc<SharedIoHostResources>,
    memory: SharedMemory,
    last_error: String,
}

impl ThreadHostState {
    fn set_err(&mut self, msg: impl Into<String>) -> i32 {
        self.last_error = msg.into();
        ERR_GENERIC
    }

    fn set_err_i64(&mut self, msg: impl Into<String>) -> i64 {
        self.last_error = msg.into();
        ERR_GENERIC as i64
    }

    fn set_io_err(&mut self, e: io::Error) -> i32 {
        match e.kind() {
            io::ErrorKind::WouldBlock => ERR_WOULD_BLOCK,
            io::ErrorKind::Interrupted => ERR_INTERRUPTED,
            _ => {
                self.last_error = e.to_string();
                ERR_GENERIC
            }
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

fn register_io_imports(linker: &mut Linker<ThreadHostState>) -> wasmtime::Result<()> {
    linker.func_wrap(
        "vmm",
        "vmm_last_error_len",
        |caller: Caller<'_, ThreadHostState>| -> u32 { caller.data().last_error.len() as u32 },
    )?;

    linker.func_wrap(
        "vmm",
        "vmm_last_error_read",
        |caller: Caller<'_, ThreadHostState>, dst_ptr: u32, dst_len: u32| -> i32 {
            let err_bytes = caller.data().last_error.as_bytes();
            let n = err_bytes.len().min(dst_len as usize);
            if write_bytes(&caller.data().memory, dst_ptr, &err_bytes[..n]).is_err() {
                return ERR_GENERIC;
            }
            n as i32
        },
    )?;

    // --- TAP Device Imports ---
    linker.func_wrap(
        "vmm",
        "tap_open",
        |mut caller: Caller<'_, ThreadHostState>,
         has_name: u32,
         name_ptr: u32,
         name_len: u32|
         -> i64 {
            let if_name = if has_name != 0 {
                let mut buf = vec![0u8; name_len as usize];
                if let Err(e) = read_bytes(&caller.data().memory, name_ptr, &mut buf) {
                    return caller.data_mut().set_err_i64(e);
                }
                match String::from_utf8(buf) {
                    Ok(s) => Some(s),
                    Err(e) => return caller.data_mut().set_err_i64(e.to_string()),
                }
            } else {
                None
            };
            let registry = match caller.data().shared.registry.try_clone() {
                Ok(r) => r,
                Err(e) => return caller.data_mut().set_io_err_i64(e),
            };
            match HostTap::new(if_name.as_deref(), registry) {
                Ok(tap) => {
                    let boxed: Box<dyn Tap> = Box::new(tap);
                    caller.data().shared.taps.insert(Mutex::new(boxed)) as i64
                }
                Err(e) => caller.data_mut().set_io_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_detected_offload",
        |caller: Caller<'_, ThreadHostState>, tap: Handle| -> u64 {
            match caller.data().shared.taps.get(tap) {
                Ok(t) => t.lock().detected_offload().bits(),
                Err(_) => 0,
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_enable_offload",
        |mut caller: Caller<'_, ThreadHostState>, tap: Handle, feature: u64| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let res = t
                .lock()
                .enable_offload(NetFeature::from_bits_retain(feature));
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_register",
        |mut caller: Caller<'_, ThreadHostState>, tap: Handle, token: u64, interests: u32| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let res = t
                .lock()
                .register(Token(token), Interest::from_bits_retain(interests as u8));
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_deregister",
        |caller: Caller<'_, ThreadHostState>, tap: Handle| {
            if let Ok(t) = caller.data().shared.taps.get(tap) {
                t.lock().deregister();
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_read",
        |mut caller: Caller<'_, ThreadHostState>,
         tap: Handle,
         dst_ptr: u32,
         max_len: u32|
         -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, dst_ptr, max_len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    caller.data().memory.data().as_ptr().add(start) as *mut u8,
                    max_len as usize,
                )
            };
            let res = t.lock().read_vectored(&mut [IoSliceMut::new(dst)]);
            match res {
                Ok(n) => n as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_write",
        |mut caller: Caller<'_, ThreadHostState>, tap: Handle, src_ptr: u32, len: u32| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    caller.data().memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            let res = t.lock().write_vectored(&[IoSlice::new(src)]);
            match res {
                Ok(n) => n as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_close",
        |caller: Caller<'_, ThreadHostState>, tap: Handle| {
            caller.data().shared.taps.remove(tap);
        },
    )?;

    // --- Block Device File Imports ---
    linker.func_wrap(
        "vmm",
        "blk_open",
        |mut caller: Caller<'_, ThreadHostState>,
         path_ptr: u32,
         path_len: u32,
         read_only: u32,
         size_out_ptr: u32|
         -> i64 {
            let mut buf = vec![0u8; path_len as usize];
            if let Err(e) = read_bytes(&caller.data().memory, path_ptr, &mut buf) {
                return caller.data_mut().set_err_i64(e);
            }
            let path_str = match String::from_utf8(buf) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err_i64(e.to_string()),
            };
            let file = match OpenOptions::new()
                .read(true)
                .write(read_only == 0)
                .open(&path_str)
            {
                Ok(f) => f,
                Err(e) => return caller.data_mut().set_io_err_i64(e),
            };
            let len = match file.metadata() {
                Ok(m) => m.len(),
                Err(e) => return caller.data_mut().set_io_err_i64(e),
            };
            if let Err(e) = write_struct(&caller.data().memory, size_out_ptr, &len) {
                return caller.data_mut().set_err_i64(e);
            }
            caller.data().shared.blocks.insert(file) as i64
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_read_at",
        |mut caller: Caller<'_, ThreadHostState>,
         blk: Handle,
         offset: u64,
         dst_ptr: u32,
         len: u32|
         -> i32 {
            let file = match caller.data().shared.blocks.get(blk) {
                Ok(f) => f,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    caller.data().memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            match file.read_exact_at(dst, offset) {
                Ok(()) => len as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_write_at",
        |mut caller: Caller<'_, ThreadHostState>,
         blk: Handle,
         offset: u64,
         src_ptr: u32,
         len: u32|
         -> i32 {
            let file = match caller.data().shared.blocks.get(blk) {
                Ok(f) => f,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    caller.data().memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            match file.write_all_at(src, offset) {
                Ok(()) => len as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_flush",
        |mut caller: Caller<'_, ThreadHostState>, blk: Handle| -> i32 {
            let file = match caller.data().shared.blocks.get(blk) {
                Ok(f) => f,
                Err(e) => return caller.data_mut().set_err(e),
            };
            match file.sync_data() {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "blk_close",
        |caller: Caller<'_, ThreadHostState>, blk: Handle| {
            caller.data().shared.blocks.remove(blk);
        },
    )?;

    // --- Serial Console Imports ---
    linker.func_wrap(
        "vmm",
        "serial_open",
        |mut caller: Caller<'_, ThreadHostState>| -> i64 {
            let registry = match caller.data().shared.registry.try_clone() {
                Ok(r) => r,
                Err(e) => return caller.data_mut().set_io_err_i64(e),
            };
            match HostSerialConsole::new(registry, TOKEN_SERIAL_STDIN) {
                Ok(s) => {
                    let boxed: Box<dyn SerialConsole> = Box::new(s);
                    caller.data().shared.serials.insert(boxed) as i64
                }
                Err(e) => caller.data_mut().set_io_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_write_byte",
        |mut caller: Caller<'_, ThreadHostState>, serial: Handle, byte: u32| -> i32 {
            let s = match caller.data().shared.serials.get(serial) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            match s.write_byte(byte as u8) {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_read_input",
        |mut caller: Caller<'_, ThreadHostState>,
         serial: Handle,
         dst_ptr: u32,
         max_len: u32|
         -> i32 {
            let s = match caller.data().shared.serials.get(serial) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let mut deque = VecDeque::new();
            match s.read_input(&mut deque) {
                Ok(None) => ERR_EOF,
                Ok(Some(_)) => {
                    let bytes: Vec<u8> = deque.into_iter().take(max_len as usize).collect();
                    if let Err(e) = write_bytes(&caller.data().memory, dst_ptr, &bytes) {
                        return caller.data_mut().set_err(e);
                    }
                    bytes.len() as i32
                }
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_shutdown",
        |mut caller: Caller<'_, ThreadHostState>, serial: Handle| -> i32 {
            let s = match caller.data().shared.serials.get(serial) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            match s.shutdown() {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_close",
        |caller: Caller<'_, ThreadHostState>, serial: Handle| {
            caller.data().shared.serials.remove(serial);
        },
    )?;

    // --- Cross-Split IO <-> Core Bridge Imports ---
    linker.func_wrap(
        "vmm",
        "io_register_vm_config",
        |mut caller: Caller<'_, ThreadHostState>,
         boot_cfg_ptr: u32,
         devs_ptr: u32,
         num_devs: u32|
         -> i32 {
            let raw_boot = match read_struct::<RawIoBootConfig>(&caller.data().memory, boot_cfg_ptr)
            {
                Ok(b) => b,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let raw_devs =
                match read_vec::<ShmVirtioDeviceSpec>(&caller.data().memory, devs_ptr, num_devs) {
                    Ok(d) => d,
                    Err(e) => return caller.data_mut().set_err(e),
                };

            let shared = caller.data().shared.clone();

            // 1. Allocate and map shared Guest RAM arena (`mem_size + 64 MiB`).
            let arena_size = (raw_boot.mem_size as usize) + (64 << 20);
            if unsafe { ftruncate(shared.ram_fd, arena_size as libc::off_t) } != 0 {
                return caller.data_mut().set_io_err(io::Error::last_os_error());
            }
            let rptr = unsafe {
                mmap(
                    null_mut(),
                    arena_size,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    shared.ram_fd,
                    0,
                )
            };
            if rptr == MAP_FAILED {
                return caller.data_mut().set_io_err(io::Error::last_os_error());
            }
            shared.ram_len.store(arena_size as u64, Ordering::Release);
            shared
                .ram_base
                .store(rptr as usize as u64, Ordering::Release);

            // 2. Load kernel and initramfs into `payload_fd`.
            let mut payload_bytes = Vec::new();
            let mut kernel_size = 0u64;
            let mut initramfs_size = 0u64;

            let klen = (raw_boot.kernel_path_len as usize).min(raw_boot.kernel_path.len());
            if klen > 0 {
                let kpath = String::from_utf8_lossy(&raw_boot.kernel_path[..klen]).into_owned();
                match std::fs::read(&kpath) {
                    Ok(kb) => {
                        kernel_size = kb.len() as u64;
                        payload_bytes.extend_from_slice(&kb);
                    }
                    Err(e) => {
                        return caller
                            .data_mut()
                            .set_err(format!("failed to read kernel '{kpath}': {e}"));
                    }
                }
            }

            let ilen = (raw_boot.initramfs_path_len as usize).min(raw_boot.initramfs_path.len());
            if ilen > 0 {
                let ipath = String::from_utf8_lossy(&raw_boot.initramfs_path[..ilen]).into_owned();
                match std::fs::read(&ipath) {
                    Ok(ib) => {
                        initramfs_size = ib.len() as u64;
                        payload_bytes.extend_from_slice(&ib);
                    }
                    Err(e) => {
                        return caller
                            .data_mut()
                            .set_err(format!("failed to read initramfs '{ipath}': {e}"));
                    }
                }
            }

            if !payload_bytes.is_empty() {
                if unsafe { ftruncate(shared.payload_fd, payload_bytes.len() as libc::off_t) } != 0
                {
                    return caller.data_mut().set_io_err(io::Error::last_os_error());
                }
                let mut f = unsafe { std::os::fd::BorrowedFd::borrow_raw(shared.payload_fd) };
                let _ = &mut f;
                let mut written = 0;
                while written < payload_bytes.len() {
                    let rc = unsafe {
                        libc::pwrite(
                            shared.payload_fd,
                            payload_bytes[written..].as_ptr() as *const c_void,
                            payload_bytes.len() - written,
                            written as libc::off_t,
                        )
                    };
                    if rc < 0 {
                        return caller.data_mut().set_io_err(io::Error::last_os_error());
                    }
                    written += rc as usize;
                }
            }

            // 3. Populate `BridgeShm` and signal `config_ready`.
            let shm = shared.shm;
            let ndevs = raw_devs.len().min(MAX_VIRTIO_DEVS);
            let mut boot_info = ShmBootInfo {
                num_cpus: raw_boot.num_cpus,
                exec_type: raw_boot.exec_type,
                mem_size: raw_boot.mem_size,
                kernel_size,
                initramfs_size,
                cmd_line_len: raw_boot.cmd_line_len,
                num_virtio_devs: ndevs as u32,
                cmd_line: raw_boot.cmd_line,
            };
            let _ = &mut boot_info;
            unsafe {
                (*shm).boot_info = boot_info;
                for (i, d) in raw_devs.into_iter().enumerate().take(ndevs) {
                    (*shm).virtio_devs[i] = vmm_core::host::abi::ShmVirtioDeviceSpec {
                        dev: d.dev,
                        device_features: d.device_features,
                        device_id: d.device_id,
                        num_queues: d.num_queues,
                        config_len: d.config_len,
                        name_len: d.name_len,
                        name: d.name,
                        config_bytes: d.config_bytes,
                    };
                }
                (*shm).config_ready.store(1, Ordering::Release);
            }
            shared.wake_cfg();
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_next_event",
        |mut caller: Caller<'_, ThreadHostState>, event_out_ptr: u32| -> i32 {
            let shared = caller.data().shared.clone();
            let raw = match shared.next_raw_event() {
                Ok(ev) => ev,
                Err(e) => return caller.data_mut().set_io_err(e),
            };
            if let Err(e) = write_struct(&caller.data().memory, event_out_ptr, &raw) {
                return caller.data_mut().set_err(e);
            }
            let _ = PollEvent {
                token: Token(0),
                is_readable: false,
                is_writable: false,
            };
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_request_shutdown",
        |caller: Caller<'_, ThreadHostState>| -> i32 {
            let shared = &caller.data().shared;
            shared.io_shutdown.store(true, Ordering::Release);
            unsafe {
                (*shared.shm).shutdown_requested.store(1, Ordering::Release);
            }
            let entry = IoToCoreEntry {
                msg_type: IO_MSG_REQUEST_SHUTDOWN,
                ..Default::default()
            };
            let _ = unsafe { BridgeShm::push_io_to_core(shared.shm, entry) };
            shared.wake_core();
            let _ = shared.poll_waker.wake();
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_guest_mem_read",
        |mut caller: Caller<'_, ThreadHostState>, gpa: u64, dst_ptr: u32, len: u32| -> i32 {
            let start = match check_bounds(&caller.data().memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    caller.data().memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            let res = caller.data().shared.read_guest_mem(gpa, dst);
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_guest_mem_write",
        |mut caller: Caller<'_, ThreadHostState>, gpa: u64, src_ptr: u32, len: u32| -> i32 {
            let start = match check_bounds(&caller.data().memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    caller.data().memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            let res = caller.data().shared.write_guest_mem(gpa, src);
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_virtio_irq",
        |caller: Caller<'_, ThreadHostState>,
         dev: Handle,
         irq_kind: u32,
         queue_index: u32|
         -> i32 {
            let shared = &caller.data().shared;
            let _ = (IRQ_KIND_CONFIG, IRQ_KIND_QUEUE);
            let entry = IoToCoreEntry {
                msg_type: IO_MSG_VIRTIO_IRQ,
                irq_kind: irq_kind as u16,
                queue_index: queue_index as u16,
                dev,
                data: [0; 48],
            };
            if unsafe { BridgeShm::push_io_to_core(shared.shm, entry) } {
                shared.wake_core();
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "io_serial_push_rx",
        |mut caller: Caller<'_, ThreadHostState>, src_ptr: u32, len: u32| -> i32 {
            let mut bytes = vec![0u8; len as usize];
            if let Err(e) = read_bytes(&caller.data().memory, src_ptr, &mut bytes) {
                return caller.data_mut().set_err(e);
            }
            let shared = &caller.data().shared;
            let mut woke = false;
            for chunk in bytes.chunks(48) {
                let mut data = [0u8; 48];
                data[..chunk.len()].copy_from_slice(chunk);
                let entry = IoToCoreEntry {
                    msg_type: IO_MSG_SERIAL_RX,
                    irq_kind: 0,
                    queue_index: chunk.len() as u16,
                    dev: 0,
                    data,
                };
                if unsafe { BridgeShm::push_io_to_core(shared.shm, entry) } {
                    woke = true;
                }
            }
            if woke {
                shared.wake_core();
            }
            let _ = Write::flush(&mut io::stdout());
            0
        },
    )?;

    Ok(())
}

pub fn run_wasm_io(
    module_path: &Path,
    config_filename: &str,
    shared_resources: Arc<SharedIoHostResources>,
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
        ThreadHostState {
            wasi: wasi_config.build_p1()?,
            shared: shared_resources,
            memory: shared_memory.clone(),
            last_error: String::new(),
        },
    );

    let mut linker = Linker::<ThreadHostState>::new(&engine);
    linker.define(&store, "env", "memory", shared_memory)?;
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_io_imports(&mut linker)?;

    let next_tid = Arc::new(AtomicI32::new(1));
    let spawn_engine = engine.clone();
    let spawn_module = module.clone();
    let spawn_wasi_config = wasi_config.clone();

    let spawn_linker_slot: Arc<RwLock<Option<Linker<ThreadHostState>>>> =
        Arc::new(RwLock::new(None));
    let spawn_linker_ref = spawn_linker_slot.clone();

    linker.func_wrap(
        "wasi",
        "thread-spawn",
        move |caller: Caller<'_, ThreadHostState>, start_arg: i32| -> i32 {
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
            let shared = caller.data().shared.clone();
            let memory = caller.data().memory.clone();

            let spawn_res = std::thread::Builder::new()
                .name(format!("io_wasm_thread_{tid}"))
                .spawn(move || {
                    let mut child_store = Store::new(
                        &engine,
                        ThreadHostState {
                            wasi: wasi_ctx,
                            shared,
                            memory,
                            last_error: String::new(),
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
