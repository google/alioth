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

//! Motor OS Ring-3 `VmmHostIo` implementation talking to Ring-0 `tests/kernel/src/vmm/`
//! over shared `SysMem` pages (`BridgeShm` + Guest RAM + payload) and `SysObj` / `SysCpu`.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use moto_sys::{SysCpu, SysHandle, SysMem, SysObj};
use vmm_core::host::abi::{
    BridgeShm, CORE_MSG_SERIAL_TX, CORE_MSG_SHUTDOWN, CORE_MSG_VIRTIO_CONFIG_WRITE,
    CORE_MSG_VIRTIO_NOTIFY, CORE_MSG_VIRTIO_RESET, CORE_MSG_VIRTIO_START, IO_MSG_REQUEST_SHUTDOWN,
    IO_MSG_SERIAL_RX, IO_MSG_VIRTIO_IRQ, IoToCoreEntry, MAX_QUEUES_PER_DEV, MAX_RAM_SLOTS,
    MAX_VIRTIO_DEVS, ShmBootInfo, spin_lock, spin_unlock,
};
use vmm_io::host::abi::{
    EXEC_TYPE_LINUX, EXEC_TYPE_NONE, EXEC_TYPE_PVH, IO_BRIDGE_EVENT_POLL,
    IO_BRIDGE_EVENT_SERIAL_INPUT, IO_BRIDGE_EVENT_SERIAL_TX, IO_BRIDGE_EVENT_SHUTDOWN,
    IO_BRIDGE_EVENT_VIRTIO_CONFIG_WRITE, IO_BRIDGE_EVENT_VIRTIO_NOTIFY,
    IO_BRIDGE_EVENT_VIRTIO_RESET, IO_BRIDGE_EVENT_VIRTIO_START, IRQ_KIND_CONFIG, IRQ_KIND_QUEUE,
    RawIoBridgeEvent, ShmVirtioQueueConfig,
};
use vmm_io::host::{
    ExecKind, Handle, Interest, IoBootConfig, IoBridgeEvent, PollEvent, Token, VirtioDeviceSpec,
    VirtioIrqKind, VirtioQueueConfig,
};
use vmm_io::virtio::dev::net::NetFeature;

use crate::ip_tap::MotorIpTap;
use crate::wasm_host::VmmHostIo;

/// Page-aligned Ring-3 virtual memory arena allocated via `SysMem::alloc`.
struct SysMemArena {
    addr: u64,
    byte_len: usize,
}

impl SysMemArena {
    fn alloc_zeroed(min_bytes: usize) -> io::Result<Self> {
        let aligned = min_bytes
            .max(PAGE_SIZE_SMALL as usize)
            .next_multiple_of(PAGE_SIZE_SMALL as usize);
        let pages = (aligned / PAGE_SIZE_SMALL as usize) as u64;
        let addr = SysMem::alloc(PAGE_SIZE_SMALL, pages)
            .map_err(|e| io::Error::other(format!("SysMem::alloc({pages} pages) failed: {e}")))?;
        unsafe {
            core::ptr::write_bytes(addr as *mut u8, 0, aligned);
        }
        Ok(Self {
            addr,
            byte_len: aligned,
        })
    }

    fn from_slice(src: &[u8]) -> io::Result<Self> {
        let arena = Self::alloc_zeroed(src.len().max(1))?;
        if !src.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr(), arena.addr as *mut u8, src.len());
            }
        }
        Ok(arena)
    }

    fn addr(&self) -> u64 {
        self.addr
    }

    fn byte_len(&self) -> usize {
        self.byte_len
    }
}

impl Drop for SysMemArena {
    fn drop(&mut self) {
        if self.addr != 0 {
            let _ = SysMem::free(self.addr);
            self.addr = 0;
        }
    }
}

struct ResourceTable<T> {
    next_id: AtomicU64,
    items: RwLock<HashMap<Handle, Arc<T>>>,
}

impl<T> Default for ResourceTable<T> {
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
        self.items.write().unwrap().insert(id, Arc::new(val));
        id
    }

    fn get(&self, id: Handle) -> io::Result<Arc<T>> {
        self.items
            .read()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid resource handle"))
    }

    fn remove(&self, id: Handle) {
        self.items.write().unwrap().remove(&id);
    }

    fn values(&self) -> Vec<Arc<T>> {
        self.items.read().unwrap().values().cloned().collect()
    }

    fn clear(&self) -> Vec<Arc<T>> {
        self.items.write().unwrap().drain().map(|(_, v)| v).collect()
    }
}

struct MotorBlock {
    file: Mutex<File>,
    read_only: bool,
}

struct StdinPipe {
    buf: Mutex<VecDeque<u8>>,
    ready: AtomicBool,
    eof: AtomicBool,
    started: AtomicBool,
}

impl StdinPipe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            buf: Mutex::new(VecDeque::with_capacity(256)),
            ready: AtomicBool::new(false),
            eof: AtomicBool::new(false),
            started: AtomicBool::new(false),
        })
    }

    fn ensure_started(self: &Arc<Self>, wake_thread: SysHandle) {
        if std::env::var_os("VMM_NO_STDIN").is_some() {
            return;
        }
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let pipe = Arc::clone(self);
        let _ = thread::Builder::new()
            .name("vmm-stdin".to_string())
            .spawn(move || {
                let mut stdin = io::stdin();
                let mut chunk = [0u8; 64];
                loop {
                    match stdin.read(&mut chunk) {
                        Ok(0) => {
                            pipe.eof.store(true, Ordering::Release);
                            pipe.ready.store(true, Ordering::Release);
                            let _ = SysCpu::wake(wake_thread);
                            break;
                        }
                        Ok(n) => {
                            {
                                let mut q = pipe.buf.lock().unwrap();
                                q.extend(&chunk[..n]);
                            }
                            pipe.ready.store(true, Ordering::Release);
                            let _ = SysCpu::wake(wake_thread);
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            pipe.eof.store(true, Ordering::Release);
                            pipe.ready.store(true, Ordering::Release);
                            let _ = SysCpu::wake(wake_thread);
                            break;
                        }
                    }
                }
            });
    }
}

struct VmMemoryHold {
    _ram: SysMemArena,
    _payload: SysMemArena,
    _cwasm: SysMemArena,
}

pub struct MotorIoHost {
    core_cwasm_path: PathBuf,
    main_thread: SysHandle,
    shm_arena: SysMemArena,
    shm: *mut BridgeShm,
    vm_handle: Mutex<Option<SysHandle>>,
    vm_mem: Mutex<Option<VmMemoryHold>>,
    ram_base: AtomicU64,
    ram_len: AtomicU64,
    io_shutdown: AtomicBool,
    pending_events: Mutex<VecDeque<RawIoBridgeEvent>>,
    stdin_pipe: Arc<StdinPipe>,
    next_tap_idx: AtomicU64,
    taps: ResourceTable<MotorIpTap>,
    blocks: ResourceTable<MotorBlock>,
    serials: ResourceTable<()>,
}

unsafe impl Send for MotorIoHost {}
unsafe impl Sync for MotorIoHost {}

impl MotorIoHost {
    pub fn new(core_cwasm_path: PathBuf) -> io::Result<Arc<Self>> {
        let shm_arena = SysMemArena::alloc_zeroed(core::mem::size_of::<BridgeShm>())?;
        let shm = shm_arena.addr() as *mut BridgeShm;
        Ok(Arc::new(Self {
            core_cwasm_path,
            main_thread: moto_sys::current_thread(),
            shm_arena,
            shm,
            vm_handle: Mutex::new(None),
            vm_mem: Mutex::new(None),
            ram_base: AtomicU64::new(0),
            ram_len: AtomicU64::new(0),
            io_shutdown: AtomicBool::new(false),
            pending_events: Mutex::new(VecDeque::with_capacity(64)),
            stdin_pipe: StdinPipe::new(),
            next_tap_idx: AtomicU64::new(0),
            taps: ResourceTable::default(),
            blocks: ResourceTable::default(),
            serials: ResourceTable::default(),
        }))
    }

    pub fn shutdown(&self) {
        self.io_shutdown.store(true, Ordering::Release);
        for tap in self.taps.clear() {
            tap.close();
        }
        unsafe {
            (*self.shm).shutdown_requested.store(1, Ordering::Release);
        }
        let entry = IoToCoreEntry {
            msg_type: IO_MSG_REQUEST_SHUTDOWN,
            ..Default::default()
        };
        let _ = unsafe { BridgeShm::push_io_to_core(self.shm, entry) };

        if let Some(vm_h) = self.vm_handle.lock().unwrap().take() {
            let _ = SysCpu::wake(vm_h);
            let _ = SysObj::put(vm_h);
        }

        // Release Ring-3 virtual mappings only after `SysObj::put(vm_handle)`.
        self.ram_base.store(0, Ordering::Release);
        self.ram_len.store(0, Ordering::Release);
        let _ = self.vm_mem.lock().unwrap().take();
        let _ = SysCpu::wake(self.main_thread);
    }

    fn wake_core(&self) {
        if let Some(vm_h) = *self.vm_handle.lock().unwrap() {
            let _ = SysCpu::wake(vm_h);
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
                CORE_MSG_VIRTIO_CONFIG_WRITE => {
                    let len = (entry.data[0] as usize).min(8);
                    let mut raw_ev = RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_VIRTIO_CONFIG_WRITE,
                        dev: entry.dev,
                        queue_index: entry.aux_u16,
                        tx_len: len as u8,
                        ..Default::default()
                    };
                    raw_ev.tx_bytes[..len].copy_from_slice(&entry.data[1..1 + len]);
                    pending.push_back(raw_ev);
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
        let mut pending = self.pending_events.lock().unwrap();
        loop {
            self.drain_c2i_ring(&mut pending);
            if self.stdin_pipe.ready.swap(false, Ordering::AcqRel) {
                pending.push_back(RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_SERIAL_INPUT,
                    ..Default::default()
                });
            }
            for tap in self.taps.values() {
                if let Some((token, is_readable, is_writable)) = tap.take_poll_event() {
                    pending.push_back(RawIoBridgeEvent {
                        kind: IO_BRIDGE_EVENT_POLL,
                        token: token.0,
                        is_readable,
                        is_writable,
                        ..Default::default()
                    });
                }
            }
            if let Some(ev) = pending.pop_front() {
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

            let Some(vm_h) = *self.vm_handle.lock().unwrap() else {
                return Ok(RawIoBridgeEvent {
                    kind: IO_BRIDGE_EVENT_SHUTDOWN,
                    ..Default::default()
                });
            };

            drop(pending);
            let mut handles = [vm_h];
            let _ = SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None);
            pending = self.pending_events.lock().unwrap();
        }
    }

    fn translate_gpa_chunk(&self, gpa: u64, max_len: usize) -> Result<(*mut u8, usize), String> {
        let rbase = self.ram_base.load(Ordering::Acquire) as usize;
        let rlen = self.ram_len.load(Ordering::Acquire) as usize;
        if rbase == 0 {
            return Err("guest RAM not yet mapped in motor-io-host".to_string());
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
                if shm_off.checked_add(chunk_len).is_none_or(|end| end > rlen) {
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
                core::ptr::copy_nonoverlapping(src_ptr as *const u8, dst.as_mut_ptr(), chunk);
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
                core::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr, chunk);
            }
            gpa += chunk as u64;
            src = &src[chunk..];
        }
        Ok(())
    }
}

impl Drop for MotorIoHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl VmmHostIo for MotorIoHost {
    fn tap_open(&self, if_name: Option<&str>) -> io::Result<Handle> {
        let idx = self.next_tap_idx.fetch_add(1, Ordering::Relaxed) as usize;
        let tap = MotorIpTap::open(if_name, idx, self.main_thread)?;
        Ok(self.taps.insert(tap))
    }

    fn tap_detected_offload(&self, tap: Handle) -> NetFeature {
        self.taps
            .get(tap)
            .map(|t| t.detected_offload())
            .unwrap_or_else(|_| NetFeature::empty())
    }

    fn tap_enable_offload(&self, _tap: Handle, _feature: NetFeature) -> io::Result<()> {
        Ok(())
    }

    fn tap_register(&self, tap: Handle, token: Token, interests: Interest) -> io::Result<()> {
        let t = self.taps.get(tap)?;
        t.register(token, interests)
    }

    fn tap_deregister(&self, tap: Handle) {
        if let Ok(t) = self.taps.get(tap) {
            t.deregister();
        }
    }

    fn tap_read(&self, tap: Handle, dst: &mut [u8]) -> io::Result<usize> {
        let t = self.taps.get(tap)?;
        t.read_frame(dst)
    }

    fn tap_write(&self, tap: Handle, src: &[u8]) -> io::Result<usize> {
        let t = self.taps.get(tap)?;
        t.write_frame(src)
    }

    fn tap_close(&self, tap: Handle) {
        if let Ok(t) = self.taps.get(tap) {
            t.close();
        }
        self.taps.remove(tap);
    }

    fn blk_open(&self, path: &Path, read_only: bool) -> io::Result<(Handle, u64)> {
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to open block image '{}': {e}", path.display()),
                )
            })?;
        let len = file.metadata()?.len();
        let handle = self.blocks.insert(MotorBlock {
            file: Mutex::new(file),
            read_only,
        });
        Ok((handle, len))
    }

    fn blk_read_at(&self, blk: Handle, offset: u64, dst: &mut [u8]) -> io::Result<usize> {
        let b = self.blocks.get(blk)?;
        let mut f = b.file.lock().unwrap();
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(dst)?;
        Ok(dst.len())
    }

    fn blk_write_at(&self, blk: Handle, offset: u64, src: &[u8]) -> io::Result<usize> {
        let b = self.blocks.get(blk)?;
        if b.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "attempted write to read-only block image",
            ));
        }
        let mut f = b.file.lock().unwrap();
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(src)?;
        Ok(src.len())
    }

    fn blk_flush(&self, blk: Handle) -> io::Result<()> {
        let b = self.blocks.get(blk)?;
        if b.read_only {
            return Ok(());
        }
        let f = b.file.lock().unwrap();
        match f.sync_all() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn blk_close(&self, blk: Handle) {
        self.blocks.remove(blk);
    }

    fn serial_open(&self) -> io::Result<Handle> {
        self.stdin_pipe.ensure_started(self.main_thread);
        Ok(self.serials.insert(()))
    }

    fn serial_write_byte(&self, serial: Handle, byte: u8) -> io::Result<()> {
        let _ = self.serials.get(serial)?;
        let mut stdout = io::stdout().lock();
        stdout.write_all(&[byte])?;
        stdout.flush()
    }

    fn serial_read_input(&self, serial: Handle, dst: &mut [u8]) -> io::Result<Option<usize>> {
        let _ = self.serials.get(serial)?;
        let mut q = self.stdin_pipe.buf.lock().unwrap();
        if q.is_empty() {
            if self.stdin_pipe.eof.load(Ordering::Acquire) {
                return Ok(None);
            }
            return Ok(Some(0));
        }
        let n = q.len().min(dst.len());
        for slot in dst.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
        }
        if !q.is_empty() {
            self.stdin_pipe.ready.store(true, Ordering::Release);
        }
        Ok(Some(n))
    }

    fn serial_shutdown(&self, serial: Handle) -> io::Result<()> {
        let _ = self.serials.get(serial)?;
        let _ = io::stdout().flush();
        Ok(())
    }

    fn serial_close(&self, serial: Handle) {
        self.serials.remove(serial);
    }

    fn io_register_vm_config(
        &self,
        boot_cfg: &IoBootConfig,
        virtio_devs: &[VirtioDeviceSpec],
    ) -> io::Result<()> {
        let ram_size = boot_cfg
            .mem_size
            .max(4 << 20)
            .next_multiple_of(PAGE_SIZE_SMALL as usize);
        let ram_arena = SysMemArena::alloc_zeroed(ram_size)?;

        let mut payload_bytes = Vec::new();
        let mut kernel_size = 0u64;
        let mut initramfs_size = 0u64;

        if let Some(kpath) = &boot_cfg.kernel_path {
            let kb = std::fs::read(kpath).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to read kernel '{}': {e}", kpath.display()),
                )
            })?;
            kernel_size = kb.len() as u64;
            payload_bytes.extend_from_slice(&kb);
        }

        if let Some(ipath) = &boot_cfg.initramfs_path {
            let ib = std::fs::read(ipath).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to read initramfs '{}': {e}", ipath.display()),
                )
            })?;
            initramfs_size = ib.len() as u64;
            payload_bytes.extend_from_slice(&ib);
        }

        let payload_arena = SysMemArena::from_slice(&payload_bytes)?;
        let payload_size = payload_bytes.len().max(PAGE_SIZE_SMALL as usize) as u64;

        let cwasm_bytes = std::fs::read(&self.core_cwasm_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "failed to read Ring-0 core cwasm '{}': {e}",
                    self.core_cwasm_path.display()
                ),
            )
        })?;
        crate::verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Ring-0 core cwasm '{}' failed zero-FP/SIMD validation: {e}",
                    self.core_cwasm_path.display()
                ),
            )
        })?;
        let cwasm_size = cwasm_bytes.len() as u64;
        let cwasm_arena = SysMemArena::from_slice(&cwasm_bytes)?;

        let shm = self.shm;
        let ndevs = virtio_devs.len().min(MAX_VIRTIO_DEVS);
        let mut boot_info = ShmBootInfo {
            num_cpus: boot_cfg.num_cpus,
            exec_type: match boot_cfg.exec_kind {
                Some(ExecKind::Linux) => EXEC_TYPE_LINUX,
                Some(ExecKind::Pvh) => EXEC_TYPE_PVH,
                None => EXEC_TYPE_NONE,
            },
            mem_size: ram_size as u64,
            kernel_size,
            initramfs_size,
            cmd_line_len: 0,
            num_virtio_devs: ndevs as u32,
            cmd_line: [0; vmm_core::host::abi::MAX_CMDLINE_LEN],
        };
        if let Some(cmd) = &boot_cfg.cmd_line {
            let bytes = cmd.as_bytes();
            let n = bytes.len().min(boot_info.cmd_line.len());
            boot_info.cmd_line[..n].copy_from_slice(&bytes[..n]);
            boot_info.cmd_line_len = n as u32;
        }

        unsafe {
            (*shm).boot_info = boot_info;
            for (i, d) in virtio_devs.iter().enumerate().take(ndevs) {
                let mut raw_spec = vmm_core::host::abi::ShmVirtioDeviceSpec {
                    dev: d.dev,
                    device_features: d.device_features,
                    device_id: d.device_id,
                    num_queues: d.num_queues,
                    config_len: 0,
                    name_len: 0,
                    pci_bdf: d.pci_bdf,
                    _pad: [0; 6],
                    name: [0; vmm_core::host::abi::MAX_DEV_NAME_LEN],
                    config_bytes: [0; vmm_core::host::abi::MAX_CONFIG_BYTES],
                };
                let nbytes = d.name.as_bytes();
                let nlen = nbytes.len().min(raw_spec.name.len());
                raw_spec.name[..nlen].copy_from_slice(&nbytes[..nlen]);
                raw_spec.name_len = nlen as u16;
                let clen = d.config_bytes.len().min(raw_spec.config_bytes.len());
                raw_spec.config_bytes[..clen].copy_from_slice(&d.config_bytes[..clen]);
                raw_spec.config_len = clen as u16;
                (*shm).virtio_devs[i] = raw_spec;
            }
            (*shm).config_ready.store(1, Ordering::Release);
        }

        let shm_addr = self.shm_arena.addr();
        let ram_addr = ram_arena.addr();
        let ram_sz_u64 = ram_size as u64;
        let payload_addr = payload_arena.addr();
        let cwasm_addr = cwasm_arena.addr();

        let vmm_url = format!(
            "vmm:shm_addr={shm_addr:#x};ram_addr={ram_addr:#x};ram_size={ram_sz_u64:#x};\
             payload_addr={payload_addr:#x};payload_size={payload_size:#x};\
             cwasm_addr={cwasm_addr:#x};cwasm_size={cwasm_size:#x}"
        );

        let vm_h = SysObj::create(SysHandle::KERNEL, 0, &vmm_url).map_err(|code| {
            if code == moto_rt::E_NOT_ALLOWED {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SysObj::create('vmm:...') denied: CAP_VMM (0x4000) is required (launch with MOTOR_OS_CAPS=0x434c or 0x430d)",
                )
            } else {
                io::Error::other(format!("SysObj::create('{vmm_url}') failed with code {code}"))
            }
        })?;

        self.ram_len
            .store(ram_arena.byte_len() as u64, Ordering::Release);
        self.ram_base.store(ram_addr, Ordering::Release);
        *self.vm_mem.lock().unwrap() = Some(VmMemoryHold {
            _ram: ram_arena,
            _payload: payload_arena,
            _cwasm: cwasm_arena,
        });
        *self.vm_handle.lock().unwrap() = Some(vm_h);
        Ok(())
    }

    fn io_next_event(&self) -> io::Result<IoBridgeEvent> {
        let raw = self.next_raw_event()?;
        match raw.kind {
            IO_BRIDGE_EVENT_VIRTIO_START => {
                let nq = (raw.num_queues as usize).min(MAX_QUEUES_PER_DEV);
                let queues = raw.queues[..nq]
                    .iter()
                    .copied()
                    .map(VirtioQueueConfig::from)
                    .collect();
                Ok(IoBridgeEvent::VirtioStart {
                    dev: raw.dev,
                    driver_features: raw.driver_features,
                    queues,
                })
            }
            IO_BRIDGE_EVENT_VIRTIO_NOTIFY => Ok(IoBridgeEvent::VirtioNotify {
                dev: raw.dev,
                queue_index: raw.queue_index,
            }),
            IO_BRIDGE_EVENT_VIRTIO_RESET => Ok(IoBridgeEvent::VirtioReset { dev: raw.dev }),
            IO_BRIDGE_EVENT_VIRTIO_CONFIG_WRITE => {
                let len = (raw.tx_len as usize).min(raw.tx_bytes.len());
                Ok(IoBridgeEvent::VirtioConfigWrite {
                    dev: raw.dev,
                    offset: raw.queue_index,
                    data: raw.tx_bytes[..len].to_vec(),
                })
            }
            IO_BRIDGE_EVENT_POLL => Ok(IoBridgeEvent::Poll(PollEvent {
                token: Token(raw.token),
                is_readable: raw.is_readable != 0,
                is_writable: raw.is_writable != 0,
            })),
            IO_BRIDGE_EVENT_SERIAL_INPUT => Ok(IoBridgeEvent::SerialInput),
            IO_BRIDGE_EVENT_SERIAL_TX => {
                let len = (raw.tx_len as usize).min(raw.tx_bytes.len());
                Ok(IoBridgeEvent::SerialTx(raw.tx_bytes[..len].to_vec()))
            }
            _ => Ok(IoBridgeEvent::Shutdown),
        }
    }

    fn io_request_shutdown(&self) -> io::Result<()> {
        self.io_shutdown.store(true, Ordering::Release);
        unsafe {
            (*self.shm).shutdown_requested.store(1, Ordering::Release);
        }
        let entry = IoToCoreEntry {
            msg_type: IO_MSG_REQUEST_SHUTDOWN,
            ..Default::default()
        };
        let _ = unsafe { BridgeShm::push_io_to_core(self.shm, entry) };
        self.wake_core();
        let _ = SysCpu::wake(self.main_thread);
        Ok(())
    }

    fn io_guest_mem_read(&self, gpa: u64, dst: &mut [u8]) -> io::Result<()> {
        self.read_guest_mem(gpa, dst).map_err(io::Error::other)
    }

    fn io_guest_mem_write(&self, gpa: u64, src: &[u8]) -> io::Result<()> {
        self.write_guest_mem(gpa, src).map_err(io::Error::other)
    }

    fn io_virtio_irq(&self, dev: Handle, kind: VirtioIrqKind) -> io::Result<()> {
        let (irq_kind, queue_index) = match kind {
            VirtioIrqKind::Config => (IRQ_KIND_CONFIG as u16, 0),
            VirtioIrqKind::Queue(q) => (IRQ_KIND_QUEUE as u16, q),
        };
        let entry = IoToCoreEntry {
            msg_type: IO_MSG_VIRTIO_IRQ,
            irq_kind,
            queue_index,
            dev,
            data: [0; 48],
        };
        if unsafe { BridgeShm::push_io_to_core(self.shm, entry) } {
            self.wake_core();
        }
        Ok(())
    }

    fn io_serial_push_rx(&self, data: &[u8]) -> io::Result<()> {
        let mut woke = false;
        for chunk in data.chunks(48) {
            let mut buf = [0u8; 48];
            buf[..chunk.len()].copy_from_slice(chunk);
            let entry = IoToCoreEntry {
                msg_type: IO_MSG_SERIAL_RX,
                irq_kind: 0,
                queue_index: chunk.len() as u16,
                dev: 0,
                data: buf,
            };
            if unsafe { BridgeShm::push_io_to_core(self.shm, entry) } {
                woke = true;
            }
        }
        if woke {
            self.wake_core();
        }
        let _ = io::stdout().flush();
        Ok(())
    }
}
