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
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    EXEC_TYPE_LINUX, EXEC_TYPE_NONE, EXEC_TYPE_PVH, IO_BRIDGE_EVENT_POLL,
    IO_BRIDGE_EVENT_SERIAL_INPUT, IO_BRIDGE_EVENT_SERIAL_TX, IO_BRIDGE_EVENT_SHUTDOWN,
    IO_BRIDGE_EVENT_VIRTIO_NOTIFY, IO_BRIDGE_EVENT_VIRTIO_RESET, IO_BRIDGE_EVENT_VIRTIO_START,
    IRQ_KIND_CONFIG, IRQ_KIND_QUEUE, RawIoBridgeEvent, ShmVirtioQueueConfig,
};
use vmm_io::host::{
    ExecKind, Handle, Interest, IoBootConfig, IoBridgeEvent, PollEvent, SerialConsole, Tap, Token,
    VirtioDeviceSpec, VirtioIrqKind, VirtioQueueConfig,
};
use vmm_io::virtio::dev::net::NetFeature;

use crate::serial::HostSerialConsole;
use crate::tap::HostTap;
use crate::wasm_host::VmmHostIo;

const TOKEN_SHUTDOWN_POLLER: mio::Token = mio::Token(usize::MAX);
const TOKEN_SERIAL_STDIN: mio::Token = mio::Token(usize::MAX - 1);
const TOKEN_CORE_BRIDGE: mio::Token = mio::Token(usize::MAX - 2);

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

/// Linux implementation of [`VmmHostIo`].
pub struct LinuxIoHost {
    shm: *mut BridgeShm,
    ram_fd: RawFd,
    payload_fd: RawFd,
    c2i_fd: RawFd,
    i2c_fd: RawFd,
    cfg_fd: RawFd,
    ram_base: AtomicU64,
    ram_len: AtomicU64,
    registry: mio::Registry,
    poll_waker: mio::Waker,
    io_shutdown: AtomicBool,
    io_poller: Mutex<IoPoller>,
    taps: ResourceTable<Mutex<Box<dyn Tap>>>,
    blocks: ResourceTable<File>,
    serials: ResourceTable<Box<dyn SerialConsole>>,
}

unsafe impl Send for LinuxIoHost {}
unsafe impl Sync for LinuxIoHost {}

impl LinuxIoHost {
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

    pub fn shutdown_bridge(&self) {
        unsafe {
            (*self.shm).shutdown_requested.store(1, Ordering::Release);
            (*self.shm).config_ready.store(1, Ordering::Release);
        }
        self.wake_cfg();
        self.wake_core();
    }

    fn wake_core(&self) {
        let val = 1u64;
        unsafe {
            let _ = write(self.i2c_fd, &val as *const u64 as *const c_void, 8);
        }
    }

    fn wake_cfg(&self) {
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

impl VmmHostIo for LinuxIoHost {
    fn tap_open(&self, if_name: Option<&str>) -> io::Result<Handle> {
        let registry = self.registry.try_clone()?;
        let tap = HostTap::new(if_name, registry)?;
        let boxed: Box<dyn Tap> = Box::new(tap);
        Ok(self.taps.insert(Mutex::new(boxed)))
    }

    fn tap_detected_offload(&self, tap: Handle) -> NetFeature {
        self.taps
            .get(tap)
            .map(|t| t.lock().detected_offload())
            .unwrap_or_else(|_| NetFeature::empty())
    }

    fn tap_enable_offload(&self, tap: Handle, feature: NetFeature) -> io::Result<()> {
        let t = self.taps.get(tap).map_err(io::Error::other)?;
        t.lock().enable_offload(feature)
    }

    fn tap_register(&self, tap: Handle, token: Token, interests: Interest) -> io::Result<()> {
        let t = self.taps.get(tap).map_err(io::Error::other)?;
        t.lock().register(token, interests)
    }

    fn tap_deregister(&self, tap: Handle) {
        if let Ok(t) = self.taps.get(tap) {
            t.lock().deregister();
        }
    }

    fn tap_read(&self, tap: Handle, dst: &mut [u8]) -> io::Result<usize> {
        let t = self.taps.get(tap).map_err(io::Error::other)?;
        t.lock().read_vectored(&mut [IoSliceMut::new(dst)])
    }

    fn tap_write(&self, tap: Handle, src: &[u8]) -> io::Result<usize> {
        let t = self.taps.get(tap).map_err(io::Error::other)?;
        t.lock().write_vectored(&[IoSlice::new(src)])
    }

    fn tap_close(&self, tap: Handle) {
        self.taps.remove(tap);
    }

    fn blk_open(&self, path: &Path, read_only: bool) -> io::Result<(Handle, u64)> {
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)?;
        let len = file.metadata()?.len();
        Ok((self.blocks.insert(file), len))
    }

    fn blk_read_at(&self, blk: Handle, offset: u64, dst: &mut [u8]) -> io::Result<usize> {
        let file = self.blocks.get(blk).map_err(io::Error::other)?;
        file.read_exact_at(dst, offset)?;
        Ok(dst.len())
    }

    fn blk_write_at(&self, blk: Handle, offset: u64, src: &[u8]) -> io::Result<usize> {
        let file = self.blocks.get(blk).map_err(io::Error::other)?;
        file.write_all_at(src, offset)?;
        Ok(src.len())
    }

    fn blk_flush(&self, blk: Handle) -> io::Result<()> {
        let file = self.blocks.get(blk).map_err(io::Error::other)?;
        file.sync_data()
    }

    fn blk_close(&self, blk: Handle) {
        self.blocks.remove(blk);
    }

    fn serial_open(&self) -> io::Result<Handle> {
        let registry = self.registry.try_clone()?;
        let s = HostSerialConsole::new(registry, TOKEN_SERIAL_STDIN)?;
        let boxed: Box<dyn SerialConsole> = Box::new(s);
        Ok(self.serials.insert(boxed))
    }

    fn serial_write_byte(&self, serial: Handle, byte: u8) -> io::Result<()> {
        let s = self.serials.get(serial).map_err(io::Error::other)?;
        s.write_byte(byte)
    }

    fn serial_read_input(&self, serial: Handle, dst: &mut [u8]) -> io::Result<Option<usize>> {
        let s = self.serials.get(serial).map_err(io::Error::other)?;
        let mut deque = VecDeque::new();
        match s.read_input(&mut deque)? {
            None => Ok(None),
            Some(_) => {
                let n = deque.len().min(dst.len());
                for slot in dst.iter_mut().take(n) {
                    *slot = deque.pop_front().unwrap();
                }
                Ok(Some(n))
            }
        }
    }

    fn serial_shutdown(&self, serial: Handle) -> io::Result<()> {
        let s = self.serials.get(serial).map_err(io::Error::other)?;
        s.shutdown()
    }

    fn serial_close(&self, serial: Handle) {
        self.serials.remove(serial);
    }

    fn io_register_vm_config(
        &self,
        boot_cfg: &IoBootConfig,
        virtio_devs: &[VirtioDeviceSpec],
    ) -> io::Result<()> {
        let arena_size = boot_cfg.mem_size + (64 << 20);
        if unsafe { ftruncate(self.ram_fd, arena_size as libc::off_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let rptr = unsafe {
            mmap(
                null_mut(),
                arena_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                self.ram_fd,
                0,
            )
        };
        if rptr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        self.ram_len.store(arena_size as u64, Ordering::Release);
        self.ram_base
            .store(rptr as usize as u64, Ordering::Release);

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

        if !payload_bytes.is_empty() {
            if unsafe { ftruncate(self.payload_fd, payload_bytes.len() as libc::off_t) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut written = 0;
            while written < payload_bytes.len() {
                let rc = unsafe {
                    libc::pwrite(
                        self.payload_fd,
                        payload_bytes[written..].as_ptr() as *const c_void,
                        payload_bytes.len() - written,
                        written as libc::off_t,
                    )
                };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
                written += rc as usize;
            }
        }

        let shm = self.shm;
        let ndevs = virtio_devs.len().min(MAX_VIRTIO_DEVS);
        let mut boot_info = ShmBootInfo {
            num_cpus: boot_cfg.num_cpus,
            exec_type: match boot_cfg.exec_kind {
                Some(ExecKind::Linux) => EXEC_TYPE_LINUX,
                Some(ExecKind::Pvh) => EXEC_TYPE_PVH,
                None => EXEC_TYPE_NONE,
            },
            mem_size: boot_cfg.mem_size as u64,
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
        self.wake_cfg();
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
        let _ = self.poll_waker.wake();
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
        let _ = Write::flush(&mut io::stdout());
        Ok(())
    }
}
