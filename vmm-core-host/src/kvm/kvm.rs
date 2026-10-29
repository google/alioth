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

pub(crate) mod bindings;
pub(crate) mod vcpu;

use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{
    EFD_CLOEXEC, EFD_NONBLOCK, MAP_FAILED, MAP_SHARED, POLLIN, PROT_EXEC, PROT_READ, PROT_WRITE,
    c_void, eventfd, mmap, poll, pollfd, read, write,
};
use parking_lot::{Condvar, Mutex};
use vmm_core::host::abi::{
    BridgeShm, CORE_MSG_SHUTDOWN, CORE_MSG_VIRTIO_NOTIFY, CoreToIoEntry, IO_MSG_REQUEST_SHUTDOWN,
    IO_MSG_SERIAL_RX, IO_MSG_VIRTIO_IRQ, IRQ_KIND_CONFIG, IoToCoreEntry, MAX_QUEUES_PER_DEV,
    MAX_VIRTIO_DEVS, ShmBootInfo, ShmDeviceMsixRouting, ShmMsiEntry, ShmVirtioDeviceSpec,
    ShmVirtioQueueConfig, spin_lock, spin_unlock,
};
use vmm_core::host::{HvError, HvResult, IoSpace, PayloadKind, VmmCoreBridge};

use crate::ffi;
use bindings::{KvmMsi, kvm_signal_msi};
use vcpu::io_to_hv_err;

pub struct CoreBridgeFds {
    pub bridge_fd: RawFd,
    pub ram_fd: RawFd,
    pub payload_fd: RawFd,
    pub c2i_fd: RawFd,
    pub i2c_fd: RawFd,
    pub cfg_fd: RawFd,
}

#[derive(Debug, Clone, Copy)]
struct FreeRamRange {
    offset: u64,
    len: u64,
}

#[derive(Debug, Default)]
struct RamArena {
    next_offset: u64,
    free_list: Vec<FreeRamRange>,
}

pub struct SharedCoreBridge {
    pub shm: *mut BridgeShm,
    pub ram_fd: RawFd,
    pub payload_fd: RawFd,
    pub c2i_fd: RawFd,
    pub i2c_fd: RawFd,
    pub cfg_fd: RawFd,
    pub ram_base: AtomicU64,
    pub ram_len: AtomicU64,
    ram_arena: Mutex<RamArena>,
    pub payload_base: AtomicU64,
    pub payload_len: AtomicU64,
    pub ctrl_rx: Mutex<VecDeque<IoToCoreEntry>>,
    pub ctrl_rx_cv: Condvar,
}

unsafe impl Send for SharedCoreBridge {}
unsafe impl Sync for SharedCoreBridge {}

impl Debug for SharedCoreBridge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedCoreBridge")
            .field("ram_fd", &self.ram_fd)
            .field("payload_fd", &self.payload_fd)
            .finish()
    }
}

impl SharedCoreBridge {
    pub fn from_fds(fds: CoreBridgeFds) -> std::io::Result<Arc<Self>> {
        let shm_size = size_of::<BridgeShm>();
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
            return Err(std::io::Error::last_os_error());
        }
        Ok(Arc::new(Self {
            shm: ptr as *mut BridgeShm,
            ram_fd: fds.ram_fd,
            payload_fd: fds.payload_fd,
            c2i_fd: fds.c2i_fd,
            i2c_fd: fds.i2c_fd,
            cfg_fd: fds.cfg_fd,
            ram_base: AtomicU64::new(0),
            ram_len: AtomicU64::new(0),
            ram_arena: Mutex::new(RamArena::default()),
            payload_base: AtomicU64::new(0),
            payload_len: AtomicU64::new(0),
            ctrl_rx: Mutex::new(VecDeque::new()),
            ctrl_rx_cv: Condvar::new(),
        }))
    }

    pub fn wake_io(&self) {
        let val = 1u64;
        unsafe {
            let _ = write(self.c2i_fd, &val as *const u64 as *const c_void, 8);
        }
    }

    pub fn ensure_mapped(&self) -> HvResult<()> {
        let shm = unsafe { &*self.shm };
        while shm.config_ready.load(Ordering::Acquire) == 0 {
            let mut val = 0u64;
            let _ = unsafe { read(self.cfg_fd, &mut val as *mut u64 as *mut c_void, 8) };
        }

        if self.ram_base.load(Ordering::Acquire) == 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            ffi!(unsafe { libc::fstat(self.ram_fd, &mut st) }).map_err(io_to_hv_err)?;
            let rlen = st.st_size as usize;
            if rlen > 0 {
                let rptr = unsafe {
                    mmap(
                        null_mut(),
                        rlen,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_SHARED,
                        self.ram_fd,
                        0,
                    )
                };
                if rptr == MAP_FAILED {
                    return Err(io_to_hv_err(std::io::Error::last_os_error()));
                }
                self.ram_len.store(rlen as u64, Ordering::Release);
                self.ram_base.store(rptr as usize as u64, Ordering::Release);
            }
        }

        if self.payload_base.load(Ordering::Acquire) == 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            ffi!(unsafe { libc::fstat(self.payload_fd, &mut st) }).map_err(io_to_hv_err)?;
            let plen = st.st_size as usize;
            if plen > 0 {
                let pptr =
                    unsafe { mmap(null_mut(), plen, PROT_READ, MAP_SHARED, self.payload_fd, 0) };
                if pptr == MAP_FAILED {
                    return Err(io_to_hv_err(std::io::Error::last_os_error()));
                }
                self.payload_len.store(plen as u64, Ordering::Release);
                self.payload_base
                    .store(pptr as usize as u64, Ordering::Release);
            }
        }
        Ok(())
    }

    pub fn alloc_shared_ram(&self, size: u64) -> HvResult<(NonNull<c_void>, u64, u64)> {
        if size == 0 {
            return Err(HvError::InvalidParam);
        }
        self.ensure_mapped()?;
        let aligned_size = size.checked_add(4095).ok_or(HvError::InvalidParam)? & !4095;
        let base = self.ram_base.load(Ordering::Acquire);
        let total_len = self.ram_len.load(Ordering::Acquire);
        if base == 0 {
            return Err(HvError::NoMemory);
        }

        let mut arena = self.ram_arena.lock();
        let mut reused = false;
        let offset = if let Some(idx) = arena.free_list.iter().position(|r| r.len >= aligned_size) {
            reused = true;
            let r = &mut arena.free_list[idx];
            let off = r.offset;
            if r.len == aligned_size {
                arena.free_list.remove(idx);
            } else {
                r.offset += aligned_size;
                r.len -= aligned_size;
            }
            off
        } else {
            let end = arena
                .next_offset
                .checked_add(aligned_size)
                .ok_or(HvError::NoMemory)?;
            if end > total_len {
                return Err(HvError::NoMemory);
            }
            let off = arena.next_offset;
            arena.next_offset = end;
            off
        };
        drop(arena);

        let ptr = (base + offset) as usize as *mut c_void;
        let addr = NonNull::new(ptr).ok_or(HvError::NoMemory)?;
        if reused {
            unsafe {
                std::ptr::write_bytes(addr.as_ptr() as *mut u8, 0, aligned_size as usize);
            }
        }
        Ok((addr, offset, aligned_size))
    }

    pub fn free_shared_ram(&self, offset: u64, len: u64) {
        let mut arena = self.ram_arena.lock();
        let pos = arena
            .free_list
            .partition_point(|r| r.offset < offset);
        arena.free_list.insert(pos, FreeRamRange { offset, len });

        let mut merged: Vec<FreeRamRange> = Vec::with_capacity(arena.free_list.len());
        for range in arena.free_list.drain(..) {
            if let Some(last) = merged.last_mut()
                && last.offset + last.len == range.offset
            {
                last.len += range.len;
            } else {
                merged.push(range);
            }
        }
        if let Some(last) = merged.last()
            && last.offset + last.len == arena.next_offset
        {
            arena.next_offset = last.offset;
            merged.pop();
        }
        arena.free_list = merged;
    }
}

impl VmmCoreBridge for SharedCoreBridge {
    fn boot_info(
        &self,
        out_info: &mut ShmBootInfo,
        out_devs: &mut [ShmVirtioDeviceSpec],
    ) -> HvResult<usize> {
        self.ensure_mapped()?;
        let shm = unsafe { &*self.shm };
        *out_info = shm.boot_info;
        let total_devs = (out_info.num_virtio_devs as usize).min(MAX_VIRTIO_DEVS);
        let count = total_devs.min(out_devs.len());
        out_devs[..count].copy_from_slice(&shm.virtio_devs[..count]);
        Ok(count)
    }

    fn read_payload(&self, kind: PayloadKind, offset: u64, dst: &mut [u8]) -> HvResult<usize> {
        self.ensure_mapped()?;
        let shm = unsafe { &*self.shm };
        let kernel_size = shm.boot_info.kernel_size;
        let initramfs_size = shm.boot_info.initramfs_size;
        let (base_off, total_size) = match kind {
            PayloadKind::Kernel => (0u64, kernel_size),
            PayloadKind::Initramfs => (kernel_size, initramfs_size),
        };
        if offset >= total_size || dst.is_empty() {
            return Ok(0);
        }
        let avail = (total_size - offset) as usize;
        let to_read = dst.len().min(avail);
        let pbase = self.payload_base.load(Ordering::Acquire) as usize;
        let plen = self.payload_len.load(Ordering::Acquire) as usize;
        let start = (base_off + offset) as usize;
        if pbase == 0 || start.checked_add(to_read).is_none_or(|end| end > plen) {
            return Err(HvError::InvalidParam);
        }
        let src = unsafe { std::slice::from_raw_parts((pbase + start) as *const u8, to_read) };
        dst[..to_read].copy_from_slice(src);
        Ok(to_read)
    }

    fn configure_device_queues(
        &self,
        dev: u32,
        queues: &[ShmVirtioQueueConfig],
    ) -> HvResult<()> {
        let dev_idx = dev as usize;
        if dev_idx >= MAX_VIRTIO_DEVS || queues.len() > MAX_QUEUES_PER_DEV {
            return Err(HvError::InvalidParam);
        }
        let shm = self.shm;
        unsafe {
            for (i, slot) in (*shm).device_queues[dev_idx].iter_mut().enumerate() {
                *slot = queues.get(i).copied().unwrap_or_default();
            }
        }
        Ok(())
    }

    fn update_irq_route(&self, dev: u32, routing: &ShmDeviceMsixRouting) -> HvResult<()> {
        let dev_idx = dev as usize;
        if dev_idx >= MAX_VIRTIO_DEVS {
            return Err(HvError::InvalidParam);
        }
        let shm = self.shm;
        let lock = unsafe { &(*shm).msix_lock };
        spin_lock(lock);
        unsafe {
            (*shm).msix_routing[dev_idx] = *routing;
        }
        spin_unlock(lock);
        Ok(())
    }

    fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()> {
        let shm = self.shm;
        if entry.msg_type == CORE_MSG_SHUTDOWN {
            unsafe {
                (*shm).shutdown_requested.store(1, Ordering::Release);
            }
            self.ctrl_rx_cv.notify_all();
            let _ = unsafe { BridgeShm::push_core_to_io(shm, *entry) };
            self.wake_io();
            return Ok(());
        }
        if unsafe { BridgeShm::push_core_to_io(shm, *entry) } {
            self.wake_io();
        }
        Ok(())
    }

    fn recv_io_cmd(&self, blocking: bool, out: &mut IoToCoreEntry) -> HvResult<bool> {
        let shm = self.shm;
        let mut rx = self.ctrl_rx.lock();
        loop {
            if let Some(entry) = rx.pop_front() {
                *out = entry;
                return Ok(true);
            }
            if !blocking || unsafe { (*shm).shutdown_requested.load(Ordering::Acquire) != 0 } {
                return Ok(false);
            }
            self.ctrl_rx_cv.wait(&mut rx);
        }
    }
}

pub(crate) struct KvmDoorbellEntry {
    pub space: IoSpace,
    pub addr: u64,
    pub size: u8,
    pub datamatch: Option<u64>,
    pub dev_id: u32,
    pub queue_idx: u16,
    pub evt_fd: Arc<OwnedFd>,
}

pub(crate) struct DoorbellRegistry {
    pub wake_fd: OwnedFd,
    pub entries: Mutex<Vec<KvmDoorbellEntry>>,
}

impl DoorbellRegistry {
    pub fn new() -> std::io::Result<Arc<Self>> {
        let raw_fd = ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) })?;
        Ok(Arc::new(Self {
            wake_fd: unsafe { OwnedFd::from_raw_fd(raw_fd) },
            entries: Mutex::new(Vec::new()),
        }))
    }

    pub fn wake(&self) {
        let val = 1u64;
        unsafe {
            let _ = write(
                self.wake_fd.as_raw_fd(),
                &val as *const u64 as *const c_void,
                8,
            );
        }
    }
}

pub(crate) fn spawn_i2c_listener(
    vm_fd: Arc<OwnedFd>,
    bridge: Arc<SharedCoreBridge>,
    doorbells: Arc<DoorbellRegistry>,
) {
    let _ = std::thread::Builder::new()
        .name("core-i2c-listener".to_string())
        .spawn(move || {
            let shm = bridge.shm;
            let mut poll_fds: Vec<pollfd> = Vec::with_capacity(16);
            let mut snapshot: Vec<(u32, u16, Arc<OwnedFd>)> = Vec::with_capacity(16);
            loop {
                while let Some(entry) = unsafe { BridgeShm::pop_io_to_core(shm) } {
                    match entry.msg_type {
                        IO_MSG_VIRTIO_IRQ => {
                            let dev = entry.dev as usize;
                            if dev < MAX_VIRTIO_DEVS {
                                let lock = unsafe { &(*shm).msix_lock };
                                spin_lock(lock);
                                let msi: ShmMsiEntry = unsafe {
                                    let routing = &(*shm).msix_routing[dev];
                                    if entry.irq_kind as u32 == IRQ_KIND_CONFIG {
                                        routing.config_msi
                                    } else if (entry.queue_index as usize) < MAX_QUEUES_PER_DEV {
                                        routing.queue_msis[entry.queue_index as usize]
                                    } else {
                                        ShmMsiEntry::default()
                                    }
                                };
                                spin_unlock(lock);

                                if msi.enabled != 0 && msi.addr != 0 {
                                    let kvm_msi = KvmMsi {
                                        address_lo: msi.addr as u32,
                                        address_hi: (msi.addr >> 32) as u32,
                                        data: msi.data,
                                        ..Default::default()
                                    };
                                    let _ = unsafe { kvm_signal_msi(&vm_fd, &kvm_msi) };
                                }
                            }
                        }
                        IO_MSG_SERIAL_RX => {
                            let len = (entry.queue_index as usize).min(entry.data.len());
                            if len > 0 {
                                bridge.ctrl_rx.lock().push_back(entry);
                                bridge.ctrl_rx_cv.notify_all();
                            }
                        }
                        IO_MSG_REQUEST_SHUTDOWN => {
                            unsafe {
                                (*shm).shutdown_requested.store(1, Ordering::Release);
                            }
                            bridge.ctrl_rx.lock().push_back(entry);
                            bridge.ctrl_rx_cv.notify_all();
                            return;
                        }
                        _ => {}
                    }
                }

                if unsafe { (*shm).shutdown_requested.load(Ordering::Acquire) != 0 } {
                    bridge.ctrl_rx_cv.notify_all();
                    return;
                }

                poll_fds.clear();
                snapshot.clear();
                poll_fds.push(pollfd {
                    fd: bridge.i2c_fd,
                    events: POLLIN,
                    revents: 0,
                });
                poll_fds.push(pollfd {
                    fd: doorbells.wake_fd.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
                {
                    let entries = doorbells.entries.lock();
                    for db in entries.iter() {
                        poll_fds.push(pollfd {
                            fd: db.evt_fd.as_raw_fd(),
                            events: POLLIN,
                            revents: 0,
                        });
                        snapshot.push((db.dev_id, db.queue_idx, db.evt_fd.clone()));
                    }
                }

                let rc = unsafe { poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, 50) };
                if rc > 0 {
                    if (poll_fds[0].revents & POLLIN) != 0 {
                        let mut val = 0u64;
                        let _ =
                            unsafe { read(bridge.i2c_fd, &mut val as *mut u64 as *mut c_void, 8) };
                    }
                    if (poll_fds[1].revents & POLLIN) != 0 {
                        let mut val = 0u64;
                        let _ = unsafe {
                            read(
                                doorbells.wake_fd.as_raw_fd(),
                                &mut val as *mut u64 as *mut c_void,
                                8,
                            )
                        };
                    }
                    for (i, &(dev_id, queue_idx, ref evt_fd)) in snapshot.iter().enumerate() {
                        if (poll_fds[2 + i].revents & POLLIN) != 0 {
                            let mut val = 0u64;
                            let _ = unsafe {
                                read(
                                    evt_fd.as_raw_fd(),
                                    &mut val as *mut u64 as *mut c_void,
                                    8,
                                )
                            };
                            let notify = CoreToIoEntry {
                                msg_type: CORE_MSG_VIRTIO_NOTIFY,
                                aux_u16: queue_idx,
                                _pad: 0,
                                dev: dev_id as u64,
                                features: 0,
                                data: [0; 40],
                            };
                            if unsafe { BridgeShm::push_core_to_io(shm, notify) } {
                                bridge.wake_io();
                            }
                        }
                    }
                }
            }
        });
}
