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

mod bindings;
mod vcpu;

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::mem::{size_of, transmute};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{NonNull, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use libc::{
    EFD_CLOEXEC, EFD_NONBLOCK, MAP_FAILED, MAP_SHARED, MS_ASYNC, POLLIN, PROT_EXEC, PROT_READ,
    PROT_WRITE, SIGRTMIN, c_void, eventfd, mmap, msync, poll, pollfd, read, write,
};
use parking_lot::{Condvar, Mutex};
use vmm_core::host::abi::{
    BridgeShm, CORE_MSG_SERIAL_TX, CORE_MSG_SHUTDOWN, CORE_MSG_VIRTIO_NOTIFY,
    CORE_MSG_VIRTIO_RESET, CORE_MSG_VIRTIO_START, CoreToIoEntry, EXEC_TYPE_LINUX, EXEC_TYPE_PVH,
    IO_MSG_REQUEST_SHUTDOWN, IO_MSG_SERIAL_RX, IO_MSG_VIRTIO_IRQ, IRQ_KIND_CONFIG,
    MAX_QUEUES_PER_DEV, MAX_RAM_SLOTS, MAX_VIRTIO_DEVS, ShmDeviceMsixRouting, ShmGuestRamSlot,
    ShmMsiEntry, ShmVirtioQueueConfig, spin_lock, spin_unlock,
};
use vmm_core::host::{
    CoreBootInfo, Cpuid, Error, Handle, Hypervisor, IntxSender, MemMapOption, MemPages, MsiSender,
    PayloadKind, Result, Vcpu, VirtioDeviceSpec, VirtioQueueConfig, Vm, VmMemory,
};
use vmm_core::loader::ExecType;

use crate::ffi;
use bindings::{
    KVM_API_VERSION, KVM_CAP_IRQFD, KVM_CAP_NR_MEMSLOTS, KVM_CAP_SIGNAL_MSI, KVM_MAX_CPUID_ENTRIES,
    KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmEncRegion, KvmIrqfd, KvmMemFlag, KvmMsi,
    KvmUserspaceMemoryRegion, kvm_check_extension, kvm_create_irqchip, kvm_create_vcpu,
    kvm_create_vm, kvm_get_api_version, kvm_get_supported_cpuid, kvm_get_vcpu_mmap_size, kvm_irqfd,
    kvm_memory_encrypt_reg_region, kvm_memory_encrypt_unreg_region, kvm_set_identity_map_addr,
    kvm_set_tss_addr, kvm_set_user_memory_region, kvm_signal_msi,
};
use vcpu::{KvmRunBlock, KvmVcpu};

pub struct CoreBridgeFds {
    pub bridge_fd: RawFd,
    pub ram_fd: RawFd,
    pub payload_fd: RawFd,
    pub c2i_fd: RawFd,
    pub i2c_fd: RawFd,
    pub cfg_fd: RawFd,
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
    pub ram_next_offset: AtomicU64,
    pub payload_base: AtomicU64,
    pub payload_len: AtomicU64,
    pub serial_rx: Mutex<VecDeque<u8>>,
    pub serial_rx_cv: Condvar,
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
            ram_next_offset: AtomicU64::new(0),
            payload_base: AtomicU64::new(0),
            payload_len: AtomicU64::new(0),
            serial_rx: Mutex::new(VecDeque::new()),
            serial_rx_cv: Condvar::new(),
        }))
    }

    pub fn wake_io(&self) {
        let val = 1u64;
        unsafe {
            let _ = write(self.c2i_fd, &val as *const u64 as *const c_void, 8);
        }
    }

    pub fn ensure_mapped(&self) -> Result<(), Error> {
        let shm = unsafe { &*self.shm };
        while shm.config_ready.load(Ordering::Acquire) == 0 {
            let mut val = 0u64;
            let _ = unsafe { read(self.cfg_fd, &mut val as *mut u64 as *mut c_void, 8) };
        }

        if self.ram_base.load(Ordering::Acquire) == 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            ffi!(unsafe { libc::fstat(self.ram_fd, &mut st) })?;
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
                    return Err(std::io::Error::last_os_error().into());
                }
                self.ram_len.store(rlen as u64, Ordering::Release);
                self.ram_base.store(rptr as usize as u64, Ordering::Release);
            }
        }

        if self.payload_base.load(Ordering::Acquire) == 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            ffi!(unsafe { libc::fstat(self.payload_fd, &mut st) })?;
            let plen = st.st_size as usize;
            if plen > 0 {
                let pptr =
                    unsafe { mmap(null_mut(), plen, PROT_READ, MAP_SHARED, self.payload_fd, 0) };
                if pptr == MAP_FAILED {
                    return Err(std::io::Error::last_os_error().into());
                }
                self.payload_len.store(plen as u64, Ordering::Release);
                self.payload_base
                    .store(pptr as usize as u64, Ordering::Release);
            }
        }
        Ok(())
    }

    pub fn core_get_boot_info(&self) -> Result<(CoreBootInfo, Vec<VirtioDeviceSpec>), Error> {
        self.ensure_mapped()?;
        let shm = unsafe { &*self.shm };
        let raw_boot = shm.boot_info;
        let exec_type = match raw_boot.exec_type {
            EXEC_TYPE_LINUX => Some(ExecType::Linux),
            EXEC_TYPE_PVH => Some(ExecType::Pvh),
            _ => None,
        };
        let cmd_len = (raw_boot.cmd_line_len as usize).min(raw_boot.cmd_line.len());
        let cmd_line = if cmd_len > 0 {
            Some(
                String::from_utf8_lossy(&raw_boot.cmd_line[..cmd_len])
                    .into_owned(),
            )
        } else {
            None
        };
        let initramfs_size = if raw_boot.initramfs_size > 0 {
            Some(raw_boot.initramfs_size)
        } else {
            None
        };
        let boot_info = CoreBootInfo {
            num_cpus: raw_boot.num_cpus,
            mem_size: raw_boot.mem_size as usize,
            exec_type,
            kernel_size: raw_boot.kernel_size,
            initramfs_size,
            cmd_line,
        };

        let num_devs = (raw_boot.num_virtio_devs as usize).min(MAX_VIRTIO_DEVS);
        let mut specs = Vec::with_capacity(num_devs);
        for i in 0..num_devs {
            let raw = shm.virtio_devs[i];
            let nlen = (raw.name_len as usize).min(raw.name.len());
            let name = String::from_utf8_lossy(&raw.name[..nlen]).into_owned();
            let clen = (raw.config_len as usize).min(raw.config_bytes.len());
            let config_bytes = raw.config_bytes[..clen].to_vec();
            specs.push(VirtioDeviceSpec {
                dev: raw.dev,
                name,
                device_id: raw.device_id,
                device_features: raw.device_features,
                num_queues: raw.num_queues,
                config_bytes,
            });
        }
        Ok((boot_info, specs))
    }

    pub fn core_read_payload(
        &self,
        kind: PayloadKind,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
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
        if pbase == 0 || start.checked_add(to_read).map_or(true, |end| end > plen) {
            return Err(Error::Unexpected {
                msg: "payload read out of bounds".to_string(),
            });
        }
        let src = unsafe { std::slice::from_raw_parts((pbase + start) as *const u8, to_read) };
        dst[..to_read].copy_from_slice(src);
        Ok(to_read)
    }

    pub fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> Result<(), Error> {
        let dev_idx = dev as usize;
        if dev_idx >= MAX_VIRTIO_DEVS {
            return Err(Error::Unexpected {
                msg: format!("invalid virtio dev handle {dev}"),
            });
        }
        let shm = self.shm;
        let nq = queues.len().min(MAX_QUEUES_PER_DEV);
        unsafe {
            for (i, q) in queues.iter().copied().enumerate().take(nq) {
                (*shm).device_queues[dev_idx][i] = ShmVirtioQueueConfig::from(q);
            }
        }
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_VIRTIO_START,
            aux_u16: nq as u16,
            _pad: 0,
            dev,
            features: driver_features,
            data: [0; 40],
        };
        if unsafe { BridgeShm::push_core_to_io(shm, entry) } {
            self.wake_io();
        }
        Ok(())
    }

    pub fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> Result<(), Error> {
        let shm = self.shm;
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_VIRTIO_NOTIFY,
            aux_u16: queue_index,
            _pad: 0,
            dev,
            features: 0,
            data: [0; 40],
        };
        if unsafe { BridgeShm::push_core_to_io(shm, entry) } {
            self.wake_io();
        }
        Ok(())
    }

    pub fn core_virtio_reset(&self, dev: Handle) -> Result<(), Error> {
        let shm = self.shm;
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_VIRTIO_RESET,
            aux_u16: 0,
            _pad: 0,
            dev,
            features: 0,
            data: [0; 40],
        };
        if unsafe { BridgeShm::push_core_to_io(shm, entry) } {
            self.wake_io();
        }
        Ok(())
    }

    pub fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> Result<(), Error> {
        let dev_idx = dev as usize;
        if dev_idx >= MAX_VIRTIO_DEVS {
            return Err(Error::Unexpected {
                msg: format!("invalid virtio dev handle {dev}"),
            });
        }
        let mut routing = ShmDeviceMsixRouting::default();
        if let Some((addr, data)) = config_msi {
            routing.config_msi = ShmMsiEntry {
                addr,
                data,
                enabled: 1,
            };
        }
        for (i, q_msi) in queue_msis.iter().enumerate().take(MAX_QUEUES_PER_DEV) {
            if let Some((addr, data)) = q_msi {
                routing.queue_msis[i] = ShmMsiEntry {
                    addr: *addr,
                    data: *data,
                    enabled: 1,
                };
            }
        }
        let shm = self.shm;
        let lock = unsafe { &(*shm).msix_lock };
        spin_lock(lock);
        unsafe {
            (*shm).msix_routing[dev_idx] = routing;
        }
        spin_unlock(lock);
        Ok(())
    }

    pub fn core_serial_tx(&self, byte: u8) -> Result<(), Error> {
        let shm = self.shm;
        let mut data = [0u8; 40];
        data[0] = byte;
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_SERIAL_TX,
            aux_u16: 1,
            _pad: 0,
            dev: 0,
            features: 0,
            data,
        };
        if unsafe { BridgeShm::push_core_to_io(shm, entry) } {
            self.wake_io();
        }
        Ok(())
    }

    pub fn core_serial_rx(&self, dst: &mut [u8]) -> Result<usize, Error> {
        let shm = self.shm;
        let mut rx = self.serial_rx.lock();
        while rx.is_empty() {
            if unsafe { (*shm).shutdown_requested.load(Ordering::Acquire) != 0 } {
                return Ok(0);
            }
            self.serial_rx_cv.wait(&mut rx);
        }
        let count = dst.len().min(rx.len());
        for slot in dst.iter_mut().take(count) {
            *slot = rx.pop_front().unwrap();
        }
        Ok(count)
    }

    pub fn core_notify_shutdown(&self) -> Result<(), Error> {
        let shm = self.shm;
        unsafe {
            (*shm).shutdown_requested.store(1, Ordering::Release);
        }
        self.serial_rx_cv.notify_all();
        let entry = CoreToIoEntry {
            msg_type: CORE_MSG_SHUTDOWN,
            aux_u16: 0,
            _pad: 0,
            dev: 0,
            features: 0,
            data: [0; 40],
        };
        let _ = unsafe { BridgeShm::push_core_to_io(shm, entry) };
        self.wake_io();
        Ok(())
    }
}

#[derive(Debug)]
pub struct Kvm {
    fd: OwnedFd,
    bridge: Arc<SharedCoreBridge>,
}

extern "C" fn sigrtmin_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}

impl Kvm {
    pub fn new(bridge: Arc<SharedCoreBridge>) -> Result<Self, Error> {
        let kvm_file = File::open("/dev/kvm")?;
        let kvm_fd = OwnedFd::from(kvm_file);
        let version = unsafe { kvm_get_api_version(&kvm_fd) }?;
        if version != KVM_API_VERSION {
            return Err(Error::LackCap {
                cap: format!("current KVM API version {version}, need {KVM_API_VERSION}"),
            });
        }
        let mut action: libc::sigaction = unsafe { transmute([0u8; size_of::<libc::sigaction>()]) };
        action.sa_flags = libc::SA_SIGINFO;
        action.sa_sigaction = sigrtmin_handler as *const () as _;
        ffi!(unsafe { libc::sigfillset(&mut action.sa_mask) })?;
        ffi!(unsafe { libc::sigaction(SIGRTMIN(), &action, null_mut()) })?;
        Ok(Kvm { fd: kvm_fd, bridge })
    }
}

fn spawn_i2c_listener(vm_fd: Arc<OwnedFd>, bridge: Arc<SharedCoreBridge>) {
    let _ = std::thread::Builder::new()
        .name("core-i2c-listener".to_string())
        .spawn(move || {
            let shm = bridge.shm;
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
                                let mut rx = bridge.serial_rx.lock();
                                rx.extend(&entry.data[..len]);
                                bridge.serial_rx_cv.notify_all();
                            }
                        }
                        IO_MSG_REQUEST_SHUTDOWN => {
                            unsafe {
                                (*shm).shutdown_requested.store(1, Ordering::Release);
                            }
                            bridge.serial_rx_cv.notify_all();
                            return;
                        }
                        _ => {}
                    }
                }

                if unsafe { (*shm).shutdown_requested.load(Ordering::Acquire) != 0 } {
                    bridge.serial_rx_cv.notify_all();
                    return;
                }

                let mut pfd = pollfd {
                    fd: bridge.i2c_fd,
                    events: POLLIN,
                    revents: 0,
                };
                let rc = unsafe { poll(&mut pfd, 1, 50) };
                if rc > 0 && (pfd.revents & POLLIN) != 0 {
                    let mut val = 0u64;
                    let _ = unsafe { read(bridge.i2c_fd, &mut val as *mut u64 as *mut c_void, 8) };
                }
            }
        });
}

impl Hypervisor for Kvm {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error> {
        let vcpu_mmap_size = unsafe { kvm_get_vcpu_mmap_size(&self.fd) }? as usize;
        let vm_fd = unsafe { kvm_create_vm(&self.fd, 0) }?;
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(vm_fd) });

        let kvm_vm = KvmVm {
            fd: fd.clone(),
            vcpu_mmap_size,
            memory_created: false,
            vcpus: Mutex::new(BTreeMap::new()),
            bridge: self.bridge.clone(),
        };
        unsafe { kvm_create_irqchip(&kvm_vm.fd) }?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_tss_addr(&kvm_vm.fd, 0xf000_0000) }?;
        #[cfg(target_arch = "x86_64")]
        unsafe { kvm_set_identity_map_addr(&kvm_vm.fd, &0xf000_3000) }?;

        spawn_i2c_listener(fd, self.bridge.clone());

        Ok(Box::new(kvm_vm))
    }

    #[cfg(target_arch = "x86_64")]
    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error> {
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: KVM_MAX_CPUID_ENTRIES as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        unsafe { kvm_get_supported_cpuid(&self.fd, &mut kvm_cpuid2) }?;
        let cpuids = kvm_cpuid2.entries[0..kvm_cpuid2.nent as usize]
            .iter()
            .map(|e| Cpuid {
                func: e.function,
                index: if e.flags.contains(KvmCpuid2Flag::SIGNIFCANT_INDEX) {
                    Some(e.index)
                } else {
                    None
                },
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
            })
            .collect::<Vec<_>>();
        Ok(cpuids)
    }

    fn core_get_boot_info(&self) -> Result<(CoreBootInfo, Vec<VirtioDeviceSpec>), Error> {
        self.bridge.core_get_boot_info()
    }

    fn core_read_payload(
        &self,
        kind: PayloadKind,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        self.bridge.core_read_payload(kind, offset, dst)
    }

    fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> Result<(), Error> {
        self.bridge.core_virtio_start(dev, driver_features, queues)
    }

    fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> Result<(), Error> {
        self.bridge.core_virtio_notify(dev, queue_index)
    }

    fn core_virtio_reset(&self, dev: Handle) -> Result<(), Error> {
        self.bridge.core_virtio_reset(dev)
    }

    fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> Result<(), Error> {
        self.bridge
            .core_virtio_update_irq(dev, config_msi, queue_msis)
    }

    fn core_serial_tx(&self, byte: u8) -> Result<(), Error> {
        self.bridge.core_serial_tx(byte)
    }

    fn core_serial_rx(&self, dst: &mut [u8]) -> Result<usize, Error> {
        self.bridge.core_serial_rx(dst)
    }

    fn core_notify_shutdown(&self) -> Result<(), Error> {
        self.bridge.core_notify_shutdown()
    }
}

#[derive(Debug)]
pub struct KvmMemPages {
    addr: NonNull<c_void>,
    len: usize,
}

unsafe impl Send for KvmMemPages {}
unsafe impl Sync for KvmMemPages {}

impl KvmMemPages {
    pub fn new_shared(bridge: &SharedCoreBridge, size: usize) -> std::io::Result<Self> {
        let aligned_size = (size + 4095) & !4095;
        let offset = bridge
            .ram_next_offset
            .fetch_add(aligned_size as u64, Ordering::AcqRel);
        let total_len = bridge.ram_len.load(Ordering::Acquire);
        let base = bridge.ram_base.load(Ordering::Acquire);
        if base == 0
            || offset
                .checked_add(aligned_size as u64)
                .map_or(true, |end| end > total_len)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "shared guest RAM arena exhausted",
            ));
        }
        let ptr = (base + offset) as usize as *mut c_void;
        let addr = NonNull::new(ptr).expect("shared guest RAM pointer should not be null");
        Ok(Self {
            addr,
            len: aligned_size,
        })
    }
}

impl MemPages for KvmMemPages {
    fn addr(&self) -> u64 {
        self.addr.as_ptr() as usize as u64
    }

    fn size(&self) -> usize {
        self.len
    }

    fn sync(&self) -> std::io::Result<()> {
        ffi!(unsafe { msync(self.addr.as_ptr(), self.len, MS_ASYNC) })?;
        Ok(())
    }

    fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()> {
        if offset.checked_add(dst.len()).map_or(true, |end| end > self.len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "KvmMemPages::read out of bounds",
            ));
        }
        let src = unsafe {
            std::slice::from_raw_parts((self.addr.as_ptr() as *const u8).add(offset), dst.len())
        };
        dst.copy_from_slice(src);
        Ok(())
    }

    fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
        if offset.checked_add(src.len()).map_or(true, |end| end > self.len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "KvmMemPages::write out of bounds",
            ));
        }
        let dst = unsafe {
            std::slice::from_raw_parts_mut((self.addr.as_ptr() as *mut u8).add(offset), src.len())
        };
        dst.copy_from_slice(src);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Pthread(libc::pthread_t);

unsafe impl Send for Pthread {}
unsafe impl Sync for Pthread {}

struct ImmediateExitPtr(*mut AtomicU8);
unsafe impl Send for ImmediateExitPtr {}
unsafe impl Sync for ImmediateExitPtr {}

struct VcpuControl {
    pthread: Pthread,
    immediate_exit: ImmediateExitPtr,
}

pub struct KvmVm {
    fd: Arc<OwnedFd>,
    vcpu_mmap_size: usize,
    memory_created: bool,
    vcpus: Mutex<BTreeMap<u32, VcpuControl>>,
    bridge: Arc<SharedCoreBridge>,
}

impl Debug for KvmVm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmVm")
            .field("fd", &self.fd)
            .field("vcpu_mmap_size", &self.vcpu_mmap_size)
            .finish()
    }
}

#[derive(Debug)]
pub struct KvmMemory {
    fd: Arc<OwnedFd>,
    bridge: Arc<SharedCoreBridge>,
}

impl VmMemory for KvmMemory {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
        size: usize,
        hva: u64,
        option: MemMapOption,
    ) -> Result<(), Error> {
        let mut flags = KvmMemFlag::empty();
        if !option.read || !option.exec {
            return Err(Error::MemMapOption {
                option,
                hypervisor: "kvm",
            });
        }
        if !option.write {
            flags |= KvmMemFlag::READONLY;
        }
        if option.log_dirty {
            flags |= KvmMemFlag::LOG_DIRTY_PAGES;
        }
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa,
            memory_size: size as _,
            userspace_addr: hva,
            flags,
        };
        unsafe { kvm_set_user_memory_region(&self.fd, &region) }?;

        let ram_base = self.bridge.ram_base.load(Ordering::Acquire);
        if (slot as usize) < MAX_RAM_SLOTS && hva >= ram_base {
            let shm = self.bridge.shm;
            let lock = unsafe { &(*shm).ram_slots_lock };
            spin_lock(lock);
            unsafe {
                (*shm).ram_slots[slot as usize] = ShmGuestRamSlot {
                    gpa,
                    size: size as u64,
                    shm_offset: hva - ram_base,
                    active: 1,
                    _pad: 0,
                };
            }
            spin_unlock(lock);
        }
        Ok(())
    }

    fn unmap(&self, slot: u32, gpa: u64, _size: usize) -> Result<(), Error> {
        let flags = KvmMemFlag::empty();
        let region = KvmUserspaceMemoryRegion {
            slot,
            guest_phys_addr: gpa,
            memory_size: 0,
            userspace_addr: 0,
            flags,
        };
        unsafe { kvm_set_user_memory_region(&self.fd, &region) }?;
        if (slot as usize) < MAX_RAM_SLOTS {
            let shm = self.bridge.shm;
            let lock = unsafe { &(*shm).ram_slots_lock };
            spin_lock(lock);
            unsafe {
                (*shm).ram_slots[slot as usize].active = 0;
            }
            spin_unlock(lock);
        }
        Ok(())
    }

    fn max_mem_slots(&self) -> Result<u32, Error> {
        let ret = unsafe { kvm_check_extension(&self.fd, KVM_CAP_NR_MEMSLOTS) }?;
        Ok(ret as u32)
    }

    fn register_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        let region = KvmEncRegion {
            addr,
            size: size as u64,
        };
        unsafe { kvm_memory_encrypt_reg_region(&self.fd, &region) }?;
        Ok(())
    }

    fn deregister_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        let region = KvmEncRegion {
            addr,
            size: size as u64,
        };
        unsafe { kvm_memory_encrypt_unreg_region(&self.fd, &region) }?;
        Ok(())
    }

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
        self.bridge
            .ensure_mapped()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Arc::new(KvmMemPages::new_shared(&self.bridge, size)?))
    }
}

#[derive(Debug)]
pub struct KvmIntxSender {
    event_fd: OwnedFd,
}

impl IntxSender for KvmIntxSender {
    fn send(&self) -> Result<(), Error> {
        ffi!(unsafe { write(self.event_fd.as_raw_fd(), &1u64 as *const _ as _, 8) })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct KvmMsiSender {
    vm_fd: Arc<OwnedFd>,
}

impl MsiSender for KvmMsiSender {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        let kvm_msi = KvmMsi {
            address_lo: addr as u32,
            address_hi: (addr >> 32) as u32,
            data,
            ..Default::default()
        };
        unsafe { kvm_signal_msi(&self.vm_fd, &kvm_msi) }?;
        Ok(())
    }
}

impl KvmVm {
    fn check_extension(&self, id: u64) -> Result<bool, Error> {
        let ret = unsafe { kvm_check_extension(&self.fd, id) }?;
        Ok(ret == 1)
    }
}

impl Vm for KvmVm {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error> {
        let vcpu_fd = unsafe { kvm_create_vcpu(&self.fd, id) }?;
        let kvm_run = unsafe { KvmRunBlock::new(vcpu_fd, self.vcpu_mmap_size) }?;
        let mut kvm_vcpu = KvmVcpu {
            fd: unsafe { OwnedFd::from_raw_fd(vcpu_fd) },
            kvm_run,
        };
        let immediate_exit = ImmediateExitPtr(kvm_vcpu.immediate_exit_ptr());
        self.vcpus.lock().insert(
            id,
            VcpuControl {
                pthread: Pthread(unsafe { libc::pthread_self() }),
                immediate_exit,
            },
        );
        Ok(Box::new(kvm_vcpu))
    }

    fn stop_vcpu(&self, id: u32) -> Result<(), Error> {
        let vcpus = self.vcpus.lock();
        let Some(ctrl) = vcpus.get(&id) else {
            return Err(Error::Unexpected {
                msg: format!("cannot find vcpu {id}"),
            });
        };
        unsafe { (*ctrl.immediate_exit.0).store(1, Ordering::SeqCst) };
        ffi!(unsafe { libc::pthread_kill(ctrl.pthread.0, SIGRTMIN()) })?;
        Ok(())
    }

    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error> {
        if self.memory_created {
            Err(Error::CreatingMultipleMemory)
        } else {
            let kvm_memory = KvmMemory {
                fd: self.fd.clone(),
                bridge: self.bridge.clone(),
            };
            self.memory_created = true;
            Ok(Box::new(kvm_memory))
        }
    }

    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error> {
        if !self.check_extension(KVM_CAP_IRQFD)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_IRQFD".to_string(),
            })?;
        }
        let event_fd = ffi!(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) })?;
        let request = KvmIrqfd {
            fd: event_fd as u32,
            gsi: pin as u32,
            ..Default::default()
        };
        unsafe { kvm_irqfd(&self.fd, &request) }?;
        Ok(Box::new(KvmIntxSender {
            event_fd: unsafe { OwnedFd::from_raw_fd(event_fd) },
        }))
    }

    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error> {
        if !self.check_extension(KVM_CAP_SIGNAL_MSI)? {
            Err(Error::LackCap {
                cap: "KVM_CAP_SIGNAL_MSI".to_string(),
            })?;
        }
        Ok(Box::new(KvmMsiSender {
            vm_fd: self.fd.clone(),
        }))
    }
}
