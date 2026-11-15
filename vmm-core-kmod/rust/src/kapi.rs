// SPDX-License-Identifier: GPL-2.0
//! Safe `#![no_std] + alloc` wrappers around `airlock_shim.c` (`airlock_kapi_*`),
//! global kernel heap allocator, logging macros, spinlocks, and Wasmtime C-ABI hooks.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

pub const AIRLOCK_CAP_SVM: u32 = 1 << 0;
pub const AIRLOCK_CAP_NPT: u32 = 1 << 1;
pub const AIRLOCK_CAP_IOMMU: u32 = 1 << 2;

pub const MAX_KERNEL_CPUS: usize = 512;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AirlockCreateVmReq {
    pub shm_uaddr: u64,
    pub shm_size: u64,
    pub ram_uaddr: u64,
    pub ram_size: u64,
    pub payload_uaddr: u64,
    pub payload_size: u64,
    pub cwasm_uaddr: u64,
    pub cwasm_size: u64,
    pub c2i_eventfd: i32,
    pub i2c_eventfd: i32,
}

#[repr(C)]
pub struct AirlockExecBuf {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct AirlockPinnedMem {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct AirlockEventfd {
    _opaque: [u8; 0],
}

pub type AirlockEventfdCb = unsafe extern "C" fn(opaque: *mut c_void);

#[allow(dead_code)]
unsafe extern "C" {
    pub fn airlock_kapi_log_info(msg: *const u8, len: usize);
    pub fn airlock_kapi_log_err(msg: *const u8, len: usize);

    pub fn airlock_kapi_alloc(size: usize, align: usize, zeroed: bool) -> *mut u8;
    pub fn airlock_kapi_free(ptr: *mut u8);

    pub fn airlock_kapi_num_possible_cpus() -> u32;
    pub fn airlock_kapi_raw_smp_processor_id() -> u32;
    pub fn airlock_kapi_get_cpu() -> u32;
    pub fn airlock_kapi_put_cpu();
    pub fn airlock_kapi_ktime_get_ns() -> u64;
    pub fn airlock_kapi_tsc_khz() -> u32;
    pub fn airlock_kapi_send_reschedule(cpu: u32);

    pub fn airlock_kapi_alloc_contig_pages(
        order: u32,
        nid: i32,
        out_phys: *mut u64,
        out_virt: *mut *mut u8,
    ) -> i32;
    pub fn airlock_kapi_free_contig_pages(phys: u64, order: u32);
    pub fn airlock_kapi_phys_to_virt(phys: u64) -> *mut u8;

    pub fn airlock_kapi_cpu_hsave_pa(cpu: u32) -> u64;
    pub fn airlock_kapi_cpu_host_vmsave_pa(cpu: u32) -> u64;

    pub fn airlock_kapi_exec_alloc_from_user(
        uptr: *const u8,
        byte_len: usize,
        out_buf: *mut *mut AirlockExecBuf,
        out_ro_ptr: *mut *mut u8,
    ) -> i32;
    pub fn airlock_kapi_exec_set_rx(
        buf: *mut AirlockExecBuf,
        offset: usize,
        len: usize,
        executable: bool,
    ) -> i32;
    pub fn airlock_kapi_exec_free(buf: *mut AirlockExecBuf);

    pub fn airlock_kapi_ibt_enter() -> u64;
    pub fn airlock_kapi_ibt_exit(saved_cet: u64);

    pub fn airlock_kapi_pin_user_mem(
        uaddr: u64,
        byte_len: u64,
        writable: bool,
        map_kva: bool,
        out_mem: *mut *mut AirlockPinnedMem,
        out_kva: *mut *mut u8,
    ) -> i32;
    pub fn airlock_kapi_pinned_num_pages(mem: *const AirlockPinnedMem) -> u64;
    pub fn airlock_kapi_pinned_page_phys(mem: *const AirlockPinnedMem, page_idx: u64) -> u64;
    pub fn airlock_kapi_copy_from_pinned(
        mem: *const AirlockPinnedMem,
        offset: u64,
        dst: *mut u8,
        len: usize,
    ) -> i32;
    pub fn airlock_kapi_unpin_user_mem(mem: *mut AirlockPinnedMem);

    pub fn airlock_kapi_eventfd_bind(
        fd: i32,
        cb: Option<AirlockEventfdCb>,
        opaque: *mut c_void,
        out_efd: *mut *mut AirlockEventfd,
    ) -> i32;
    pub fn airlock_kapi_eventfd_signal(efd: *mut AirlockEventfd);
    pub fn airlock_kapi_eventfd_unbind(efd: *mut AirlockEventfd);
}

pub fn log_info_str(s: &str) {
    unsafe {
        airlock_kapi_log_info(s.as_ptr(), s.len());
    }
}

pub fn log_err_str(s: &str) {
    unsafe {
        airlock_kapi_log_err(s.as_ptr(), s.len());
    }
}

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => {{
        let msg = ::alloc::format!($($arg)*);
        $crate::kapi::log_info_str(&msg);
    }};
}

#[macro_export]
macro_rules! kerr {
    ($($arg:tt)*) => {{
        let msg = ::alloc::format!($($arg)*);
        $crate::kapi::log_err_str(&msg);
    }};
}

// ============================================================================
// Global Kernel Heap Allocator (`kvmalloc` / `kvfree`)
// ============================================================================

pub struct LinuxKernelAllocator;

unsafe impl GlobalAlloc for LinuxKernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { airlock_kapi_alloc(layout.size(), layout.align(), false) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { airlock_kapi_alloc(layout.size(), layout.align(), true) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { airlock_kapi_free(ptr) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: LinuxKernelAllocator = LinuxKernelAllocator;

// ============================================================================
// Ticket / Atomic SpinLock
// ============================================================================

pub struct SpinLock<T> {
    locked: AtomicUsize,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(val: T) -> Self {
        Self {
            locked: AtomicUsize::new(0),
            data: UnsafeCell::new(val),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(0, Ordering::Release);
    }
}

// ============================================================================
// Wasmtime `no_std` + `custom-sync-primitives` Platform C-ABI Hooks
// ============================================================================

static WASMTIME_TLS: [[AtomicUsize; 2]; MAX_KERNEL_CPUS] =
    [const { [AtomicUsize::new(0), AtomicUsize::new(0)] }; MAX_KERNEL_CPUS];

#[no_mangle]
pub unsafe extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    let cpu = unsafe { airlock_kapi_raw_smp_processor_id() } as usize;
    if cpu < WASMTIME_TLS.len() && slot < 2 {
        WASMTIME_TLS[cpu][slot].load(Ordering::Relaxed) as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_tls_set(slot: usize, ptr: *mut u8) {
    let cpu = unsafe { airlock_kapi_raw_smp_processor_id() } as usize;
    if cpu < WASMTIME_TLS.len() && slot < 2 {
        WASMTIME_TLS[cpu][slot].store(ptr as usize, Ordering::Relaxed);
    }
}

const RWLOCK_WRITER_BIT: usize = 1usize << (usize::BITS - 1);

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_lock_acquire(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    while atom
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_lock_release(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    atom.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_lock_free(_lock: *mut usize) {}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_read(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    loop {
        let cur = atom.load(Ordering::Relaxed);
        if (cur & RWLOCK_WRITER_BIT) == 0
            && atom
                .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_read_release(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    atom.fetch_sub(1, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_write(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    while atom
        .compare_exchange_weak(0, RWLOCK_WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_write_release(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    atom.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_free(_lock: *mut usize) {}
