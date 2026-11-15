// SPDX-License-Identifier: GPL-2.0
//! Safe `#![no_std] + alloc` wrappers around `airlock_shim.c` (`airlock_kapi_*`),
//! global kernel heap allocator, logging, spinlocks, waitqueues, kthreads, and Wasmtime TLS/sync.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const AIRLOCK_CAP_SVM: u32 = 1 << 0;
pub const AIRLOCK_CAP_NPT: u32 = 1 << 1;
pub const AIRLOCK_CAP_IOMMU: u32 = 1 << 2;

pub const PAGE_SIZE_4K: u64 = 4096;

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

#[repr(C)]
pub struct AirlockWq {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct AirlockKthread {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct AirlockIommuCtx {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct AirlockPciDev {
    _opaque: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AirlockKapiBarDesc {
    pub phys_start: u64,
    pub size: u64,
    pub kind: u8,
    pub prefetchable: u8,
    pub _pad: [u8; 6],
}

pub type AirlockEventfdCb = unsafe extern "C" fn(opaque: *mut c_void);
pub type AirlockKthreadFn = unsafe extern "C" fn(opaque: *mut c_void);

#[allow(dead_code)]
unsafe extern "C" {
    pub fn airlock_kapi_log_info(msg: *const u8, len: usize);
    pub fn airlock_kapi_log_err(msg: *const u8, len: usize);

    pub fn airlock_kapi_alloc(size: usize, align: usize, zeroed: bool) -> *mut u8;
    pub fn airlock_kapi_free(ptr: *mut u8);

    pub fn airlock_kapi_num_possible_cpus() -> u32;
    pub fn airlock_kapi_raw_smp_processor_id() -> u32;
    pub fn airlock_kapi_current_task() -> usize;
    pub fn airlock_kapi_ktime_get_ns() -> u64;
    pub fn airlock_kapi_ktime_get_real_ns() -> u64;
    pub fn airlock_kapi_tsc_khz() -> u32;
    pub fn airlock_kapi_send_reschedule(cpu: u32);
    pub fn airlock_kapi_cond_resched();
    pub fn airlock_kapi_signal_pending() -> bool;

    pub fn airlock_kapi_alloc_contig_pages(
        order: u32,
        nid: i32,
        out_phys: *mut u64,
        out_virt: *mut *mut u8,
    ) -> i32;
    pub fn airlock_kapi_free_contig_pages(phys: u64, order: u32);
    pub fn airlock_kapi_phys_to_virt(phys: u64) -> *mut u8;

    pub fn airlock_kapi_wq_alloc() -> *mut AirlockWq;
    pub fn airlock_kapi_wq_wake(wq: *mut AirlockWq);
    pub fn airlock_kapi_wq_wait_ns(wq: *mut AirlockWq, timeout_ns: u64) -> i32;
    pub fn airlock_kapi_wq_free(wq: *mut AirlockWq);

    pub fn airlock_kapi_kthread_spawn(
        func: AirlockKthreadFn,
        opaque: *mut c_void,
        name: *const u8,
        name_len: usize,
        out_kt: *mut *mut AirlockKthread,
    ) -> i32;
    pub fn airlock_kapi_kthread_should_stop() -> bool;
    pub fn airlock_kapi_kthread_stop(kt: *mut AirlockKthread);

    pub fn airlock_kapi_svm_run_slice(
        gprs: *mut u64,
        vmcb_pa: u64,
        vmcb_va: *mut c_void,
        fpu_buf: *mut u8,
        guest_xcr0: u64,
        guest_tsc_aux: u64,
        kick_flag: *const u32,
        on_cpu_slot: *mut u32,
        last_pcpu: *mut u32,
    ) -> i32;

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

    pub fn airlock_kapi_wasm_call_enter() -> u64;
    pub fn airlock_kapi_wasm_call_exit(saved_state: u64);

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

    pub fn airlock_kapi_iommu_alloc_for_bdf(
        bdf: u16,
        out_ctx: *mut *mut AirlockIommuCtx,
    ) -> i32;
    pub fn airlock_kapi_iommu_map(
        ctx: *mut AirlockIommuCtx,
        iova: u64,
        paddr: u64,
        size: u64,
        readable: bool,
        writable: bool,
    ) -> i32;
    pub fn airlock_kapi_iommu_unmap(ctx: *mut AirlockIommuCtx, iova: u64, size: u64);
    pub fn airlock_kapi_iommu_free(ctx: *mut AirlockIommuCtx);

    pub fn airlock_kapi_pci_open(
        bdf: u16,
        iommu_ctx: *mut AirlockIommuCtx,
        hv_ptr: usize,
        out_bars: *mut AirlockKapiBarDesc,
        out_dev: *mut *mut AirlockPciDev,
    ) -> i32;
    pub fn airlock_kapi_pci_close(adev: *mut AirlockPciDev);
    pub fn airlock_kapi_pci_reset(adev: *mut AirlockPciDev) -> i32;
    pub fn airlock_kapi_pci_read_config(
        adev: *mut AirlockPciDev,
        offset: u16,
        size: u8,
        out_val: *mut u32,
    ) -> i32;
    pub fn airlock_kapi_pci_write_config(
        adev: *mut AirlockPciDev,
        offset: u16,
        size: u8,
        val: u32,
    ) -> i32;
    pub fn airlock_kapi_pci_bar_io(
        adev: *mut AirlockPciDev,
        bar_idx: u8,
        offset: u64,
        size: u8,
        is_write: bool,
        write_val: u64,
        out_val: *mut u64,
    ) -> i32;
    pub fn airlock_kapi_pci_configure_msix(
        adev: *mut AirlockPciDev,
        entry_idx: u16,
        enabled: bool,
        guest_addr: u64,
        guest_data: u32,
    ) -> i32;
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
// TSC & Paravirtual Clock Helpers
// ============================================================================

#[inline]
pub fn rdtsc_now() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[inline]
pub fn tsc_khz() -> u32 {
    let khz = unsafe { airlock_kapi_tsc_khz() };
    if khz == 0 { 3_000_000 } else { khz }
}

#[inline]
pub fn nanos_to_tsc_delta(nanos: u64) -> u64 {
    let khz = tsc_khz() as u128;
    (((nanos as u128) * khz) / 1_000_000u128) as u64
}

#[inline]
pub fn tsc_delta_to_nanos(delta_tsc: u64) -> u64 {
    let khz = tsc_khz() as u128;
    (((delta_tsc as u128) * 1_000_000u128) / khz) as u64
}

/// Returns `(wall_clock_ns, system_time_ns, tsc_timestamp, tsc_to_system_mul, tsc_shift)`.
pub fn pvclock_snapshot() -> (u64, u64, u64, u32, i8) {
    let tsc_ts = rdtsc_now();
    let mono_ns = unsafe { airlock_kapi_ktime_get_ns() };
    let real_ns = unsafe { airlock_kapi_ktime_get_real_ns() };
    let boot_wall_ns = real_ns.saturating_sub(mono_ns);

    let hz = (tsc_khz() as u128) * 1000u128;
    let mut shift: i8 = 0;
    let mut scaled_ns: u128 = 1_000_000_000u128 << 32;
    while scaled_ns < (hz << 31) && shift > -31 {
        scaled_ns <<= 1;
        shift -= 1;
    }
    while (scaled_ns >> 32) >= hz && shift < 31 {
        scaled_ns >>= 1;
        shift += 1;
    }
    let mul = (scaled_ns / hz) as u32;
    (boot_wall_ns, mono_ns, tsc_ts, mul, shift)
}

// ============================================================================
// RAII Wrappers for Contiguous Kernel Pages, Pinned User Memory, WaitQueue, Eventfd
// ============================================================================

pub struct ContigPages {
    phys: u64,
    virt: *mut u8,
    order: u32,
}

unsafe impl Send for ContigPages {}
unsafe impl Sync for ContigPages {}

impl ContigPages {
    pub fn alloc_order(order: u32) -> Result<Self, i32> {
        let mut phys = 0u64;
        let mut virt = null_mut();
        let rc = unsafe { airlock_kapi_alloc_contig_pages(order, -1, &mut phys, &mut virt) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(Self { phys, virt, order })
    }

    #[inline]
    pub fn phys(&self) -> u64 {
        self.phys
    }

    #[inline]
    pub fn virt(&self) -> *mut u8 {
        self.virt
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        4096usize << self.order
    }
}

impl Drop for ContigPages {
    fn drop(&mut self) {
        if self.phys != 0 {
            unsafe { airlock_kapi_free_contig_pages(self.phys, self.order) };
            self.phys = 0;
        }
    }
}

pub struct PinnedUserMem {
    raw: *mut AirlockPinnedMem,
    kva: *mut u8,
    byte_len: u64,
}

unsafe impl Send for PinnedUserMem {}
unsafe impl Sync for PinnedUserMem {}

impl PinnedUserMem {
    pub fn pin(uaddr: u64, byte_len: u64, writable: bool, map_kva: bool) -> Result<Self, i32> {
        let mut raw = null_mut();
        let mut kva = null_mut();
        let rc = unsafe {
            airlock_kapi_pin_user_mem(uaddr, byte_len, writable, map_kva, &mut raw, &mut kva)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(Self { raw, kva, byte_len })
    }

    #[inline]
    pub fn kva(&self) -> *mut u8 {
        self.kva
    }

    #[inline]
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[inline]
    pub fn num_pages(&self) -> usize {
        unsafe { airlock_kapi_pinned_num_pages(self.raw) as usize }
    }

    #[inline]
    pub fn page_phys(&self, page_idx: usize) -> Option<u64> {
        let pa = unsafe { airlock_kapi_pinned_page_phys(self.raw, page_idx as u64) };
        (pa != 0).then_some(pa)
    }

    pub fn copy_to_slice(&self, offset: u64, dst: &mut [u8]) -> Result<(), i32> {
        if dst.is_empty() {
            return Ok(());
        }
        let rc =
            unsafe { airlock_kapi_copy_from_pinned(self.raw, offset, dst.as_mut_ptr(), dst.len()) };
        if rc < 0 { Err(rc) } else { Ok(()) }
    }
}

impl Drop for PinnedUserMem {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { airlock_kapi_unpin_user_mem(self.raw) };
            self.raw = null_mut();
        }
    }
}

pub struct WaitQueue {
    raw: *mut AirlockWq,
}

unsafe impl Send for WaitQueue {}
unsafe impl Sync for WaitQueue {}

impl WaitQueue {
    pub fn new() -> Result<Self, i32> {
        let raw = unsafe { airlock_kapi_wq_alloc() };
        if raw.is_null() {
            return Err(-12); // -ENOMEM
        }
        Ok(Self { raw })
    }

    #[inline]
    pub fn wake(&self) {
        unsafe { airlock_kapi_wq_wake(self.raw) };
    }

    #[inline]
    pub fn wait_timeout_ns(&self, timeout_ns: Option<u64>) {
        let ns = timeout_ns.unwrap_or(u64::MAX);
        unsafe {
            let _ = airlock_kapi_wq_wait_ns(self.raw, ns);
        }
    }
}

impl Drop for WaitQueue {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { airlock_kapi_wq_free(self.raw) };
            self.raw = null_mut();
        }
    }
}

pub struct EventfdBinding {
    raw: *mut AirlockEventfd,
}

unsafe impl Send for EventfdBinding {}
unsafe impl Sync for EventfdBinding {}

impl EventfdBinding {
    pub fn bind(
        fd: i32,
        cb: Option<AirlockEventfdCb>,
        opaque: *mut c_void,
    ) -> Result<Self, i32> {
        let mut raw = null_mut();
        let rc = unsafe { airlock_kapi_eventfd_bind(fd, cb, opaque, &mut raw) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(Self { raw })
    }

    #[inline]
    pub fn signal(&self) {
        unsafe { airlock_kapi_eventfd_signal(self.raw) };
    }
}

impl Drop for EventfdBinding {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { airlock_kapi_eventfd_unbind(self.raw) };
            self.raw = null_mut();
        }
    }
}

pub struct WasmCallGuard {
    saved_cet: u64,
}

impl WasmCallGuard {
    #[inline]
    pub fn enter() -> Self {
        let saved_cet = unsafe { airlock_kapi_wasm_call_enter() };
        Self { saved_cet }
    }
}

impl Drop for WasmCallGuard {
    #[inline]
    fn drop(&mut self) {
        unsafe { airlock_kapi_wasm_call_exit(self.saved_cet) };
    }
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
// Atomic SpinLock
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

    #[inline]
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
// Task-Indexed Wasmtime `no_std` TLS + Custom Sync Primitives
// ============================================================================

const MAX_CONCURRENT_WASM_TASKS: usize = 256;

struct TaskTlsEntry {
    task: AtomicUsize,
    slots: [AtomicUsize; 2],
}

impl TaskTlsEntry {
    const fn empty() -> Self {
        Self {
            task: AtomicUsize::new(0),
            slots: [AtomicUsize::new(0), AtomicUsize::new(0)],
        }
    }
}

static WASMTIME_TASK_TLS: [TaskTlsEntry; MAX_CONCURRENT_WASM_TASKS] =
    [const { TaskTlsEntry::empty() }; MAX_CONCURRENT_WASM_TASKS];

#[no_mangle]
pub unsafe extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    if slot >= 2 {
        return null_mut();
    }
    let me = unsafe { airlock_kapi_current_task() };
    let start = (me >> 6) % MAX_CONCURRENT_WASM_TASKS;
    for step in 0..MAX_CONCURRENT_WASM_TASKS {
        let idx = (start + step) % MAX_CONCURRENT_WASM_TASKS;
        if WASMTIME_TASK_TLS[idx].task.load(Ordering::Acquire) == me {
            return WASMTIME_TASK_TLS[idx].slots[slot].load(Ordering::Relaxed) as *mut u8;
        }
    }
    null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_tls_set(slot: usize, ptr: *mut u8) {
    if slot >= 2 {
        return;
    }
    let me = unsafe { airlock_kapi_current_task() };
    let start = (me >> 6) % MAX_CONCURRENT_WASM_TASKS;

    for step in 0..MAX_CONCURRENT_WASM_TASKS {
        let idx = (start + step) % MAX_CONCURRENT_WASM_TASKS;
        let e = &WASMTIME_TASK_TLS[idx];
        if e.task.load(Ordering::Acquire) == me {
            e.slots[slot].store(ptr as usize, Ordering::Relaxed);
            if ptr.is_null()
                && e.slots[0].load(Ordering::Relaxed) == 0
                && e.slots[1].load(Ordering::Relaxed) == 0
            {
                e.task.store(0, Ordering::Release);
            }
            return;
        }
    }

    if ptr.is_null() {
        return;
    }

    for step in 0..MAX_CONCURRENT_WASM_TASKS {
        let idx = (start + step) % MAX_CONCURRENT_WASM_TASKS;
        let e = &WASMTIME_TASK_TLS[idx];
        if e.task
            .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            e.slots[slot].store(ptr as usize, Ordering::Relaxed);
            return;
        }
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
