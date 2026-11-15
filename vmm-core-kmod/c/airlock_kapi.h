/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AIRLOCK_KAPI_H_
#define _AIRLOCK_KAPI_H_

#include <linux/types.h>
#include "airlock_uapi.h"

/* =========================================================================
 * Narrow C <-> Rust Kernel FFI Contract
 * ========================================================================= */

/* Logging */
void airlock_kapi_log_info(const char *msg, size_t len);
void airlock_kapi_log_err(const char *msg, size_t len);

/* Heap allocation for Rust `#[global_allocator]` */
void *airlock_kapi_alloc(size_t size, size_t align, bool zeroed);
void airlock_kapi_free(void *ptr);

/* CPU / SMP / Task / Time */
u32 airlock_kapi_num_possible_cpus(void);
u32 airlock_kapi_raw_smp_processor_id(void);
uintptr_t airlock_kapi_current_task(void);
u64 airlock_kapi_ktime_get_ns(void);
u64 airlock_kapi_ktime_get_real_ns(void);
u32 airlock_kapi_tsc_khz(void);
void airlock_kapi_send_reschedule(u32 cpu);
void airlock_kapi_cond_resched(void);
bool airlock_kapi_signal_pending(void);

/* Physical 4 KiB page allocation (for VMCBs, FPU areas, IOPM/MSRPM, Stage-2 NPT tables) */
int airlock_kapi_alloc_contig_pages(u32 order, int nid, u64 *out_phys, void **out_virt);
void airlock_kapi_free_contig_pages(u64 phys, u32 order);
void *airlock_kapi_phys_to_virt(u64 phys);

/* Waitqueue + nanosecond hrtimer sleep (for blocking guest `HLT`, AP pre-SIPI, and RX worker) */
struct airlock_wq;
struct airlock_wq *airlock_kapi_wq_alloc(void);
void airlock_kapi_wq_wake(struct airlock_wq *wq);
/* `timeout_ns == U64_MAX` waits indefinitely until woken, signal, or kthread_stop. */
int airlock_kapi_wq_wait_ns(struct airlock_wq *wq, u64 timeout_ns);
void airlock_kapi_wq_free(struct airlock_wq *wq);

/* Kernel threads (`airlock-vcpu/%u` and `airlock-rx`) */
struct airlock_kthread;
typedef void (*airlock_kthread_fn_t)(void *opaque);
int airlock_kapi_kthread_spawn(airlock_kthread_fn_t fn, void *opaque,
                               const char *name, size_t name_len,
                               struct airlock_kthread **out_kt);
bool airlock_kapi_kthread_should_stop(void);
void airlock_kapi_kthread_stop(struct airlock_kthread *kt);

/*
 * KVM-independent per-slice SVM guest entry (`airlock_svm_vmrun` + FPU/XSAVE +
 * IRQ-off `EFER.SVME` & `MSR_VM_HSAVE_PA` save/restore).
 * Returns:
 *   0 = `VMRUN` executed and exited normally (exit details in VMCB)
 *   1 = pre-entry abort (`need_resched`, `signal_pending`, `kthread_should_stop`, or `*kick_flag`)
 */
int airlock_kapi_svm_run_slice(u64 *gprs, u64 vmcb_pa, void *vmcb_va,
                               u8 *fpu_buf, u64 guest_xcr0, u64 guest_tsc_aux,
                               const u32 *kick_flag, u32 *on_cpu_slot,
                               u32 *last_pcpu);

/* Executable `.cwasm` W^X code backing (`vmap` + `lookup_address` PAGE_KERNEL_ROX) */
struct airlock_exec_buf;
int airlock_kapi_exec_alloc_from_user(const void __user *uptr, size_t byte_len,
                                      struct airlock_exec_buf **out_buf,
                                      void **out_ro_ptr);
int airlock_kapi_exec_set_rx(struct airlock_exec_buf *buf, size_t offset,
                             size_t len, bool executable);
void airlock_kapi_exec_free(struct airlock_exec_buf *buf);

/* IBT (`MSR_IA32_S_CET`) guard around Cranelift `.cwasm` calls */
u64 airlock_kapi_wasm_call_enter(void);
void airlock_kapi_wasm_call_exit(u64 saved_state);

/* Pinned user memory (`BridgeShm`, Guest RAM, Boot Payload) */
struct airlock_pinned_mem;
int airlock_kapi_pin_user_mem(u64 uaddr, u64 byte_len, bool writable, bool map_kva,
                              struct airlock_pinned_mem **out_mem, void **out_kva);
u64 airlock_kapi_pinned_num_pages(const struct airlock_pinned_mem *mem);
u64 airlock_kapi_pinned_page_phys(const struct airlock_pinned_mem *mem, u64 page_idx);
int airlock_kapi_copy_from_pinned(const struct airlock_pinned_mem *mem, u64 offset,
                                  void *dst, size_t len);
void airlock_kapi_unpin_user_mem(struct airlock_pinned_mem *mem);

/* Eventfd doorbells (`c2i` signal & `i2c` wakeup callback) */
struct airlock_eventfd;
typedef void (*airlock_eventfd_cb_t)(void *opaque);
int airlock_kapi_eventfd_bind(int fd, airlock_eventfd_cb_t cb, void *opaque,
                              struct airlock_eventfd **out_efd);
void airlock_kapi_eventfd_signal(struct airlock_eventfd *efd);
void airlock_kapi_eventfd_unbind(struct airlock_eventfd *efd);

/* Rust entrypoints called from `airlock_shim.c` */
int airlock_rust_init(void);
void airlock_rust_exit(void);
u32 airlock_rust_get_caps(void);
int airlock_rust_vm_create(const struct airlock_create_vm *req, void **out_vm);
void airlock_rust_vm_destroy(void *vm);

#endif /* _AIRLOCK_KAPI_H_ */
