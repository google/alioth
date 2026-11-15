/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AIRLOCK_KAPI_H_
#define _AIRLOCK_KAPI_H_

#include <linux/types.h>
#include "airlock_uapi.h"

/* =========================================================================
 * Narrow C <-> Rust Kernel FFI Contract
 *
 * `airlock_kapi_*` functions are implemented in `airlock_shim.c` (using
 * official Linux kernel headers, inline helpers, and exported GPL symbols).
 * `airlock_rust_*` functions are implemented in `libairlock_rust.a`.
 * ========================================================================= */

/* Logging */
void airlock_kapi_log_info(const char *msg, size_t len);
void airlock_kapi_log_err(const char *msg, size_t len);

/* Heap allocation for Rust `#[global_allocator]` (page/slab backed, zeroed option) */
void *airlock_kapi_alloc(size_t size, size_t align, bool zeroed);
void airlock_kapi_free(void *ptr);

/* CPU / SMP / Time */
u32 airlock_kapi_num_possible_cpus(void);
u32 airlock_kapi_raw_smp_processor_id(void);
u32 airlock_kapi_get_cpu(void);
void airlock_kapi_put_cpu(void);
u64 airlock_kapi_ktime_get_ns(void);
u32 airlock_kapi_tsc_khz(void);
void airlock_kapi_send_reschedule(u32 cpu);

/* Physical 4 KiB page allocation (for VMCBs, IOPM/MSRPM, Stage-2 NPT tables) */
int airlock_kapi_alloc_contig_pages(u32 order, int nid, u64 *out_phys, void **out_virt);
void airlock_kapi_free_contig_pages(u64 phys, u32 order);
void *airlock_kapi_phys_to_virt(u64 phys);

/* Per-CPU SVM save-area physical addresses allocated at module init */
u64 airlock_kapi_cpu_hsave_pa(u32 cpu);
u64 airlock_kapi_cpu_host_vmsave_pa(u32 cpu);

/* Executable `.cwasm` W^X code backing (`vmap` + `lookup_address` PAGE_KERNEL_ROX) */
struct airlock_exec_buf;
int airlock_kapi_exec_alloc_from_user(const void __user *uptr, size_t byte_len,
                                      struct airlock_exec_buf **out_buf,
                                      void **out_ro_ptr);
int airlock_kapi_exec_set_rx(struct airlock_exec_buf *buf, size_t offset,
                             size_t len, bool executable);
void airlock_kapi_exec_free(struct airlock_exec_buf *buf);

/* IBT (`MSR_IA32_S_CET`) guard when calling Cranelift `.cwasm` functions */
u64 airlock_kapi_ibt_enter(void);
void airlock_kapi_ibt_exit(u64 saved_cet);

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

/*Rust entrypoints called from `airlock_shim.c` */
int airlock_rust_init(void);
void airlock_rust_exit(void);
u32 airlock_rust_get_caps(void);
int airlock_rust_vm_create(const struct airlock_create_vm *req, void **out_vm);
void airlock_rust_vm_destroy(void *vm);

#endif /* _AIRLOCK_KAPI_H_ */
