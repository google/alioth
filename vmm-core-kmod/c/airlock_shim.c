// SPDX-License-Identifier: GPL-2.0
/*
 * Out-of-tree Linux Ring-0 C shim for `airlock.ko` (`vmm-core-host`).
 *
 * Bridges Linux kernel C macros, VFS/miscdevice/anon_inode registration,
 * memory pinning, W^X `.cwasm` PTE permissions, kthreads, waitqueues, and
 * KVM-independent per-slice SVM guest entry to `libairlock_rust.a`.
 */

#define pr_fmt(fmt) "airlock: " fmt

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/cpufeature.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/percpu.h>
#include <linux/poll.h>
#include <linux/preempt.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include <asm/fpu/api.h>
#include <asm/ibt.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/tsc.h>

#include "airlock_kapi.h"

extern void airlock_svm_vmrun(u64 *gprs, u64 vmcb_pa, u64 host_vmsave_pa);

/* =========================================================================
 * Logging & Heap Allocation (`#[global_allocator]`)
 * ========================================================================= */

void airlock_kapi_log_info(const char *msg, size_t len)
{
    pr_info("%.*s\n", (int)len, msg);
}

void airlock_kapi_log_err(const char *msg, size_t len)
{
    pr_err("%.*s\n", (int)len, msg);
}

void *airlock_kapi_alloc(size_t size, size_t align, bool zeroed)
{
    size_t req = size ? size : 1;
    gfp_t gfp = (in_atomic() ? GFP_ATOMIC : GFP_KERNEL) | (zeroed ? __GFP_ZERO : 0);

    if (align > ARCH_KMALLOC_MINALIGN) {
        if (align > PAGE_SIZE)
            return NULL;
        req = ALIGN(req, align);
    }
    if (in_atomic())
        return kmalloc(req, gfp);
    return kvmalloc(req, gfp);
}

void airlock_kapi_free(void *ptr)
{
    if (ptr)
        kvfree(ptr);
}

/* =========================================================================
 * CPU / SMP / Task / Time & Per-CPU SVM Save Areas
 * ========================================================================= */

static DEFINE_PER_CPU(struct page *, airlock_hsave_page);
static DEFINE_PER_CPU(struct page *, airlock_host_vmsave_page);
static DEFINE_PER_CPU(u64, airlock_hsave_pa);
static DEFINE_PER_CPU(u64, airlock_host_vmsave_pa);
static DEFINE_PER_CPU(call_single_data_t, airlock_kick_csd);
static DEFINE_PER_CPU(raw_spinlock_t, airlock_kick_csd_lock);

u32 airlock_kapi_num_possible_cpus(void)
{
    return (u32)num_possible_cpus();
}

u32 airlock_kapi_raw_smp_processor_id(void)
{
    return (u32)raw_smp_processor_id();
}

uintptr_t airlock_kapi_current_task(void)
{
    return (uintptr_t)current;
}

u64 airlock_kapi_ktime_get_ns(void)
{
    return ktime_get_ns();
}

u64 airlock_kapi_ktime_get_real_ns(void)
{
    return ktime_get_real_ns();
}

u32 airlock_kapi_tsc_khz(void)
{
    return tsc_khz;
}

static void airlock_kick_ipi_noop(void *info)
{
    (void)info;
}

void airlock_kapi_send_reschedule(u32 cpu)
{
    unsigned long flags;
    raw_spinlock_t *lock;

    if (cpu >= nr_cpu_ids || !cpu_online(cpu))
        return;
    lock = &per_cpu(airlock_kick_csd_lock, cpu);
    raw_spin_lock_irqsave(lock, flags);
    smp_call_function_single_async((int)cpu, &per_cpu(airlock_kick_csd, cpu));
    raw_spin_unlock_irqrestore(lock, flags);
}

void airlock_kapi_cond_resched(void)
{
    cond_resched();
}

bool airlock_kapi_signal_pending(void)
{
    return signal_pending(current);
}

int airlock_kapi_alloc_contig_pages(u32 order, int nid, u64 *out_phys, void **out_virt)
{
    struct page *p;
    gfp_t gfp = (in_atomic() ? GFP_ATOMIC : GFP_KERNEL) | __GFP_ZERO;

    p = (nid < 0) ? alloc_pages(gfp, order) : alloc_pages_node(nid, gfp, order);
    if (!p)
        return -ENOMEM;
    *out_phys = page_to_phys(p);
    *out_virt = page_address(p);
    return 0;
}

void airlock_kapi_free_contig_pages(u64 phys, u32 order)
{
    if (!phys)
        return;
    __free_pages(phys_to_page(phys), order);
}

void *airlock_kapi_phys_to_virt(u64 phys)
{
    return page_address(phys_to_page(phys));
}

static int airlock_alloc_percpu_svm_areas(void)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        int nid = cpu_to_node(cpu);
        struct page *hs = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, 0);
        struct page *vms = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, 0);

        if (!hs || !vms) {
            if (hs)
                __free_page(hs);
            if (vms)
                __free_page(vms);
            return -ENOMEM;
        }
        per_cpu(airlock_hsave_page, cpu) = hs;
        per_cpu(airlock_host_vmsave_page, cpu) = vms;
        per_cpu(airlock_hsave_pa, cpu) = page_to_phys(hs);
        per_cpu(airlock_host_vmsave_pa, cpu) = page_to_phys(vms);
        INIT_CSD(&per_cpu(airlock_kick_csd, cpu), airlock_kick_ipi_noop, NULL);
        raw_spin_lock_init(&per_cpu(airlock_kick_csd_lock, cpu));
    }
    return 0;
}

static void airlock_free_percpu_svm_areas(void)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        struct page *hs = per_cpu(airlock_hsave_page, cpu);
        struct page *vms = per_cpu(airlock_host_vmsave_page, cpu);

        if (hs) {
            __free_page(hs);
            per_cpu(airlock_hsave_page, cpu) = NULL;
            per_cpu(airlock_hsave_pa, cpu) = 0;
        }
        if (vms) {
            __free_page(vms);
            per_cpu(airlock_host_vmsave_page, cpu) = NULL;
            per_cpu(airlock_host_vmsave_pa, cpu) = 0;
        }
    }
}

/* =========================================================================
 * Waitqueues (`airlock_wq`) & Kernel Threads (`airlock_kthread`)
 * ========================================================================= */

struct airlock_wq {
    wait_queue_head_t head;
    atomic_t kicked;
};

struct airlock_wq *airlock_kapi_wq_alloc(void)
{
    struct airlock_wq *wq = kzalloc(sizeof(*wq), GFP_KERNEL);

    if (!wq)
        return NULL;
    init_waitqueue_head(&wq->head);
    atomic_set(&wq->kicked, 0);
    return wq;
}

void airlock_kapi_wq_wake(struct airlock_wq *wq)
{
    if (!wq)
        return;
    atomic_set(&wq->kicked, 1);
    wake_up_interruptible(&wq->head);
}

int airlock_kapi_wq_wait_ns(struct airlock_wq *wq, u64 timeout_ns)
{
    if (!wq)
        return -EINVAL;
    if (atomic_xchg(&wq->kicked, 0))
        return 0;

    if (timeout_ns == U64_MAX) {
        long rc = wait_event_interruptible(
            wq->head,
            atomic_xchg(&wq->kicked, 0) || kthread_should_stop());
        return rc < 0 ? (int)rc : 0;
    } else {
        ktime_t kt = ns_to_ktime(timeout_ns);
        long rc = wait_event_interruptible_hrtimeout(
            wq->head,
            atomic_xchg(&wq->kicked, 0) || kthread_should_stop(),
            kt);
        return (rc < 0 && rc != -ETIME) ? (int)rc : 0;
    }
}

void airlock_kapi_wq_free(struct airlock_wq *wq)
{
    kfree(wq);
}

struct airlock_kthread {
    struct task_struct *task;
    airlock_kthread_fn_t fn;
    void *opaque;
};

static int airlock_kthread_entry(void *arg)
{
    struct airlock_kthread *kt = (struct airlock_kthread *)arg;

    kt->fn(kt->opaque);

    /*
     * Park cleanly if the guest exited autonomously so `kthread_stop()` in
     * `airlock_kapi_kthread_stop` always joins without races.
     */
    while (!kthread_should_stop()) {
        set_current_state(TASK_INTERRUPTIBLE);
        if (!kthread_should_stop())
            schedule();
    }
    __set_current_state(TASK_RUNNING);
    return 0;
}

int airlock_kapi_kthread_spawn(airlock_kthread_fn_t fn, void *opaque,
                               const char *name, size_t name_len,
                               struct airlock_kthread **out_kt)
{
    struct airlock_kthread *kt;
    struct task_struct *task;

    kt = kzalloc(sizeof(*kt), GFP_KERNEL);
    if (!kt)
        return -ENOMEM;
    kt->fn = fn;
    kt->opaque = opaque;

    task = kthread_create_on_node(airlock_kthread_entry, kt, NUMA_NO_NODE,
                                  "%.*s", (int)name_len, name);
    if (IS_ERR(task)) {
        int err = PTR_ERR(task);
        kfree(kt);
        return err;
    }

    get_task_struct(task);
    kt->task = task;
    wake_up_process(task);
    *out_kt = kt;
    return 0;
}

bool airlock_kapi_kthread_should_stop(void)
{
    return kthread_should_stop();
}

void airlock_kapi_kthread_stop(struct airlock_kthread *kt)
{
    if (!kt)
        return;
    if (kt->task) {
        kthread_stop(kt->task);
        put_task_struct(kt->task);
        kt->task = NULL;
    }
    kfree(kt);
}

/* =========================================================================
 * KVM-Independent Per-Slice SVM Guest Entry + FPU/XSAVE Context Switch
 * ========================================================================= */

static __always_inline u64 airlock_xgetbv0(void)
{
    u32 eax, edx;

    asm volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((u64)edx << 32) | eax;
}

static __always_inline void airlock_xsetbv0(u64 val)
{
    u32 eax = (u32)val;
    u32 edx = (u32)(val >> 32);

    asm volatile("xsetbv" :: "c"(0), "a"(eax), "d"(edx));
}

static __always_inline void airlock_fpu_restore_guest(const u8 *fpu_buf, bool has_xsave, u32 xmask)
{
    if (has_xsave) {
        u32 hi = 0;
        asm volatile("xrstor64 %0" :: "m"(*fpu_buf), "a"(xmask), "d"(hi) : "memory");
    } else {
        asm volatile("fxrstor64 %0" :: "m"(*fpu_buf) : "memory");
    }
}

static __always_inline void airlock_fpu_save_guest(u8 *fpu_buf, bool has_xsave, u32 xmask)
{
    if (has_xsave) {
        u32 hi = 0;
        asm volatile("xsave64 %0" : "=m"(*fpu_buf) : "a"(xmask), "d"(hi) : "memory");
    } else {
        asm volatile("fxsave64 %0" : "=m"(*fpu_buf) :: "memory");
    }
}

/* VMCB `control.tlb_ctl` byte lives at offset 0x05c (verified by static_assert in svm.rs). */
#define AIRLOCK_VMCB_TLB_CTL_OFFSET 0x05c
#define AIRLOCK_TLB_FLUSH_ASID      3

int airlock_kapi_svm_run_slice(u64 *gprs, u64 vmcb_pa, void *vmcb_va,
                               u8 *fpu_buf, u64 guest_xcr0, u64 guest_tsc_aux,
                               const u32 *kick_flag, u32 *on_cpu_slot,
                               u32 *last_pcpu)
{
    bool has_xsave = boot_cpu_has(X86_FEATURE_XSAVE);
    u64 host_xcr0 = 0;
    u32 xmask = 0x7;
    unsigned long irq_flags;
    int aborted = 0;

    kernel_fpu_begin_mask(0);

    if (has_xsave) {
        host_xcr0 = airlock_xgetbv0();
        xmask = (u32)(host_xcr0 & 0x7);
    }

    /* Restore X87+SSE+AVX with full host XCR0 enabled before narrowing to guest XCR0. */
    airlock_fpu_restore_guest(fpu_buf, has_xsave, xmask);
    if (has_xsave && (guest_xcr0 & host_xcr0) == guest_xcr0 && guest_xcr0 != host_xcr0)
        airlock_xsetbv0(guest_xcr0);

    local_irq_save(irq_flags);
    {
        u32 cpu = (u32)raw_smp_processor_id();
        u8 *tlb_ctl_ptr = (u8 *)vmcb_va + AIRLOCK_VMCB_TLB_CTL_OFFSET;

        WRITE_ONCE(*on_cpu_slot, cpu);
        smp_mb();

        if (*last_pcpu != cpu) {
            *last_pcpu = cpu;
            *tlb_ctl_ptr = AIRLOCK_TLB_FLUSH_ASID;
        }

        if (need_resched() || signal_pending(current) || kthread_should_stop() ||
            READ_ONCE(*kick_flag) != 0) {
            aborted = 1;
        } else {
            u64 orig_efer = 0, orig_hsave = 0, host_tsc_aux = 0;
            u64 my_hsave = per_cpu(airlock_hsave_pa, cpu);
            u64 my_vmsave = per_cpu(airlock_host_vmsave_pa, cpu);
            bool has_rdtscp = boot_cpu_has(X86_FEATURE_RDTSCP);

            rdmsrq(MSR_EFER, orig_efer);
            rdmsrq(MSR_VM_HSAVE_PA, orig_hsave);

            /* If KVM also holds a save area on this CPU, flush our ASID to avoid tag aliasing. */
            if (orig_hsave != 0 && orig_hsave != my_hsave)
                *tlb_ctl_ptr = AIRLOCK_TLB_FLUSH_ASID;

            if (!(orig_efer & EFER_SVME))
                wrmsrq(MSR_EFER, orig_efer | EFER_SVME);
            if (orig_hsave != my_hsave)
                wrmsrq(MSR_VM_HSAVE_PA, my_hsave);

            if (has_rdtscp) {
                rdmsrq(MSR_TSC_AUX, host_tsc_aux);
                if (host_tsc_aux != guest_tsc_aux)
                    wrmsrq(MSR_TSC_AUX, guest_tsc_aux);
            }

            /*
             * Mask all physical interrupts with GIF=0 (`clgi`) while setting RFLAGS.IF=1
             * so `VMRUN` records host IF=1 in `VM_HSAVE_PA` (required with `V_INTR_MASKING=1`
             * so host physical interrupts break out of guest execution even if guest IF=0).
             */
            asm volatile("clgi" ::: "memory");
            raw_local_irq_enable();

            airlock_svm_vmrun(gprs, vmcb_pa, my_vmsave);

            if (cpu_feature_enabled(X86_FEATURE_IBPB_ON_VMEXIT))
                wrmsrq(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);

            raw_local_irq_disable();
            asm volatile("stgi" ::: "memory");

            if (has_rdtscp && host_tsc_aux != guest_tsc_aux)
                wrmsrq(MSR_TSC_AUX, host_tsc_aux);
            if (orig_hsave != my_hsave)
                wrmsrq(MSR_VM_HSAVE_PA, orig_hsave);
            if (!(orig_efer & EFER_SVME))
                wrmsrq(MSR_EFER, orig_efer);
        }

        WRITE_ONCE(*on_cpu_slot, U32_MAX);
    }
    local_irq_restore(irq_flags);

    if (has_xsave && airlock_xgetbv0() != host_xcr0)
        airlock_xsetbv0(host_xcr0);
    airlock_fpu_save_guest(fpu_buf, has_xsave, xmask);

    kernel_fpu_end();
    return aborted;
}

/* =========================================================================
 * W^X Executable `.cwasm` Backing (`vmap` 4 KiB PTEs + `lookup_address`)
 * ========================================================================= */

struct airlock_exec_buf {
    struct page **pages;
    unsigned int nr_pages;
    void *vaddr;
    size_t byte_len;
};

struct airlock_tlb_range {
    unsigned long start;
    unsigned long end;
};

static void airlock_flush_tlb_range_cpu(void *info)
{
    const struct airlock_tlb_range *r = (const struct airlock_tlb_range *)info;
    unsigned long addr;

    for (addr = r->start; addr < r->end; addr += PAGE_SIZE)
        asm volatile("invlpg (%0)" :: "r"(addr) : "memory");
}

int airlock_kapi_exec_alloc_from_user(const void __user *uptr, size_t byte_len,
                                      struct airlock_exec_buf **out_buf,
                                      void **out_ro_ptr)
{
    struct airlock_exec_buf *buf;
    unsigned int nr_pages, i;
    size_t rem;

    if (!byte_len || byte_len > (16UL << 20))
        return -EINVAL;

    nr_pages = (unsigned int)(PAGE_ALIGN(byte_len) >> PAGE_SHIFT);
    buf = kzalloc(sizeof(*buf), GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    buf->pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL | __GFP_ZERO);
    if (!buf->pages) {
        kfree(buf);
        return -ENOMEM;
    }
    buf->nr_pages = nr_pages;
    buf->byte_len = byte_len;

    rem = byte_len;
    for (i = 0; i < nr_pages; i++) {
        size_t chunk = min_t(size_t, rem, PAGE_SIZE);

        buf->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!buf->pages[i])
            goto err_free;
        if (chunk && copy_from_user(page_address(buf->pages[i]),
                                    (const u8 __user *)uptr + ((size_t)i << PAGE_SHIFT),
                                    chunk)) {
            goto err_free;
        }
        rem -= chunk;
    }

    buf->vaddr = vmap(buf->pages, nr_pages, VM_MAP, PAGE_KERNEL_RO);
    if (!buf->vaddr)
        goto err_free;

    *out_buf = buf;
    *out_ro_ptr = buf->vaddr;
    return 0;

err_free:
    for (i = 0; i < nr_pages; i++) {
        if (buf->pages[i])
            __free_page(buf->pages[i]);
    }
    kvfree(buf->pages);
    kfree(buf);
    return -EFAULT;
}

int airlock_kapi_exec_set_rx(struct airlock_exec_buf *buf, size_t offset,
                             size_t len, bool executable)
{
    size_t start_off, end_off, off;
    struct airlock_tlb_range range;

    if (!buf || !len)
        return 0;
    if (offset > buf->byte_len || len > buf->byte_len - offset)
        return -EINVAL;

    start_off = offset & PAGE_MASK;
    end_off = PAGE_ALIGN(offset + len);

    for (off = start_off; off < end_off; off += PAGE_SIZE) {
        unsigned long va = (unsigned long)buf->vaddr + off;
        unsigned int level = 0;
        pte_t *ptep = lookup_address(va, &level);
        unsigned long pfn;
        pgprot_t prot;

        if (!ptep || level != PG_LEVEL_4K)
            return -EFAULT;

        pfn = pte_pfn(*ptep);
        prot = executable ? PAGE_KERNEL_ROX : PAGE_KERNEL_RO;
        set_pte_atomic(ptep, pfn_pte(pfn, prot));
    }

    range.start = (unsigned long)buf->vaddr + start_off;
    range.end   = (unsigned long)buf->vaddr + end_off;
    on_each_cpu(airlock_flush_tlb_range_cpu, &range, 1);
    return 0;
}

void airlock_kapi_exec_free(struct airlock_exec_buf *buf)
{
    unsigned int i;

    if (!buf)
        return;
    if (buf->vaddr) {
        airlock_kapi_exec_set_rx(buf, 0, (size_t)buf->nr_pages << PAGE_SHIFT, false);
        vunmap(buf->vaddr);
    }
    for (i = 0; i < buf->nr_pages; i++) {
        if (buf->pages[i])
            __free_page(buf->pages[i]);
    }
    kvfree(buf->pages);
    kfree(buf);
}

/* =========================================================================
 * Kernel CET IBT (`MSR_IA32_S_CET`) Guard Around Cranelift `.cwasm` Calls
 * ========================================================================= */

u64 airlock_kapi_wasm_call_enter(void)
{
#ifdef CONFIG_X86_KERNEL_IBT
    if (cpu_feature_enabled(X86_FEATURE_IBT)) {
        u64 cet = 0;

        preempt_disable();
        rdmsrq(MSR_IA32_S_CET, cet);
        if (cet & CET_ENDBR_EN)
            wrmsrq(MSR_IA32_S_CET, cet & ~CET_ENDBR_EN);
        return cet | (1ULL << 63);
    }
#endif
    return 0;
}

void airlock_kapi_wasm_call_exit(u64 saved_cet)
{
#ifdef CONFIG_X86_KERNEL_IBT
    if (saved_cet & (1ULL << 63)) {
        u64 orig = saved_cet & ~(1ULL << 63);

        if (orig & CET_ENDBR_EN)
            wrmsrq(MSR_IA32_S_CET, orig);
        preempt_enable();
    }
#else
    (void)saved_cet;
#endif
}

/* =========================================================================
 * Pinned User Memory (`pin_user_pages_fast`)
 * ========================================================================= */

struct airlock_pinned_mem {
    struct page **pages;
    unsigned long nr_pages;
    bool writable;
    void *kva;
};

int airlock_kapi_pin_user_mem(u64 uaddr, u64 byte_len, bool writable, bool map_kva,
                              struct airlock_pinned_mem **out_mem, void **out_kva)
{
    struct airlock_pinned_mem *mem;
    unsigned long nr_pages, pinned = 0;
    unsigned int gup_flags = FOLL_LONGTERM | (writable ? FOLL_WRITE : 0);

    if ((uaddr & ~PAGE_MASK) || !byte_len)
        return -EINVAL;

    nr_pages = PAGE_ALIGN(byte_len) >> PAGE_SHIFT;
    mem = kzalloc(sizeof(*mem), GFP_KERNEL);
    if (!mem)
        return -ENOMEM;

    mem->pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL | __GFP_ZERO);
    if (!mem->pages) {
        kfree(mem);
        return -ENOMEM;
    }
    mem->nr_pages = nr_pages;
    mem->writable = writable;

    while (pinned < nr_pages) {
        int chunk = (int)min_t(unsigned long, nr_pages - pinned, 16384UL);
        int ret = pin_user_pages_fast(uaddr + (pinned << PAGE_SHIFT),
                                      chunk, gup_flags, mem->pages + pinned);
        if (ret <= 0) {
            if (pinned)
                unpin_user_pages_dirty_lock(mem->pages, pinned, false);
            kvfree(mem->pages);
            kfree(mem);
            return ret < 0 ? ret : -EFAULT;
        }
        pinned += (unsigned long)ret;
    }

    if (map_kva) {
        mem->kva = vmap(mem->pages, (unsigned int)nr_pages, VM_MAP,
                        writable ? PAGE_KERNEL : PAGE_KERNEL_RO);
        if (!mem->kva) {
            unpin_user_pages_dirty_lock(mem->pages, nr_pages, false);
            kvfree(mem->pages);
            kfree(mem);
            return -ENOMEM;
        }
    }

    *out_mem = mem;
    if (out_kva)
        *out_kva = mem->kva;
    return 0;
}

u64 airlock_kapi_pinned_num_pages(const struct airlock_pinned_mem *mem)
{
    return mem ? (u64)mem->nr_pages : 0;
}

u64 airlock_kapi_pinned_page_phys(const struct airlock_pinned_mem *mem, u64 page_idx)
{
    if (!mem || page_idx >= mem->nr_pages)
        return 0;
    return page_to_phys(mem->pages[page_idx]);
}

int airlock_kapi_copy_from_pinned(const struct airlock_pinned_mem *mem, u64 offset,
                                  void *dst, size_t len)
{
    u8 *out = (u8 *)dst;
    u64 max_bytes;

    if (!mem)
        return -EINVAL;
    max_bytes = (u64)mem->nr_pages << PAGE_SHIFT;
    if (offset > max_bytes || len > max_bytes - offset)
        return -EINVAL;

    while (len > 0) {
        u64 pg = offset >> PAGE_SHIFT;
        size_t pg_off = (size_t)(offset & ~PAGE_MASK);
        size_t chunk = min_t(size_t, len, PAGE_SIZE - pg_off);
        const u8 *src = (const u8 *)page_address(mem->pages[pg]) + pg_off;

        memcpy(out, src, chunk);
        out += chunk;
        offset += chunk;
        len -= chunk;
    }
    return 0;
}

void airlock_kapi_unpin_user_mem(struct airlock_pinned_mem *mem)
{
    if (!mem)
        return;
    if (mem->kva)
        vunmap(mem->kva);
    unpin_user_pages_dirty_lock(mem->pages, mem->nr_pages, mem->writable);
    kvfree(mem->pages);
    kfree(mem);
}

/* =========================================================================
 * Eventfd Doorbells (`c2i` signal & `i2c` poll waitqueue observer)
 * ========================================================================= */

struct airlock_eventfd {
    struct file *file;
    struct eventfd_ctx *ctx;
    wait_queue_entry_t wait;
    wait_queue_head_t *wqh;
    poll_table pt;
    airlock_eventfd_cb_t cb;
    void *opaque;
};

static int airlock_eventfd_wakeup(wait_queue_entry_t *wait, unsigned int mode,
                                  int sync, void *key)
{
    struct airlock_eventfd *efd = container_of(wait, struct airlock_eventfd, wait);
    __poll_t flags = key_to_poll(key);

    (void)mode;
    (void)sync;
    if (flags & EPOLLIN) {
        __u64 cnt = 0;

        eventfd_ctx_do_read(efd->ctx, &cnt);
        if (efd->cb)
            efd->cb(efd->opaque);
    }
    return 0;
}

static void airlock_eventfd_ptable_queue(struct file *file,
                                         wait_queue_head_t *wqh,
                                         poll_table *pt)
{
    struct airlock_eventfd *efd = container_of(pt, struct airlock_eventfd, pt);

    (void)file;
    efd->wqh = wqh;
    add_wait_queue(wqh, &efd->wait);
}

int airlock_kapi_eventfd_bind(int fd, airlock_eventfd_cb_t cb, void *opaque,
                              struct airlock_eventfd **out_efd)
{
    struct airlock_eventfd *efd;
    struct file *file;
    struct eventfd_ctx *ctx;

    file = fget(fd);
    if (!file)
        return -EBADF;

    ctx = eventfd_ctx_fileget(file);
    if (IS_ERR(ctx)) {
        fput(file);
        return PTR_ERR(ctx);
    }

    efd = kzalloc(sizeof(*efd), GFP_KERNEL);
    if (!efd) {
        eventfd_ctx_put(ctx);
        fput(file);
        return -ENOMEM;
    }

    efd->file = file;
    efd->ctx = ctx;
    efd->cb = cb;
    efd->opaque = opaque;

    if (cb) {
        __poll_t events;

        init_waitqueue_func_entry(&efd->wait, airlock_eventfd_wakeup);
        init_poll_funcptr(&efd->pt, airlock_eventfd_ptable_queue);
        events = vfs_poll(file, &efd->pt);
        if (events & EPOLLIN)
            cb(opaque);
    }

    *out_efd = efd;
    return 0;
}

void airlock_kapi_eventfd_signal(struct airlock_eventfd *efd)
{
    if (efd && efd->ctx)
        eventfd_signal(efd->ctx);
}

void airlock_kapi_eventfd_unbind(struct airlock_eventfd *efd)
{
    if (!efd)
        return;
    if (efd->wqh) {
        __u64 cnt = 0;

        eventfd_ctx_remove_wait_queue(efd->ctx, &efd->wait, &cnt);
        efd->wqh = NULL;
    }
    eventfd_ctx_put(efd->ctx);
    fput(efd->file);
    kfree(efd);
}

/* =========================================================================
 * `/dev/airlock` Misc Device & `airlock-vm` Anonymous Inode Lifecycle
 * ========================================================================= */

static int airlock_vm_release(struct inode *inode, struct file *filp)
{
    void *vm = filp->private_data;

    (void)inode;
    filp->private_data = NULL;
    if (vm)
        airlock_rust_vm_destroy(vm);
    module_put(THIS_MODULE);
    return 0;
}

static const struct file_operations airlock_vm_fops = {
    .owner   = THIS_MODULE,
    .release = airlock_vm_release,
};

static long airlock_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    (void)filp;
    switch (cmd) {
    case AIRLOCK_IOC_GET_API_VERSION: {
        u32 ver = AIRLOCK_API_VERSION;

        if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
            return -EFAULT;
        return 0;
    }
    case AIRLOCK_IOC_GET_CAPS: {
        u32 caps = airlock_rust_get_caps();

        if (copy_to_user((void __user *)arg, &caps, sizeof(caps)))
            return -EFAULT;
        return 0;
    }
    case AIRLOCK_IOC_CREATE_VM: {
        struct airlock_create_vm req;
        void *vm = NULL;
        int ret, vm_fd;

        if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
            return -EFAULT;

        if (!try_module_get(THIS_MODULE))
            return -ENODEV;

        ret = airlock_rust_vm_create(&req, &vm);
        if (ret < 0) {
            module_put(THIS_MODULE);
            return ret;
        }

        vm_fd = anon_inode_getfd("airlock-vm", &airlock_vm_fops, vm, O_RDWR | O_CLOEXEC);
        if (vm_fd < 0) {
            airlock_rust_vm_destroy(vm);
            module_put(THIS_MODULE);
            return vm_fd;
        }
        return vm_fd;
    }
    default:
        return -ENOTTY;
    }
}

static const struct file_operations airlock_dev_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = airlock_dev_ioctl,
    .compat_ioctl   = compat_ptr_ioctl,
};

static struct miscdevice airlock_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "airlock",
    .fops  = &airlock_dev_fops,
    .mode  = 0660,
};

static int airlock_reboot_notify(struct notifier_block *nb, unsigned long code, void *unused)
{
    (void)nb;
    (void)code;
    (void)unused;
    return NOTIFY_DONE;
}

static struct notifier_block airlock_reboot_nb = {
    .notifier_call = airlock_reboot_notify,
};

static int __init airlock_mod_init(void)
{
    int ret;

    ret = airlock_alloc_percpu_svm_areas();
    if (ret) {
        airlock_free_percpu_svm_areas();
        return ret;
    }

    ret = airlock_rust_init();
    if (ret) {
        airlock_free_percpu_svm_areas();
        return ret;
    }

    ret = register_reboot_notifier(&airlock_reboot_nb);
    if (ret) {
        airlock_rust_exit();
        airlock_free_percpu_svm_areas();
        return ret;
    }

    ret = misc_register(&airlock_miscdev);
    if (ret) {
        unregister_reboot_notifier(&airlock_reboot_nb);
        airlock_rust_exit();
        airlock_free_percpu_svm_areas();
        return ret;
    }

    pr_info("loaded (/dev/airlock ready, caps=0x%x)\n", airlock_rust_get_caps());
    return 0;
}

static void __exit airlock_mod_exit(void)
{
    misc_deregister(&airlock_miscdev);
    unregister_reboot_notifier(&airlock_reboot_nb);
    airlock_rust_exit();
    airlock_free_percpu_svm_areas();
    pr_info("unloaded\n");
}

module_init(airlock_mod_init);
module_exit(airlock_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Airlock Ring-0 Wasm VMM Core Host (KVM-independent)");
MODULE_AUTHOR("Airlock Contributors");
