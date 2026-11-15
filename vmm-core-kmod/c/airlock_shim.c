// SPDX-License-Identifier: GPL-2.0
/*
 * Out-of-tree Linux Ring-0 C shim for `airlock.ko` (`vmm-core-host`).
 *
 * Bridges Linux kernel C macros, VFS/miscdevice/anon_inode registration,
 * memory pinning, W^X `.cwasm` PTE permissions, and eventfd waitqueues to the
 * `#![no_std] + alloc` Rust hypervisor core (`libairlock_rust.a`).
 * Zero symbols or Kconfig options from `kvm.ko` are referenced.
 */

#define pr_fmt(fmt) "airlock: " fmt

#include <linux/anon_inodes.h>
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
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/percpu.h>
#include <linux/poll.h>
#include <linux/reboot.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <asm/ibt.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/tsc.h>

#include "airlock_kapi.h"

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
    gfp_t gfp = GFP_KERNEL | (zeroed ? __GFP_ZERO : 0);

    /*
     * Rust's `Layout` guarantees `align` is a power of two. For alignments
     * larger than `ARCH_KMALLOC_MINALIGN`, round `req` up to `align` because
     * Linux's slab/page allocator naturally aligns power-of-two sizes >=align,
     * and `kvmalloc` >= PAGE_SIZE is always PAGE_SIZE-aligned.
     */
    if (align > ARCH_KMALLOC_MINALIGN) {
        if (align > PAGE_SIZE)
            return NULL;
        req = ALIGN(req, align);
    }
    return kvmalloc(req, gfp);
}

void airlock_kapi_free(void *ptr)
{
    if (ptr)
        kvfree(ptr);
}

/* =========================================================================
 * CPU / SMP / Time & Per-CPU SVM Save Areas
 * ========================================================================= */

static DEFINE_PER_CPU(struct page *, airlock_hsave_page);
static DEFINE_PER_CPU(struct page *, airlock_host_vmsave_page);
static DEFINE_PER_CPU(u64, airlock_hsave_pa);
static DEFINE_PER_CPU(u64, airlock_host_vmsave_pa);

u32 airlock_kapi_num_possible_cpus(void)
{
    return (u32)num_possible_cpus();
}

u32 airlock_kapi_raw_smp_processor_id(void)
{
    return (u32)raw_smp_processor_id();
}

u32 airlock_kapi_get_cpu(void)
{
    return (u32)get_cpu();
}

void airlock_kapi_put_cpu(void)
{
    put_cpu();
}

u64 airlock_kapi_ktime_get_ns(void)
{
    return ktime_get_ns();
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
    if (cpu < nr_cpu_ids && cpu_online(cpu))
        smp_call_function_single((int)cpu, airlock_kick_ipi_noop, NULL, 0);
}

u64 airlock_kapi_cpu_hsave_pa(u32 cpu)
{
    if (cpu >= nr_cpu_ids)
        return 0;
    return per_cpu(airlock_hsave_pa, cpu);
}

u64 airlock_kapi_cpu_host_vmsave_pa(u32 cpu)
{
    if (cpu >= nr_cpu_ids)
        return 0;
    return per_cpu(airlock_host_vmsave_pa, cpu);
}

int airlock_kapi_alloc_contig_pages(u32 order, int nid, u64 *out_phys, void **out_virt)
{
    struct page *p;
    gfp_t gfp = GFP_KERNEL | __GFP_ZERO;

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

    /* `invlpg` invalidates 4 KiB TLB entries even when `_PAGE_GLOBAL` is set. */
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

    /* `vmap()` maps each `struct page *` with dedicated 4 KiB PTEs (RO + NX). */
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
        /* Strictly W^X: either RO+X (`PAGE_KERNEL_ROX`) or RO+NX (`PAGE_KERNEL_RO`). */
        prot = executable ? PAGE_KERNEL_ROX : PAGE_KERNEL_RO;
        set_pte_atomic(ptep, pfn_pte(pfn, prot));
    }

    {
        struct airlock_tlb_range range = {
            .start = (unsigned long)buf->vaddr + start_off,
            .end   = (unsigned long)buf->vaddr + end_off,
        };
        on_each_cpu(airlock_flush_tlb_range_cpu, &range, 1);
    }
    return 0;
}

void airlock_kapi_exec_free(struct airlock_exec_buf *buf)
{
    unsigned int i;

    if (!buf)
        return;
    if (buf->vaddr) {
        /* Ensure all vmap PTEs are restored to RO+NX before unmapping. */
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
 * Kernel CET IBT (`MSR_IA32_S_CET`) Guard for Cranelift `.cwasm` Calls
 * ========================================================================= */

u64 airlock_kapi_ibt_enter(void)
{
#ifdef CONFIG_X86_KERNEL_IBT
    if (cpu_feature_enabled(X86_FEATURE_IBT)) {
        u64 cet = 0;

        rdmsrq(MSR_IA32_S_CET, cet);
        if (cet & CET_ENDBR_EN)
            wrmsrq(MSR_IA32_S_CET, cet & ~CET_ENDBR_EN);
        return cet;
    }
#endif
    return 0;
}

void airlock_kapi_ibt_exit(u64 saved_cet)
{
#ifdef CONFIG_X86_KERNEL_IBT
    if ((saved_cet & CET_ENDBR_EN) && cpu_feature_enabled(X86_FEATURE_IBT))
        wrmsrq(MSR_IA32_S_CET, saved_cet);
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
    if ((flags & EPOLLIN) && efd->cb)
        efd->cb(efd->opaque);
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
