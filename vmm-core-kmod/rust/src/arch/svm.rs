// SPDX-License-Identifier: GPL-2.0
// KVM-independent AMD-V (SVM) Ring-0 hardware virtualization backend for `airlock.ko`.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use vmm_core::host::abi::{
    RawCpuid, RawSegReg, RawVmEntry, RawVmExit, VcpuCommPage, GPR_R10, GPR_R11, GPR_R12, GPR_R13,
    GPR_R14, GPR_R15, GPR_R8, GPR_R9, GPR_RAX, GPR_RBP, GPR_RBX, GPR_RCX, GPR_RDI, GPR_RDX,
    GPR_RSI, GPR_RSP, SYNC_REG_GPRS, SYNC_REG_RIP_RFLAGS, SYNC_REG_SREGS,
};
use vmm_core::host::{
    DtReg, DtRegVal, HvError, HvResult, Reg, RegId, RegVal, SReg, SegReg, SegRegVal, VmEntry,
    VmExit,
};
use vmm_core::hw::reg::SegAccess;

use super::FastExit;
use crate::kapi::{airlock_kapi_svm_run_slice, rdtsc_now, ContigPages};
use crate::kerr;
use crate::lapic::VcpuLapic;
use crate::stage2::Stage2Mmu;

const MSR_IA32_TSC: u32 = 0x0000_0010;
const MSR_IA32_TSC_ADJUST: u32 = 0x0000_003b;
const MSR_PAT: u32 = 0x0000_0277;
const MSR_SYSENTER_CS: u32 = 0x0000_0174;
const MSR_SYSENTER_ESP: u32 = 0x0000_0175;
const MSR_SYSENTER_EIP: u32 = 0x0000_0176;
const MSR_IA32_EFER: u32 = 0xc000_0080;
const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_CSTAR: u32 = 0xc000_0083;
const MSR_SFMASK: u32 = 0xc000_0084;
const MSR_FS_BASE: u32 = 0xc000_0100;
const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;
const MSR_TSC_AUX: u32 = 0xc000_0103;
const MSR_VM_CR: u32 = 0xc001_0114;

const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_SVME: u64 = 1 << 12;
const VM_CR_SVMDIS: u64 = 1 << 4;
const DEFAULT_PAT: u64 = 0x0007_0406_0007_0406;

// VMCB Control Area intercepts_1 (offset 0x00c)
const INTERCEPT_INTR: u32 = 1 << 0;
const INTERCEPT_NMI: u32 = 1 << 1;
const INTERCEPT_INIT: u32 = 1 << 3;
const INTERCEPT_VINTR: u32 = 1 << 4;
const INTERCEPT_CPUID: u32 = 1 << 18;
const INTERCEPT_HLT: u32 = 1 << 24;
const INTERCEPT_IOIO_PROT: u32 = 1 << 27;
const INTERCEPT_MSR_PROT: u32 = 1 << 28;
const INTERCEPT_FERR_FREEZE: u32 = 1 << 30;
const INTERCEPT_SHUTDOWN: u32 = 1 << 31;

// VMCB Control Area intercepts_2 (offset 0x010)
const INTERCEPT_VMRUN: u32 = 1 << 0;
const INTERCEPT_VMMCALL: u32 = 1 << 1;
const INTERCEPT_VMLOAD: u32 = 1 << 2;
const INTERCEPT_VMSAVE: u32 = 1 << 3;
const INTERCEPT_STGI: u32 = 1 << 4;
const INTERCEPT_CLGI: u32 = 1 << 5;
const INTERCEPT_SKINIT: u32 = 1 << 6;
const INTERCEPT_MONITOR: u32 = 1 << 10;
const INTERCEPT_MWAIT: u32 = 1 << 11;
const INTERCEPT_XSETBV: u32 = 1 << 13;

// VMCB int_ctl (offset 0x060)
const V_IRQ: u32 = 1 << 8;
const V_INTR_PRIO_MAX: u32 = 0xf << 16;
const V_IGN_TPR: u32 = 1 << 20;
const V_INTR_MASKING: u32 = 1 << 24;

// VMCB event_inj (offset 0x0a8)
const EVENT_INJ_VALID: u64 = 1 << 31;
const EVENT_INJ_ERR_VALID: u64 = 1 << 11;
const EVENT_TYPE_INTR: u64 = 0 << 8;
const EVENT_TYPE_EXC: u64 = 3 << 8;

// SVM Exit Codes
const VMEXIT_INTR: u64 = 0x60;
const VMEXIT_NMI: u64 = 0x61;
const VMEXIT_VINTR: u64 = 0x64;
const VMEXIT_CPUID: u64 = 0x72;
const VMEXIT_HLT: u64 = 0x78;
const VMEXIT_IOIO: u64 = 0x7b;
const VMEXIT_MSR: u64 = 0x7c;
const VMEXIT_SHUTDOWN: u64 = 0x7f;
const VMEXIT_VMRUN: u64 = 0x80;
const VMEXIT_VMMCALL: u64 = 0x81;
const VMEXIT_VMLOAD: u64 = 0x82;
const VMEXIT_VMSAVE: u64 = 0x83;
const VMEXIT_STGI: u64 = 0x84;
const VMEXIT_CLGI: u64 = 0x85;
const VMEXIT_SKINIT: u64 = 0x86;
const VMEXIT_MONITOR: u64 = 0x8a;
const VMEXIT_MWAIT: u64 = 0x8b;
const VMEXIT_XSETBV: u64 = 0x8d;
const VMEXIT_NPF: u64 = 0x400;
const VMEXIT_INVALID: u64 = u64::MAX;

static NEXT_ASID: AtomicU32 = AtomicU32::new(1);

#[inline]
fn rdmsr_raw(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

pub fn is_supported() -> bool {
    let max_ext = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if max_ext < 0x8000_000a {
        return false;
    }
    let ext_feat = core::arch::x86_64::__cpuid(0x8000_0001);
    if (ext_feat.ecx & (1 << 2)) == 0 {
        return false;
    }
    if (rdmsr_raw(MSR_VM_CR) & VM_CR_SVMDIS) != 0 {
        return false;
    }
    let svm_feat = core::arch::x86_64::__cpuid(0x8000_000a);
    (svm_feat.edx & 1) != 0 && svm_feat.ebx >= 2
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VmcbSeg {
    selector: u16,
    attrib: u16,
    limit: u32,
    base: u64,
}

#[repr(C)]
struct VmcbControlArea {
    intercept_cr: u32,
    intercept_dr: u32,
    intercept_exceptions: u32,
    intercepts_1: u32,
    intercepts_2: u32,
    _reserved_1: [u8; 0x28],
    pause_filter_thresh: u16,
    pause_filter_count: u16,
    iopm_base_pa: u64,
    msrpm_base_pa: u64,
    tsc_offset: u64,
    guest_asid: u32,
    tlb_ctl: u8,
    _reserved_2: [u8; 3],
    int_ctl: u32,
    int_vector: u32,
    int_state: u64,
    exit_code: u64,
    exit_info_1: u64,
    exit_info_2: u64,
    exit_int_info: u64,
    np_ctl: u64,
    avic_vapic_bar: u64,
    ghcb_gpa: u64,
    event_inj: u64,
    n_cr3: u64,
    lbr_virt_enable: u64,
    clean_bits: u32,
    _reserved_3: u32,
    next_rip: u64,
    insn_len: u8,
    insn_bytes: [u8; 15],
    _reserved_4: [u8; 0x320],
}

#[repr(C)]
struct VmcbSaveArea {
    es: VmcbSeg,
    cs: VmcbSeg,
    ss: VmcbSeg,
    ds: VmcbSeg,
    fs: VmcbSeg,
    gs: VmcbSeg,
    gdtr: VmcbSeg,
    ldtr: VmcbSeg,
    idtr: VmcbSeg,
    tr: VmcbSeg,
    _reserved_1: [u8; 0x2b],
    cpl: u8,
    _reserved_2: u32,
    efer: u64,
    _reserved_3: [u8; 0x70],
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    _reserved_4: [u8; 0x58],
    rsp: u64,
    _reserved_5: [u8; 0x18],
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    cr2: u64,
    _reserved_6: [u8; 0x20],
    g_pat: u64,
    _reserved_7: [u8; 0x990],
}

#[repr(C, align(4096))]
struct Vmcb {
    control: VmcbControlArea,
    save: VmcbSaveArea,
}

const _: () = assert!(size_of::<VmcbSeg>() == 16);
const _: () = assert!(size_of::<VmcbControlArea>() == 0x400);
const _: () = assert!(size_of::<VmcbSaveArea>() == 0xc00);
const _: () = assert!(size_of::<Vmcb>() == 0x1000);
const _: () = assert!(offset_of!(Vmcb, control.iopm_base_pa) == 0x040);
const _: () = assert!(offset_of!(Vmcb, control.msrpm_base_pa) == 0x048);
const _: () = assert!(offset_of!(Vmcb, control.guest_asid) == 0x058);
const _: () = assert!(offset_of!(Vmcb, control.tlb_ctl) == 0x05c);
const _: () = assert!(offset_of!(Vmcb, control.int_ctl) == 0x060);
const _: () = assert!(offset_of!(Vmcb, control.int_state) == 0x068);
const _: () = assert!(offset_of!(Vmcb, control.exit_code) == 0x070);
const _: () = assert!(offset_of!(Vmcb, control.exit_info_1) == 0x078);
const _: () = assert!(offset_of!(Vmcb, control.exit_info_2) == 0x080);
const _: () = assert!(offset_of!(Vmcb, control.exit_int_info) == 0x088);
const _: () = assert!(offset_of!(Vmcb, control.np_ctl) == 0x090);
const _: () = assert!(offset_of!(Vmcb, control.event_inj) == 0x0a8);
const _: () = assert!(offset_of!(Vmcb, control.n_cr3) == 0x0b0);
const _: () = assert!(offset_of!(Vmcb, control.clean_bits) == 0x0c0);
const _: () = assert!(offset_of!(Vmcb, control.next_rip) == 0x0c8);
const _: () = assert!(offset_of!(Vmcb, control.insn_len) == 0x0d0);
const _: () = assert!(offset_of!(Vmcb, save.es) == 0x400);
const _: () = assert!(offset_of!(Vmcb, save.cpl) == 0x4cb);
const _: () = assert!(offset_of!(Vmcb, save.efer) == 0x4d0);
const _: () = assert!(offset_of!(Vmcb, save.cr4) == 0x548);
const _: () = assert!(offset_of!(Vmcb, save.cr3) == 0x550);
const _: () = assert!(offset_of!(Vmcb, save.cr0) == 0x558);
const _: () = assert!(offset_of!(Vmcb, save.rflags) == 0x570);
const _: () = assert!(offset_of!(Vmcb, save.rip) == 0x578);
const _: () = assert!(offset_of!(Vmcb, save.rsp) == 0x5d8);
const _: () = assert!(offset_of!(Vmcb, save.rax) == 0x5f8);
const _: () = assert!(offset_of!(Vmcb, save.star) == 0x600);
const _: () = assert!(offset_of!(Vmcb, save.cr2) == 0x640);
const _: () = assert!(offset_of!(Vmcb, save.g_pat) == 0x668);

fn clear_msrpm_intercept(msrpm: &mut [u8], msr: u32) {
    let (base, byte_base) = if msr <= 0x1fff {
        (0u32, 0usize)
    } else if (0xc000_0000..=0xc000_1fff).contains(&msr) {
        (0xc000_0000u32, 0x800usize)
    } else if (0xc001_0000..=0xc001_1fff).contains(&msr) {
        (0xc001_0000u32, 0x1000usize)
    } else {
        return;
    };
    let rel = (msr - base) as usize;
    let bit = rel * 2;
    let idx = byte_base + (bit / 8);
    let shift = bit % 8;
    msrpm[idx] &= !(0b11 << shift);
}

pub struct SvmSharedTables {
    _iopm_pages: ContigPages,
    _msrpm_pages: ContigPages,
    pub iopm_phys: u64,
    pub msrpm_phys: u64,
    pub asid: u32,
}

impl SvmSharedTables {
    pub fn new() -> HvResult<Self> {
        if !is_supported() {
            return Err(HvError::Unsupported);
        }
        let nasid = core::arch::x86_64::__cpuid(0x8000_000a).ebx;
        // Order 2 = 4 contiguous pages (16 KiB >= 12 KiB IOPM); Order 1 = 2 contiguous pages (8 KiB MSRPM).
        let iopm_pages = ContigPages::alloc_order(2).map_err(|_| HvError::NoMemory)?;
        let msrpm_pages = ContigPages::alloc_order(1).map_err(|_| HvError::NoMemory)?;

        let iopm_phys = iopm_pages.phys();
        let msrpm_phys = msrpm_pages.phys();

        let iopm_slice =
            unsafe { core::slice::from_raw_parts_mut(iopm_pages.virt(), iopm_pages.byte_len()) };
        iopm_slice.fill(0xff);

        let msrpm_slice =
            unsafe { core::slice::from_raw_parts_mut(msrpm_pages.virt(), msrpm_pages.byte_len()) };
        msrpm_slice.fill(0xff);
        for msr in [
            MSR_SYSENTER_CS,
            MSR_SYSENTER_ESP,
            MSR_SYSENTER_EIP,
            MSR_STAR,
            MSR_LSTAR,
            MSR_CSTAR,
            MSR_SFMASK,
            MSR_FS_BASE,
            MSR_GS_BASE,
            MSR_KERNEL_GS_BASE,
        ] {
            clear_msrpm_intercept(msrpm_slice, msr);
        }

        let raw_asid = NEXT_ASID.fetch_add(1, Ordering::Relaxed);
        let usable = (nasid - 1).max(1);
        let asid = 1 + ((raw_asid - 1) % usable);

        Ok(Self {
            _iopm_pages: iopm_pages,
            _msrpm_pages: msrpm_pages,
            iopm_phys,
            msrpm_phys,
            asid,
        })
    }
}

fn seg_to_vmcb(val: SegRegVal) -> VmcbSeg {
    let raw = val.access.0;
    let attrib = if (raw & (1 << 16)) != 0 {
        0u16
    } else {
        ((raw & 0xff) as u16) | (((raw >> 4) & 0x0f00) as u16)
    };
    VmcbSeg {
        selector: val.selector,
        attrib,
        limit: val.limit,
        base: val.base,
    }
}

fn vmcb_to_seg(seg: VmcbSeg) -> SegRegVal {
    let access = if seg.attrib == 0 {
        1u32 << 16
    } else {
        ((seg.attrib & 0xff) as u32) | (((seg.attrib & 0x0f00) as u32) << 4)
    };
    SegRegVal {
        selector: seg.selector,
        base: seg.base,
        limit: seg.limit,
        access: SegAccess(access),
    }
}

fn host_xcr0_allow_mask() -> u64 {
    if core::arch::x86_64::__cpuid(0).eax >= 0xd {
        let d0 = core::arch::x86_64::__cpuid_count(0xd, 0);
        ((d0.eax as u64) & 0x7).max(1)
    } else {
        1
    }
}

pub struct SvmVcpu {
    vmcb_page: ContigPages,
    fpu_page: ContigPages,
    iopm_phys: u64,
    msrpm_phys: u64,
    asid: u32,
    gprs: [u64; 16],
    guest_efer: u64,
    guest_xcr0: u64,
    host_xcr0_allow: u64,
    guest_tsc_aux: u64,
    guest_tsc_adjust: u64,
    guest_tsc_offset: u64,
    last_tlb_gen: u64,
    last_pcpu: u32,
    cpuids: Vec<RawCpuid>,
}

impl SvmVcpu {
    pub fn new(shared: &SvmSharedTables, npt_root_pa: u64) -> HvResult<Self> {
        let vmcb_page = ContigPages::alloc_order(0).map_err(|_| HvError::NoMemory)?;
        let fpu_page = ContigPages::alloc_order(0).map_err(|_| HvError::NoMemory)?;

        let mut vcpu = Self {
            vmcb_page,
            fpu_page,
            iopm_phys: shared.iopm_phys,
            msrpm_phys: shared.msrpm_phys,
            asid: shared.asid,
            gprs: [0; 16],
            guest_efer: 0,
            guest_xcr0: 1,
            host_xcr0_allow: host_xcr0_allow_mask(),
            guest_tsc_aux: 0,
            guest_tsc_adjust: 0,
            guest_tsc_offset: 0,
            last_tlb_gen: 0,
            last_pcpu: u32::MAX,
            cpuids: Vec::new(),
        };
        vcpu.reset_vmcb(npt_root_pa);
        Ok(vcpu)
    }

    #[inline]
    fn vmcb(&self) -> &Vmcb {
        unsafe { &*(self.vmcb_page.virt() as *const Vmcb) }
    }

    #[inline]
    fn vmcb_mut(&mut self) -> &mut Vmcb {
        unsafe { &mut *(self.vmcb_page.virt() as *mut Vmcb) }
    }

    fn reset_fpu_area(&mut self) {
        unsafe {
            core::ptr::write_bytes(self.fpu_page.virt(), 0, 4096);
            // Architectural x87 FCW = 0x037f (+0) and SSE MXCSR = 0x1f80 (+24)
            (self.fpu_page.virt() as *mut u16).write(0x037f);
            (self.fpu_page.virt().add(24) as *mut u32).write(0x1f80);
        }
    }

    fn reset_vmcb(&mut self, npt_root_pa: u64) {
        unsafe {
            core::ptr::write_bytes(self.vmcb_page.virt(), 0, 4096);
        }
        self.reset_fpu_area();
        self.gprs = [0; 16];
        self.guest_efer = 0;
        self.guest_xcr0 = 1;
        self.guest_tsc_aux = 0;
        self.last_tlb_gen = 0;
        self.last_pcpu = u32::MAX;

        let iopm_phys = self.iopm_phys;
        let msrpm_phys = self.msrpm_phys;
        let asid = self.asid;
        let tsc_offset = self.guest_tsc_offset;
        let vmcb = self.vmcb_mut();

        vmcb.control.intercepts_1 = INTERCEPT_INTR
            | INTERCEPT_NMI
            | INTERCEPT_INIT
            | INTERCEPT_CPUID
            | INTERCEPT_HLT
            | INTERCEPT_IOIO_PROT
            | INTERCEPT_MSR_PROT
            | INTERCEPT_FERR_FREEZE
            | INTERCEPT_SHUTDOWN;
        vmcb.control.intercepts_2 = INTERCEPT_VMRUN
            | INTERCEPT_VMMCALL
            | INTERCEPT_VMLOAD
            | INTERCEPT_VMSAVE
            | INTERCEPT_STGI
            | INTERCEPT_CLGI
            | INTERCEPT_SKINIT
            | INTERCEPT_MONITOR
            | INTERCEPT_MWAIT
            | INTERCEPT_XSETBV;
        vmcb.control.iopm_base_pa = iopm_phys;
        vmcb.control.msrpm_base_pa = msrpm_phys;
        vmcb.control.tsc_offset = tsc_offset;
        vmcb.control.guest_asid = asid;
        vmcb.control.tlb_ctl = 3;
        vmcb.control.int_ctl = V_INTR_MASKING;
        vmcb.control.np_ctl = 1;
        vmcb.control.n_cr3 = npt_root_pa;

        vmcb.save.cs = VmcbSeg {
            selector: 0xf000,
            attrib: 0x009b,
            limit: 0xffff,
            base: 0xffff_0000,
        };
        let data_seg = VmcbSeg {
            selector: 0,
            attrib: 0x0093,
            limit: 0xffff,
            base: 0,
        };
        vmcb.save.ds = data_seg;
        vmcb.save.es = data_seg;
        vmcb.save.fs = data_seg;
        vmcb.save.gs = data_seg;
        vmcb.save.ss = data_seg;
        vmcb.save.ldtr = VmcbSeg {
            selector: 0,
            attrib: 0x0082,
            limit: 0xffff,
            base: 0,
        };
        vmcb.save.tr = VmcbSeg {
            selector: 0,
            attrib: 0x008b,
            limit: 0xffff,
            base: 0,
        };
        vmcb.save.gdtr = VmcbSeg {
            selector: 0,
            attrib: 0,
            limit: 0xffff,
            base: 0,
        };
        vmcb.save.idtr = VmcbSeg {
            selector: 0,
            attrib: 0,
            limit: 0xffff,
            base: 0,
        };
        vmcb.save.cpl = 0;
        vmcb.save.efer = EFER_SVME;
        vmcb.save.cr0 = 0x6000_0010;
        vmcb.save.cr4 = 0;
        vmcb.save.cr3 = 0;
        vmcb.save.dr6 = 0xffff_0ff0;
        vmcb.save.dr7 = 0x0000_0400;
        vmcb.save.rflags = 0x2;
        vmcb.save.rip = 0xfff0;
        vmcb.save.g_pat = DEFAULT_PAT;
    }

    pub fn configure_cpuids(&mut self, cpuids: &[RawCpuid]) -> HvResult<()> {
        self.cpuids.clear();
        self.cpuids
            .try_reserve_exact(cpuids.len())
            .map_err(|_| HvError::NoMemory)?;
        self.cpuids.extend_from_slice(cpuids);
        Ok(())
    }

    pub fn apply_sipi(&mut self, start_page: u8, npt_root_pa: u64) {
        self.reset_vmcb(npt_root_pa);
        let vmcb = self.vmcb_mut();
        vmcb.save.cs = VmcbSeg {
            selector: (start_page as u16) << 8,
            attrib: 0x009b,
            limit: 0xffff,
            base: (start_page as u64) << 12,
        };
        vmcb.save.rip = 0;
    }

    pub fn advance_rip(&mut self, bytes: u8) {
        let vmcb = self.vmcb_mut();
        vmcb.save.rip = vmcb.save.rip.wrapping_add(bytes as u64);
        vmcb.control.int_state &= !1;
    }

    pub fn complete_rdmsr(&mut self, val: u64, insn_len: u8) {
        let rax = (val as u32) as u64;
        self.gprs[GPR_RAX] = rax;
        self.gprs[GPR_RDX] = (val >> 32) & 0xffff_ffff;
        let vmcb = self.vmcb_mut();
        vmcb.save.rax = rax;
        vmcb.save.rip = vmcb.save.rip.wrapping_add(insn_len as u64);
        vmcb.control.int_state &= !1;
    }

    pub fn inject_gp0(&mut self) {
        self.vmcb_mut().control.event_inj =
            EVENT_INJ_VALID | EVENT_INJ_ERR_VALID | EVENT_TYPE_EXC | 13;
    }

    fn inject_exception(&mut self, vector: u8, error_code: Option<u32>) {
        let mut ev = EVENT_INJ_VALID | EVENT_TYPE_EXC | (vector as u64);
        if let Some(ec) = error_code {
            ev |= EVENT_INJ_ERR_VALID | ((ec as u64) << 32);
        }
        self.vmcb_mut().control.event_inj = ev;
    }

    fn gpr_idx(reg: Reg) -> Option<usize> {
        match reg {
            Reg::Rax => Some(GPR_RAX),
            Reg::Rcx => Some(GPR_RCX),
            Reg::Rdx => Some(GPR_RDX),
            Reg::Rbx => Some(GPR_RBX),
            Reg::Rsp => Some(GPR_RSP),
            Reg::Rbp => Some(GPR_RBP),
            Reg::Rsi => Some(GPR_RSI),
            Reg::Rdi => Some(GPR_RDI),
            Reg::R8 => Some(GPR_R8),
            Reg::R9 => Some(GPR_R9),
            Reg::R10 => Some(GPR_R10),
            Reg::R11 => Some(GPR_R11),
            Reg::R12 => Some(GPR_R12),
            Reg::R13 => Some(GPR_R13),
            Reg::R14 => Some(GPR_R14),
            Reg::R15 => Some(GPR_R15),
            Reg::Rip | Reg::Rflags => None,
        }
    }

    pub fn get_regs(&self, lapic: &VcpuLapic, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        if ids.len() != out.len() {
            return Err(HvError::InvalidParam);
        }
        let vmcb = self.vmcb();
        for (&id, dst) in ids.iter().zip(out.iter_mut()) {
            *dst = match id {
                RegId::Gpr(Reg::Rip) => RegVal::Scalar(vmcb.save.rip),
                RegId::Gpr(Reg::Rflags) => RegVal::Scalar(vmcb.save.rflags),
                RegId::Gpr(r) => RegVal::Scalar(self.gprs[Self::gpr_idx(r).unwrap()]),
                RegId::SReg(SReg::Cr0) => RegVal::Scalar(vmcb.save.cr0),
                RegId::SReg(SReg::Cr2) => RegVal::Scalar(vmcb.save.cr2),
                RegId::SReg(SReg::Cr3) => RegVal::Scalar(vmcb.save.cr3),
                RegId::SReg(SReg::Cr4) => RegVal::Scalar(vmcb.save.cr4),
                RegId::SReg(SReg::Cr8) => RegVal::Scalar(lapic.tpr()),
                RegId::SReg(SReg::Efer) => RegVal::Scalar(self.guest_efer),
                RegId::SReg(SReg::ApicBase) => RegVal::Scalar(lapic.apic_base()),
                RegId::SegReg(SegReg::Cs) => RegVal::Seg(vmcb_to_seg(vmcb.save.cs)),
                RegId::SegReg(SegReg::Ds) => RegVal::Seg(vmcb_to_seg(vmcb.save.ds)),
                RegId::SegReg(SegReg::Es) => RegVal::Seg(vmcb_to_seg(vmcb.save.es)),
                RegId::SegReg(SegReg::Fs) => RegVal::Seg(vmcb_to_seg(vmcb.save.fs)),
                RegId::SegReg(SegReg::Gs) => RegVal::Seg(vmcb_to_seg(vmcb.save.gs)),
                RegId::SegReg(SegReg::Ss) => RegVal::Seg(vmcb_to_seg(vmcb.save.ss)),
                RegId::SegReg(SegReg::Tr) => RegVal::Seg(vmcb_to_seg(vmcb.save.tr)),
                RegId::SegReg(SegReg::Ldtr) => RegVal::Seg(vmcb_to_seg(vmcb.save.ldtr)),
                RegId::DtReg(DtReg::Gdtr) => RegVal::Dt(DtRegVal {
                    base: vmcb.save.gdtr.base,
                    limit: vmcb.save.gdtr.limit as u16,
                }),
                RegId::DtReg(DtReg::Idtr) => RegVal::Dt(DtRegVal {
                    base: vmcb.save.idtr.base,
                    limit: vmcb.save.idtr.limit as u16,
                }),
                RegId::Msr(msr) => {
                    let v = match msr {
                        MSR_IA32_EFER => self.guest_efer,
                        MSR_STAR => vmcb.save.star,
                        MSR_LSTAR => vmcb.save.lstar,
                        MSR_CSTAR => vmcb.save.cstar,
                        MSR_SFMASK => vmcb.save.sfmask,
                        MSR_FS_BASE => vmcb.save.fs.base,
                        MSR_GS_BASE => vmcb.save.gs.base,
                        MSR_KERNEL_GS_BASE => vmcb.save.kernel_gs_base,
                        MSR_SYSENTER_CS => vmcb.save.sysenter_cs,
                        MSR_SYSENTER_ESP => vmcb.save.sysenter_esp,
                        MSR_SYSENTER_EIP => vmcb.save.sysenter_eip,
                        MSR_PAT => vmcb.save.g_pat,
                        MSR_TSC_AUX => self.guest_tsc_aux,
                        MSR_IA32_TSC => rdtsc_now().wrapping_add(self.guest_tsc_offset),
                        MSR_IA32_TSC_ADJUST => self.guest_tsc_adjust,
                        _ => lapic.try_rdmsr(msr).unwrap_or(0),
                    };
                    RegVal::Scalar(v)
                }
                RegId::MpState => RegVal::MpState(lapic.mp_state()),
            };
        }
        Ok(())
    }

    pub fn set_regs(&mut self, lapic: &VcpuLapic, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        for &(id, val) in regs {
            match (id, val) {
                (RegId::Gpr(Reg::Rip), RegVal::Scalar(v)) => self.vmcb_mut().save.rip = v,
                (RegId::Gpr(Reg::Rflags), RegVal::Scalar(v)) => {
                    self.vmcb_mut().save.rflags = v | 0x2;
                }
                (RegId::Gpr(r), RegVal::Scalar(v)) => {
                    let idx = Self::gpr_idx(r).unwrap();
                    self.gprs[idx] = v;
                    if idx == GPR_RAX {
                        self.vmcb_mut().save.rax = v;
                    } else if idx == GPR_RSP {
                        self.vmcb_mut().save.rsp = v;
                    }
                }
                (RegId::SReg(SReg::Cr0), RegVal::Scalar(v)) => self.vmcb_mut().save.cr0 = v,
                (RegId::SReg(SReg::Cr2), RegVal::Scalar(v)) => self.vmcb_mut().save.cr2 = v,
                (RegId::SReg(SReg::Cr3), RegVal::Scalar(v)) => self.vmcb_mut().save.cr3 = v,
                (RegId::SReg(SReg::Cr4), RegVal::Scalar(v)) => self.vmcb_mut().save.cr4 = v,
                (RegId::SReg(SReg::Cr8), RegVal::Scalar(v)) => lapic.set_tpr_cr8(v),
                (RegId::SReg(SReg::Efer), RegVal::Scalar(v)) => {
                    self.guest_efer = v & !EFER_SVME;
                    self.vmcb_mut().save.efer = self.guest_efer | EFER_SVME;
                }
                (RegId::SReg(SReg::ApicBase), RegVal::Scalar(v)) => lapic.set_apic_base(v),
                (RegId::SegReg(SegReg::Cs), RegVal::Seg(s)) => {
                    let vseg = seg_to_vmcb(s);
                    let cpl = ((vseg.attrib >> 5) & 0x3) as u8;
                    let vmcb = self.vmcb_mut();
                    vmcb.save.cs = vseg;
                    vmcb.save.cpl = cpl;
                }
                (RegId::SegReg(SegReg::Ds), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.ds = seg_to_vmcb(s);
                }
                (RegId::SegReg(SegReg::Es), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.es = seg_to_vmcb(s);
                }
                (RegId::SegReg(SegReg::Fs), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.fs = seg_to_vmcb(s);
                }
                (RegId::SegReg(SegReg::Gs), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.gs = seg_to_vmcb(s);
                }
                (RegId::SegReg(SegReg::Ss), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.ss = seg_to_vmcb(s);
                }
                (RegId::SegReg(SegReg::Tr), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.tr = seg_to_vmcb(s);
                }
                (RegId::SegReg(SegReg::Ldtr), RegVal::Seg(s)) => {
                    self.vmcb_mut().save.ldtr = seg_to_vmcb(s);
                }
                (RegId::DtReg(DtReg::Gdtr), RegVal::Dt(d)) => {
                    let gdtr = &mut self.vmcb_mut().save.gdtr;
                    gdtr.base = d.base;
                    gdtr.limit = d.limit as u32;
                }
                (RegId::DtReg(DtReg::Idtr), RegVal::Dt(d)) => {
                    let idtr = &mut self.vmcb_mut().save.idtr;
                    idtr.base = d.base;
                    idtr.limit = d.limit as u32;
                }
                (RegId::Msr(msr), RegVal::Scalar(v)) => match msr {
                    MSR_IA32_EFER => {
                        self.guest_efer = v & !EFER_SVME;
                        self.vmcb_mut().save.efer = self.guest_efer | EFER_SVME;
                    }
                    MSR_STAR => self.vmcb_mut().save.star = v,
                    MSR_LSTAR => self.vmcb_mut().save.lstar = v,
                    MSR_CSTAR => self.vmcb_mut().save.cstar = v,
                    MSR_SFMASK => self.vmcb_mut().save.sfmask = v,
                    MSR_FS_BASE => self.vmcb_mut().save.fs.base = v,
                    MSR_GS_BASE => self.vmcb_mut().save.gs.base = v,
                    MSR_KERNEL_GS_BASE => self.vmcb_mut().save.kernel_gs_base = v,
                    MSR_SYSENTER_CS => self.vmcb_mut().save.sysenter_cs = v,
                    MSR_SYSENTER_ESP => self.vmcb_mut().save.sysenter_esp = v,
                    MSR_SYSENTER_EIP => self.vmcb_mut().save.sysenter_eip = v,
                    MSR_PAT => self.vmcb_mut().save.g_pat = v,
                    MSR_TSC_AUX => self.guest_tsc_aux = v,
                    MSR_IA32_TSC => {
                        let new_off = v.wrapping_sub(rdtsc_now());
                        let delta = new_off.wrapping_sub(self.guest_tsc_offset);
                        self.guest_tsc_offset = new_off;
                        self.guest_tsc_adjust = self.guest_tsc_adjust.wrapping_add(delta);
                        self.vmcb_mut().control.tsc_offset = new_off;
                    }
                    MSR_IA32_TSC_ADJUST => {
                        let delta = v.wrapping_sub(self.guest_tsc_adjust);
                        self.guest_tsc_adjust = v;
                        self.guest_tsc_offset = self.guest_tsc_offset.wrapping_add(delta);
                        self.vmcb_mut().control.tsc_offset = self.guest_tsc_offset;
                    }
                    _ => {
                        let _ = lapic.try_wrmsr(msr, v);
                    }
                },
                (RegId::MpState, RegVal::MpState(st)) => lapic.set_mp_state(st),
                _ => return Err(HvError::InvalidParam),
            }
        }
        Ok(())
    }

    pub fn sync_to_comm(&self, comm: &mut VcpuCommPage) {
        let vmcb = self.vmcb();
        comm.gprs = self.gprs;
        comm.rip = vmcb.save.rip;
        comm.rflags = vmcb.save.rflags;
        comm.cr0 = vmcb.save.cr0;
        comm.cr2 = vmcb.save.cr2;
        comm.cr3 = vmcb.save.cr3;
        comm.cr4 = vmcb.save.cr4;
        comm.efer = self.guest_efer;
        comm.cs = RawSegReg::from(vmcb_to_seg(vmcb.save.cs));
        comm.ds_base = vmcb.save.ds.base;
        comm.es_base = vmcb.save.es.base;
        comm.fs_base = vmcb.save.fs.base;
        comm.gs_base = vmcb.save.gs.base;
        comm.ss_base = vmcb.save.ss.base;
        comm.synced_regs = SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS | SYNC_REG_SREGS;
    }

    fn flush_from_comm(&mut self, comm: &mut VcpuCommPage) {
        let dirty = comm.dirty_regs;
        if dirty != 0 {
            if (dirty & SYNC_REG_GPRS) != 0 {
                self.gprs = comm.gprs;
            }
            let guest_efer = comm.efer & !EFER_SVME;
            if (dirty & SYNC_REG_SREGS) != 0 {
                self.guest_efer = guest_efer;
            }
            let vmcb = self.vmcb_mut();
            if (dirty & SYNC_REG_GPRS) != 0 {
                vmcb.save.rax = comm.gprs[GPR_RAX];
                vmcb.save.rsp = comm.gprs[GPR_RSP];
            }
            if (dirty & SYNC_REG_RIP_RFLAGS) != 0 {
                vmcb.save.rip = comm.rip;
                vmcb.save.rflags = comm.rflags | 0x2;
                vmcb.control.int_state &= !1;
            }
            if (dirty & SYNC_REG_SREGS) != 0 {
                vmcb.save.cr0 = comm.cr0;
                vmcb.save.cr2 = comm.cr2;
                vmcb.save.cr3 = comm.cr3;
                vmcb.save.cr4 = comm.cr4;
                vmcb.save.efer = guest_efer | EFER_SVME;
                let cs_seg = seg_to_vmcb(SegRegVal::from(comm.cs));
                vmcb.save.cpl = ((cs_seg.attrib >> 5) & 0x3) as u8;
                vmcb.save.cs = cs_seg;
            }
            comm.dirty_regs = 0;
        }

        let entry = comm.entry.to_entry();
        comm.entry = RawVmEntry::default();
        match entry {
            VmEntry::None | VmEntry::Io { .. } | VmEntry::Mmio { .. } => {}
            VmEntry::Msr { error, .. } => {
                if error != 0 {
                    self.inject_gp0();
                }
            }
            VmEntry::InjectFault { vector, error_code } => {
                self.inject_exception(vector, error_code);
            }
            VmEntry::Shutdown | VmEntry::Reboot => {}
        }
    }

    fn lookup_cpuid(&self, func: u32, index: u32) -> (u32, u32, u32, u32) {
        for c in &self.cpuids {
            if c.func == func && (c.has_index == 0 || c.index == index) {
                return (c.eax, c.ebx, c.ecx, c.edx);
            }
        }
        (0, 0, 0, 0)
    }

    #[inline]
    fn insn_step(vmcb: &Vmcb, fallback: u64) -> u64 {
        if vmcb.control.next_rip > vmcb.save.rip {
            vmcb.control.next_rip - vmcb.save.rip
        } else {
            fallback
        }
    }

    pub fn enter_guest(
        &mut self,
        lapic: &VcpuLapic,
        stage2: &Stage2Mmu,
        comm: &mut VcpuCommPage,
    ) -> HvResult<FastExit> {
        self.flush_from_comm(comm);
        lapic.clear_kick_flag();

        let cur_tlb_gen = stage2.tlb_gen();
        let npt_root_pa = stage2.root_phys();

        let need_tlb_flush = self.last_tlb_gen != cur_tlb_gen;
        if need_tlb_flush {
            self.last_tlb_gen = cur_tlb_gen;
        }
        let rax = self.gprs[GPR_RAX];
        let rsp = self.gprs[GPR_RSP];
        let efer = self.guest_efer | EFER_SVME;

        {
            let vmcb = self.vmcb_mut();
            vmcb.control.n_cr3 = npt_root_pa;
            vmcb.control.clean_bits = 0;
            vmcb.save.rax = rax;
            vmcb.save.rsp = rsp;
            vmcb.save.efer = efer;
            vmcb.control.tlb_ctl = if need_tlb_flush { 3 } else { 0 };

            let tpr_cr8 = (lapic.tpr() as u32) & 0xf;
            let mut int_ctl = V_INTR_MASKING | tpr_cr8;

            if (vmcb.control.event_inj & EVENT_INJ_VALID) == 0 {
                let in_shadow = (vmcb.control.int_state & 1) != 0;
                let guest_if = (vmcb.save.rflags & (1 << 9)) != 0 && !in_shadow;
                let (inject_vec, need_window) = lapic.pop_injectable_interrupt(guest_if);
                if let Some(vec) = inject_vec {
                    vmcb.control.event_inj = EVENT_INJ_VALID | EVENT_TYPE_INTR | (vec as u64);
                }
                if need_window {
                    vmcb.control.intercepts_1 |= INTERCEPT_VINTR;
                    int_ctl |= V_IRQ | V_IGN_TPR | V_INTR_PRIO_MAX;
                } else {
                    vmcb.control.intercepts_1 &= !INTERCEPT_VINTR;
                }
            } else {
                vmcb.control.intercepts_1 &= !INTERCEPT_VINTR;
            }
            vmcb.control.int_ctl = int_ctl;
        }

        let aborted = unsafe {
            airlock_kapi_svm_run_slice(
                self.gprs.as_mut_ptr(),
                self.vmcb_page.phys(),
                self.vmcb_page.virt() as *mut c_void,
                self.fpu_page.virt(),
                self.guest_xcr0,
                self.guest_tsc_aux,
                lapic.kick_flag_ptr(),
                lapic.on_cpu_mut_ptr(),
                &mut self.last_pcpu,
            )
        };
        if aborted != 0 {
            return Ok(FastExit::HostIntr);
        }

        {
            let (rax_out, rsp_out, efer_out, int_ctl_out) = {
                let vmcb = self.vmcb();
                (
                    vmcb.save.rax,
                    vmcb.save.rsp,
                    vmcb.save.efer,
                    vmcb.control.int_ctl,
                )
            };
            self.gprs[GPR_RAX] = rax_out;
            self.gprs[GPR_RSP] = rsp_out;
            self.guest_efer = efer_out & !EFER_SVME;
            lapic.set_tpr_cr8((int_ctl_out & 0xf) as u64);
        }

        // Preserve any interrupted event vectoring across intercepts (e.g., NPF during IDT push).
        {
            let vmcb = self.vmcb_mut();
            let exit_int = vmcb.control.exit_int_info;
            if (exit_int & EVENT_INJ_VALID) != 0 && (vmcb.control.event_inj & EVENT_INJ_VALID) == 0
            {
                let int_type = (exit_int >> 8) & 0x7;
                if int_type == 0 || int_type == 2 || int_type == 3 {
                    vmcb.control.event_inj = exit_int;
                }
            }
        }

        let (exit_code, info1, info2) = {
            let vmcb = self.vmcb();
            (
                vmcb.control.exit_code,
                vmcb.control.exit_info_1,
                vmcb.control.exit_info_2,
            )
        };

        match exit_code {
            VMEXIT_INTR | VMEXIT_NMI => Ok(FastExit::HostIntr),
            VMEXIT_VINTR => {
                self.vmcb_mut().control.intercepts_1 &= !INTERCEPT_VINTR;
                Ok(FastExit::EmulateHandled)
            }
            VMEXIT_CPUID => {
                let func = self.gprs[GPR_RAX] as u32;
                let index = self.gprs[GPR_RCX] as u32;
                let (eax, ebx, ecx, edx) = self.lookup_cpuid(func, index);
                let rax_new = eax as u64;
                self.gprs[GPR_RAX] = rax_new;
                self.gprs[GPR_RBX] = ebx as u64;
                self.gprs[GPR_RCX] = ecx as u64;
                self.gprs[GPR_RDX] = edx as u64;
                let step = Self::insn_step(self.vmcb(), 2);
                let vmcb = self.vmcb_mut();
                vmcb.save.rax = rax_new;
                vmcb.save.rip = vmcb.save.rip.wrapping_add(step);
                vmcb.control.int_state &= !1;
                Ok(FastExit::Cpuid)
            }
            VMEXIT_HLT => {
                let step = Self::insn_step(self.vmcb(), 1);
                let vmcb = self.vmcb_mut();
                vmcb.save.rip = vmcb.save.rip.wrapping_add(step);
                vmcb.control.int_state &= !1;
                Ok(FastExit::Hlt)
            }
            VMEXIT_IOIO => {
                if (info1 & (1 << 2)) != 0 {
                    self.inject_gp0();
                    return Ok(FastExit::EmulateHandled);
                }
                let is_in = (info1 & 1) != 0;
                let size: u8 = if (info1 & (1 << 4)) != 0 {
                    1
                } else if (info1 & (1 << 5)) != 0 {
                    2
                } else {
                    4
                };
                let port = ((info1 >> 16) & 0xffff) as u16;
                let rip = self.vmcb().save.rip;
                let insn_len = info2.wrapping_sub(rip) as u8;
                let write = if is_in {
                    None
                } else {
                    let mask = match size {
                        1 => 0xff,
                        2 => 0xffff,
                        _ => 0xffff_ffff,
                    };
                    Some((self.gprs[GPR_RAX] & mask) as u32)
                };
                self.sync_to_comm(comm);
                let mut raw = RawVmExit::from_exit(VmExit::Io { port, write, size });
                raw.insn_len = insn_len;
                comm.exit = raw;
                Ok(FastExit::Pio {
                    port,
                    write,
                    size,
                    insn_len,
                })
            }
            VMEXIT_MSR => {
                let msr = self.gprs[GPR_RCX] as u32;
                let insn_len = Self::insn_step(self.vmcb(), 2) as u8;
                if (info1 & 1) != 0 {
                    let val = ((self.gprs[GPR_RDX] & 0xffff_ffff) << 32)
                        | (self.gprs[GPR_RAX] & 0xffff_ffff);
                    match msr {
                        MSR_IA32_EFER => {
                            let pg = (self.vmcb().save.cr0 & (1 << 31)) != 0;
                            let mut new_efer = val & !(EFER_SVME | EFER_LMA);
                            if pg && (new_efer & EFER_LME) != 0 {
                                new_efer |= EFER_LMA;
                            }
                            self.guest_efer = new_efer;
                            let vmcb = self.vmcb_mut();
                            vmcb.save.efer = new_efer | EFER_SVME;
                            vmcb.save.rip = vmcb.save.rip.wrapping_add(insn_len as u64);
                            vmcb.control.int_state &= !1;
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_PAT => {
                            let vmcb = self.vmcb_mut();
                            vmcb.save.g_pat = val;
                            vmcb.save.rip = vmcb.save.rip.wrapping_add(insn_len as u64);
                            vmcb.control.int_state &= !1;
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_TSC_AUX => {
                            self.guest_tsc_aux = val;
                            self.advance_rip(insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_IA32_TSC => {
                            let new_off = val.wrapping_sub(rdtsc_now());
                            let delta = new_off.wrapping_sub(self.guest_tsc_offset);
                            self.guest_tsc_offset = new_off;
                            self.guest_tsc_adjust = self.guest_tsc_adjust.wrapping_add(delta);
                            self.vmcb_mut().control.tsc_offset = new_off;
                            self.advance_rip(insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_IA32_TSC_ADJUST => {
                            let delta = val.wrapping_sub(self.guest_tsc_adjust);
                            self.guest_tsc_adjust = val;
                            self.guest_tsc_offset = self.guest_tsc_offset.wrapping_add(delta);
                            self.vmcb_mut().control.tsc_offset = self.guest_tsc_offset;
                            self.advance_rip(insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        _ => Ok(FastExit::MsrWrite { msr, val, insn_len }),
                    }
                } else {
                    match msr {
                        MSR_IA32_EFER => {
                            self.complete_rdmsr(self.guest_efer, insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_PAT => {
                            let pat = self.vmcb().save.g_pat;
                            self.complete_rdmsr(pat, insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_TSC_AUX => {
                            self.complete_rdmsr(self.guest_tsc_aux, insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_IA32_TSC => {
                            let tsc = rdtsc_now().wrapping_add(self.guest_tsc_offset);
                            self.complete_rdmsr(tsc, insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        MSR_IA32_TSC_ADJUST => {
                            self.complete_rdmsr(self.guest_tsc_adjust, insn_len);
                            Ok(FastExit::EmulateHandled)
                        }
                        _ => Ok(FastExit::MsrRead { msr, insn_len }),
                    }
                }
            }
            VMEXIT_XSETBV => {
                let index = self.gprs[GPR_RCX] as u32;
                let val =
                    ((self.gprs[GPR_RDX] & 0xffff_ffff) << 32) | (self.gprs[GPR_RAX] & 0xffff_ffff);
                let insn_len = Self::insn_step(self.vmcb(), 3) as u8;
                let cpl = self.vmcb().save.cpl;
                let cr4 = self.vmcb().save.cr4;
                let valid = cpl == 0
                    && (cr4 & (1 << 18)) != 0
                    && index == 0
                    && (val & 1) != 0
                    && (val & !self.host_xcr0_allow) == 0
                    && (val & 0x6) != 0x4;
                if valid {
                    self.guest_xcr0 = val;
                    self.advance_rip(insn_len);
                } else {
                    self.inject_gp0();
                }
                Ok(FastExit::EmulateHandled)
            }
            VMEXIT_VMMCALL => {
                let step = Self::insn_step(self.vmcb(), 3);
                let ret = if self.vmcb().save.cpl == 0 {
                    (-1000i64) as u64
                } else {
                    (-1i64) as u64
                };
                self.gprs[GPR_RAX] = ret;
                let vmcb = self.vmcb_mut();
                vmcb.save.rax = ret;
                vmcb.save.rip = vmcb.save.rip.wrapping_add(step);
                vmcb.control.int_state &= !1;
                Ok(FastExit::EmulateHandled)
            }
            VMEXIT_VMRUN | VMEXIT_VMLOAD | VMEXIT_VMSAVE | VMEXIT_STGI | VMEXIT_CLGI
            | VMEXIT_SKINIT | VMEXIT_MONITOR | VMEXIT_MWAIT => {
                self.inject_exception(6, None);
                Ok(FastExit::EmulateHandled)
            }
            VMEXIT_NPF => {
                let is_write = (info1 & 0x2) != 0;
                let gpa = info2;
                let (insn_len, insn_bytes) = {
                    let vmcb = self.vmcb();
                    (vmcb.control.insn_len, vmcb.control.insn_bytes)
                };
                self.sync_to_comm(comm);
                comm.exit = RawVmExit::from_exit(VmExit::MmioFault {
                    gpa,
                    gva: None,
                    is_write,
                    insn_len,
                    insn_bytes,
                });
                Ok(FastExit::MmioFault { gpa, is_write })
            }
            VMEXIT_SHUTDOWN => {
                let vmcb = self.vmcb();
                kerr!(
                    "SVM VMEXIT_SHUTDOWN: rip={:#x} rsp={:#x} cr0={:#x} cr2={:#x} cr3={:#x} cr4={:#x} efer={:#x} exit_int={:#x}",
                    vmcb.save.rip,
                    vmcb.save.rsp,
                    vmcb.save.cr0,
                    vmcb.save.cr2,
                    vmcb.save.cr3,
                    vmcb.save.cr4,
                    vmcb.save.efer,
                    vmcb.control.exit_int_info,
                );
                Ok(FastExit::Shutdown)
            }
            VMEXIT_INVALID => {
                kerr!(
                    "SVM VMEXIT_INVALID: rip={:#x} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x}",
                    self.vmcb().save.rip,
                    self.vmcb().save.cr0,
                    self.vmcb().save.cr3,
                    self.vmcb().save.cr4,
                    self.vmcb().save.efer,
                );
                Err(HvError::HardwareFault)
            }
            other => {
                kerr!(
                    "Unhandled SVM exit {other:#x} info1={info1:#x} info2={info2:#x} rip={:#x}",
                    self.vmcb().save.rip
                );
                Err(HvError::HardwareFault)
            }
        }
    }
}
