// Ring-0 per-vCPU Local APIC (x2APIC MSRs + early xAPIC MMIO at `0xfee0_0000`),
// TSC-deadline & one-shot/periodic countdown timer, and INIT/SIPI state machine.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use vmm_core::host::abi::{RawVmExit, VcpuCommPage, SYNC_REG_GPRS, SYNC_REG_RIP_RFLAGS};
use vmm_core::host::{HvError, HvResult, MpState};

use crate::arch::time::{nanos_to_tsc_delta, rdtsc_now, tsc_delta_to_nanos, Instant};
use crate::mm::PAGING_DIRECT_MAP_OFFSET;
use crate::uspace::SysObject;

use super::stage2::Stage2Mmu;

pub const MSR_IA32_APIC_BASE: u32 = 0x1b;
pub const MSR_IA32_TSC_DEADLINE: u32 = 0x6e0;

const X2APIC_ID: u32 = 0x802;
const X2APIC_VER: u32 = 0x803;
const X2APIC_TPR: u32 = 0x808;
const X2APIC_PPR: u32 = 0x80a;
const X2APIC_EOI: u32 = 0x80b;
const X2APIC_LDR: u32 = 0x80d;
const X2APIC_SVR: u32 = 0x80f;
const X2APIC_ISR_BASE: u32 = 0x810;
const X2APIC_TMR_BASE: u32 = 0x818;
const X2APIC_IRR_BASE: u32 = 0x820;
const X2APIC_ESR: u32 = 0x828;
const X2APIC_ICR: u32 = 0x830;
const X2APIC_LVT_TIMER: u32 = 0x832;
const X2APIC_LVT_THERMAL: u32 = 0x833;
const X2APIC_LVT_PMI: u32 = 0x834;
const X2APIC_LVT_LINT0: u32 = 0x835;
const X2APIC_LVT_LINT1: u32 = 0x836;
const X2APIC_LVT_ERROR: u32 = 0x837;
const X2APIC_INIT_COUNT: u32 = 0x838;
const X2APIC_CUR_COUNT: u32 = 0x839;
const X2APIC_DIV_CONF: u32 = 0x83e;
const X2APIC_SELF_IPI: u32 = 0x83f;

const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_MODE_MASK: u32 = 0b11 << 17;
const LVT_TIMER_MODE_ONESHOT: u32 = 0b00 << 17;
const LVT_TIMER_MODE_PERIODIC: u32 = 0b01 << 17;
const LVT_TIMER_MODE_TSC_DEADLINE: u32 = 0b10 << 17;
const SVR_APIC_ENABLED: u32 = 1 << 8;

pub const DEFAULT_APIC_BASE: u64 = 0xfee0_0000;
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_EXTD: u64 = 1 << 10;
const APIC_BASE_EN: u64 = 1 << 11;

#[inline]
fn timer_divide_shift(div_conf: u32) -> u32 {
    let code = ((div_conf & 0x8) >> 1) | (div_conf & 0x3);
    match code {
        0b000 => 1,
        0b001 => 2,
        0b010 => 3,
        0b011 => 4,
        0b100 => 5,
        0b101 => 6,
        0b110 => 7,
        _ => 0,
    }
}

/// Action emitted when a guest writes `X2APIC_ICR` (`INIT`, `SIPI`, or cross-vCPU IPI).
#[derive(Clone, Copy)]
pub enum IpiAction {
    None,
    Fixed {
        dest: u32,
        shorthand: u8,
        vector: u8,
    },
    Init {
        dest: u32,
        shorthand: u8,
    },
    Sipi {
        dest: u32,
        shorthand: u8,
        start_page: u8,
    },
}

pub struct VcpuLapic {
    vcpu_id: u32,
    apic_base: AtomicU64,
    tpr: AtomicU32,
    svr: AtomicU32,
    esr: AtomicU32,
    icr_hi: AtomicU32,
    dfr: AtomicU32,
    xapic_ldr: AtomicU32,
    lvt_timer: AtomicU32,
    lvt_lint0: AtomicU32,
    lvt_lint1: AtomicU32,
    lvt_error: AtomicU32,
    lvt_pmi: AtomicU32,
    lvt_thermal: AtomicU32,
    init_count: AtomicU32,
    div_conf: AtomicU32,
    count_deadline_tsc: AtomicU64,
    count_period_tsc: AtomicU64,
    tsc_deadline: AtomicU64,
    irr: [AtomicU64; 4],
    isr: [AtomicU64; 4],
    mp_state: AtomicU32,
    sipi_vector: AtomicU8,
    on_cpu: AtomicU32,
    pub kick_obj: Arc<SysObject>,
}

impl VcpuLapic {
    pub fn new(vcpu_id: u32) -> Self {
        let base = DEFAULT_APIC_BASE | APIC_BASE_EN | if vcpu_id == 0 { APIC_BASE_BSP } else { 0 };
        let initial_mp = if vcpu_id == 0 {
            MpState::Runnable as u32
        } else {
            MpState::Uninitialized as u32
        };
        Self {
            vcpu_id,
            apic_base: AtomicU64::new(base),
            tpr: AtomicU32::new(0),
            svr: AtomicU32::new(0x1ff),
            esr: AtomicU32::new(0),
            icr_hi: AtomicU32::new(0),
            dfr: AtomicU32::new(0xffff_ffff),
            xapic_ldr: AtomicU32::new(0),
            lvt_timer: AtomicU32::new(LVT_MASKED),
            lvt_lint0: AtomicU32::new(LVT_MASKED),
            lvt_lint1: AtomicU32::new(LVT_MASKED),
            lvt_error: AtomicU32::new(LVT_MASKED),
            lvt_pmi: AtomicU32::new(LVT_MASKED),
            lvt_thermal: AtomicU32::new(LVT_MASKED),
            init_count: AtomicU32::new(0),
            div_conf: AtomicU32::new(0),
            count_deadline_tsc: AtomicU64::new(0),
            count_period_tsc: AtomicU64::new(0),
            tsc_deadline: AtomicU64::new(0),
            irr: [const { AtomicU64::new(0) }; 4],
            isr: [const { AtomicU64::new(0) }; 4],
            mp_state: AtomicU32::new(initial_mp),
            sipi_vector: AtomicU8::new(0),
            on_cpu: AtomicU32::new(u32::MAX),
            kick_obj: SysObject::new(Arc::new(alloc::format!("vcpu_kick:{vcpu_id}"))),
        }
    }

    pub fn set_on_cpu(&self, pcpu: Option<u32>) {
        self.on_cpu
            .store(pcpu.unwrap_or(u32::MAX), Ordering::Release);
    }

    pub fn kick(&self) {
        self.kick_obj.wake(false);
        let pcpu = self.on_cpu.load(Ordering::Acquire);
        if pcpu != u32::MAX && pcpu != crate::arch::current_cpu() as u32 {
            crate::sched::poke_cpu(pcpu);
        }
    }

    pub fn mp_state(&self) -> MpState {
        MpState::from_u32(self.mp_state.load(Ordering::Acquire)).unwrap_or(MpState::Runnable)
    }

    pub fn set_mp_state(&self, state: MpState) {
        self.mp_state.store(state as u32, Ordering::Release);
        if state == MpState::Runnable {
            self.kick();
        }
    }

    pub fn apic_base(&self) -> u64 {
        self.apic_base.load(Ordering::Acquire)
    }

    pub fn set_apic_base(&self, val: u64) {
        self.apic_base.store(val, Ordering::Release);
    }

    pub fn tpr(&self) -> u64 {
        (self.tpr.load(Ordering::Acquire) >> 4) as u64 & 0xf
    }

    pub fn set_tpr_cr8(&self, cr8: u64) {
        self.tpr.store((cr8 as u32 & 0xf) << 4, Ordering::Release);
    }

    pub fn receive_init(&self) {
        if self.vcpu_id != 0 {
            self.mp_state
                .store(MpState::InitReceived as u32, Ordering::Release);
            self.kick();
        }
    }

    pub fn receive_sipi(&self, start_page: u8) {
        if self.vcpu_id == 0 {
            return;
        }
        self.sipi_vector.store(start_page, Ordering::Release);
        let prev = self.mp_state.load(Ordering::Acquire);
        if prev == MpState::InitReceived as u32 || prev == MpState::Uninitialized as u32 {
            self.mp_state
                .store(MpState::SipiReceived as u32, Ordering::Release);
            self.kick();
        }
    }

    /// Consumes a pending `SipiReceived` state on the AP thread itself, returning
    /// `Some(start_page)` and transitioning the AP to `MpState::Runnable`.
    pub fn take_sipi(&self) -> Option<u8> {
        if self
            .mp_state
            .compare_exchange(
                MpState::SipiReceived as u32,
                MpState::Runnable as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            Some(self.sipi_vector.load(Ordering::Acquire))
        } else {
            None
        }
    }

    pub fn set_irr(&self, vector: u8) {
        if vector < 16 {
            return;
        }
        let word = (vector >> 6) as usize;
        let bit = 1u64 << (vector & 63);
        self.irr[word].fetch_or(bit, Ordering::AcqRel);
        if self.mp_state.load(Ordering::Acquire) == MpState::Halted as u32 {
            let _ = self.mp_state.compare_exchange(
                MpState::Halted as u32,
                MpState::Runnable as u32,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
        self.kick();
    }

    fn arm_countdown(&self, count: u32) {
        self.init_count.store(count, Ordering::Release);
        let lvt = self.lvt_timer.load(Ordering::Acquire);
        if count == 0 || (lvt & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_TSC_DEADLINE {
            self.count_deadline_tsc.store(0, Ordering::Release);
            self.count_period_tsc.store(0, Ordering::Release);
            return;
        }
        let shift = timer_divide_shift(self.div_conf.load(Ordering::Acquire));
        let nanos = (count as u64) << shift;
        let period_tsc = nanos_to_tsc_delta(nanos).max(1);
        self.count_period_tsc.store(period_tsc, Ordering::Release);
        self.count_deadline_tsc
            .store(rdtsc_now().wrapping_add(period_tsc), Ordering::Release);
    }

    fn read_cur_count(&self) -> u32 {
        self.poll_timer();
        let dl = self.count_deadline_tsc.load(Ordering::Acquire);
        if dl == 0 {
            return 0;
        }
        let now = rdtsc_now();
        if now >= dl {
            return 0;
        }
        let shift = timer_divide_shift(self.div_conf.load(Ordering::Acquire));
        let rem_ns = tsc_delta_to_nanos(dl - now);
        let cur = rem_ns >> shift;
        let max_init = self.init_count.load(Ordering::Acquire) as u64;
        cur.min(max_init) as u32
    }

    #[inline]
    fn latch_timer_irq(&self, lvt: u32) {
        if (lvt & LVT_MASKED) == 0 {
            let vec = (lvt & 0xff) as u8;
            if vec >= 16 {
                let word = (vec >> 6) as usize;
                self.irr[word].fetch_or(1u64 << (vec & 63), Ordering::AcqRel);
            }
        }
    }

    /// Checks whether the armed TSC-deadline or countdown timer has expired, latching its vector into `IRR`.
    pub fn poll_timer(&self) {
        let lvt = self.lvt_timer.load(Ordering::Acquire);
        match lvt & LVT_TIMER_MODE_MASK {
            LVT_TIMER_MODE_TSC_DEADLINE => {
                let dl = self.tsc_deadline.load(Ordering::Acquire);
                if dl != 0
                    && rdtsc_now() >= dl
                    && self
                        .tsc_deadline
                        .compare_exchange(dl, 0, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                {
                    self.latch_timer_irq(lvt);
                }
            }
            LVT_TIMER_MODE_ONESHOT => {
                let dl = self.count_deadline_tsc.load(Ordering::Acquire);
                if dl != 0
                    && rdtsc_now() >= dl
                    && self
                        .count_deadline_tsc
                        .compare_exchange(dl, 0, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                {
                    self.latch_timer_irq(lvt);
                }
            }
            LVT_TIMER_MODE_PERIODIC => {
                let dl = self.count_deadline_tsc.load(Ordering::Acquire);
                let period = self.count_period_tsc.load(Ordering::Acquire);
                if dl != 0 && period != 0 {
                    let now = rdtsc_now();
                    if now >= dl {
                        let elapsed = now - dl;
                        let steps = (elapsed / period) + 1;
                        let next_dl = dl.wrapping_add(steps.saturating_mul(period));
                        if self
                            .count_deadline_tsc
                            .compare_exchange(dl, next_dl, Ordering::AcqRel, Ordering::Relaxed)
                            .is_ok()
                        {
                            self.latch_timer_irq(lvt);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Returns the active future APIC timer deadline as a host `Instant` for `HLT` sleep.
    pub fn active_deadline_instant(&self) -> Option<Instant> {
        self.poll_timer();
        let lvt = self.lvt_timer.load(Ordering::Acquire);
        if (lvt & LVT_MASKED) != 0 {
            return None;
        }
        let dl = match lvt & LVT_TIMER_MODE_MASK {
            LVT_TIMER_MODE_TSC_DEADLINE => self.tsc_deadline.load(Ordering::Acquire),
            LVT_TIMER_MODE_ONESHOT | LVT_TIMER_MODE_PERIODIC => {
                self.count_deadline_tsc.load(Ordering::Acquire)
            }
            _ => 0,
        };
        (dl != 0).then(|| Instant::from_u64(dl))
    }

    fn highest_bit(words: &[AtomicU64; 4]) -> Option<u8> {
        for w in (0..4).rev() {
            let v = words[w].load(Ordering::Acquire);
            if v != 0 {
                let bit = 63 - v.leading_zeros() as u8;
                return Some((w as u8) * 64 + bit);
            }
        }
        None
    }

    fn ppr(&self) -> u8 {
        let tpr_class = (self.tpr.load(Ordering::Acquire) as u8) & 0xf0;
        let isrv_class = Self::highest_bit(&self.isr).map_or(0, |v| v & 0xf0);
        tpr_class.max(isrv_class)
    }

    pub fn has_pending_irr(&self) -> bool {
        self.poll_timer();
        if (self.svr.load(Ordering::Acquire) & SVR_APIC_ENABLED) == 0 {
            return false;
        }
        Self::highest_bit(&self.irr).is_some()
    }

    /// Pops the highest-priority deliverable vector (`IRR > PPR`) into `ISR` if `guest_if`.
    /// If an interrupt is pending in `IRR` but masked by `!guest_if` or `PPR`, returns `(None, true)`
    /// so `svm.rs` arms `INTERCEPT_VINTR` interrupt-window exiting.
    pub fn pop_injectable_interrupt(&self, guest_if: bool) -> (Option<u8>, bool) {
        self.poll_timer();
        if (self.svr.load(Ordering::Acquire) & SVR_APIC_ENABLED) == 0 {
            return (None, false);
        }
        let Some(irr_vec) = Self::highest_bit(&self.irr) else {
            return (None, false);
        };
        let ppr = self.ppr();
        if (irr_vec & 0xf0) <= ppr {
            return (None, false);
        }
        if !guest_if {
            return (None, true);
        }
        let word = (irr_vec >> 6) as usize;
        let mask = 1u64 << (irr_vec & 63);
        if (self.irr[word].fetch_and(!mask, Ordering::AcqRel) & mask) != 0 {
            self.isr[word].fetch_or(mask, Ordering::AcqRel);
            (Some(irr_vec), Self::highest_bit(&self.irr).is_some())
        } else {
            (None, Self::highest_bit(&self.irr).is_some())
        }
    }

    fn eoi(&self) {
        if let Some(isr_vec) = Self::highest_bit(&self.isr) {
            let word = (isr_vec >> 6) as usize;
            let mask = 1u64 << (isr_vec & 63);
            self.isr[word].fetch_and(!mask, Ordering::AcqRel);
        }
    }

    fn read_bitmap_32(words: &[AtomicU64; 4], idx_32: u32) -> u64 {
        let word = (idx_32 >> 1) as usize;
        let shift = (idx_32 & 1) * 32;
        (words[word].load(Ordering::Acquire) >> shift) & 0xffff_ffff
    }

    pub fn try_rdmsr(&self, msr: u32) -> Option<u64> {
        match msr {
            MSR_IA32_APIC_BASE => Some(self.apic_base()),
            MSR_IA32_TSC_DEADLINE => Some(self.tsc_deadline.load(Ordering::Acquire)),
            X2APIC_ID => Some(self.vcpu_id as u64),
            X2APIC_VER => Some(0x0005_0014), // Integrated APIC + 6 LVT entries
            X2APIC_TPR => Some(self.tpr.load(Ordering::Acquire) as u64),
            X2APIC_PPR => Some(self.ppr() as u64),
            X2APIC_LDR => {
                let cluster = (self.vcpu_id >> 4) << 16;
                let logical = 1u32 << (self.vcpu_id & 0xf);
                Some((cluster | logical) as u64)
            }
            X2APIC_SVR => Some(self.svr.load(Ordering::Acquire) as u64),
            m if (X2APIC_ISR_BASE..X2APIC_ISR_BASE + 8).contains(&m) => {
                Some(Self::read_bitmap_32(&self.isr, m - X2APIC_ISR_BASE))
            }
            m if (X2APIC_TMR_BASE..X2APIC_TMR_BASE + 8).contains(&m) => Some(0),
            m if (X2APIC_IRR_BASE..X2APIC_IRR_BASE + 8).contains(&m) => {
                self.poll_timer();
                Some(Self::read_bitmap_32(&self.irr, m - X2APIC_IRR_BASE))
            }
            X2APIC_ESR => Some(self.esr.load(Ordering::Acquire) as u64),
            X2APIC_ICR => Some(0),
            X2APIC_LVT_TIMER => Some(self.lvt_timer.load(Ordering::Acquire) as u64),
            X2APIC_LVT_THERMAL => Some(self.lvt_thermal.load(Ordering::Acquire) as u64),
            X2APIC_LVT_PMI => Some(self.lvt_pmi.load(Ordering::Acquire) as u64),
            X2APIC_LVT_LINT0 => Some(self.lvt_lint0.load(Ordering::Acquire) as u64),
            X2APIC_LVT_LINT1 => Some(self.lvt_lint1.load(Ordering::Acquire) as u64),
            X2APIC_LVT_ERROR => Some(self.lvt_error.load(Ordering::Acquire) as u64),
            X2APIC_INIT_COUNT => Some(self.init_count.load(Ordering::Acquire) as u64),
            X2APIC_CUR_COUNT => Some(self.read_cur_count() as u64),
            X2APIC_DIV_CONF => Some(self.div_conf.load(Ordering::Acquire) as u64),
            m if (0x800..=0x83f).contains(&m) => Some(0),
            _ => None,
        }
    }

    pub fn try_wrmsr(&self, msr: u32, val: u64) -> Option<IpiAction> {
        match msr {
            MSR_IA32_APIC_BASE => {
                self.set_apic_base(val);
                Some(IpiAction::None)
            }
            MSR_IA32_TSC_DEADLINE => {
                self.tsc_deadline.store(val, Ordering::Release);
                self.poll_timer();
                Some(IpiAction::None)
            }
            X2APIC_TPR => {
                self.tpr.store((val as u32) & 0xff, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_EOI => {
                self.eoi();
                Some(IpiAction::None)
            }
            X2APIC_SVR => {
                self.svr.store((val as u32) & 0x1ff, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_ESR => {
                self.esr.store(0, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_ICR => {
                let dest = (val >> 32) as u32;
                let vector = (val & 0xff) as u8;
                let delivery_mode = ((val >> 8) & 0x7) as u8;
                let level_assert = ((val >> 14) & 1) != 0;
                let shorthand = ((val >> 18) & 0x3) as u8;
                let action = match delivery_mode {
                    0b000 => IpiAction::Fixed {
                        dest,
                        shorthand,
                        vector,
                    },
                    0b101 if level_assert => IpiAction::Init { dest, shorthand },
                    0b110 => IpiAction::Sipi {
                        dest,
                        shorthand,
                        start_page: vector,
                    },
                    _ => IpiAction::None,
                };
                Some(action)
            }
            X2APIC_LVT_TIMER => {
                let new_lvt = val as u32;
                let old_mode = self.lvt_timer.swap(new_lvt, Ordering::AcqRel) & LVT_TIMER_MODE_MASK;
                let new_mode = new_lvt & LVT_TIMER_MODE_MASK;
                if new_mode != old_mode {
                    self.tsc_deadline.store(0, Ordering::Release);
                    if new_mode == LVT_TIMER_MODE_TSC_DEADLINE {
                        self.count_deadline_tsc.store(0, Ordering::Release);
                        self.count_period_tsc.store(0, Ordering::Release);
                    }
                }
                Some(IpiAction::None)
            }
            X2APIC_LVT_THERMAL => {
                self.lvt_thermal.store(val as u32, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_LVT_PMI => {
                self.lvt_pmi.store(val as u32, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_LVT_LINT0 => {
                self.lvt_lint0.store(val as u32, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_LVT_LINT1 => {
                self.lvt_lint1.store(val as u32, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_LVT_ERROR => {
                self.lvt_error.store(val as u32, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_INIT_COUNT => {
                self.arm_countdown(val as u32);
                Some(IpiAction::None)
            }
            X2APIC_DIV_CONF => {
                self.div_conf.store(val as u32, Ordering::Release);
                Some(IpiAction::None)
            }
            X2APIC_SELF_IPI => {
                self.set_irr((val & 0xff) as u8);
                Some(IpiAction::None)
            }
            m if (0x800..=0x83f).contains(&m) => Some(IpiAction::None),
            _ => None,
        }
    }

    /// Returns `true` when `gpa` falls within this vCPU's enabled xAPIC MMIO page.
    #[inline]
    pub fn in_xapic_mmio_range(&self, gpa: u64) -> bool {
        let base = self.apic_base();
        (base & APIC_BASE_EN) != 0
            && (base & APIC_BASE_EXTD) == 0
            && (gpa & !0xfff) == (base & !0xfff)
    }

    pub fn xapic_mmio_read(&self, offset: u64) -> u32 {
        match offset & 0xff0 {
            0x020 => self.vcpu_id << 24,
            0x0d0 => self.xapic_ldr.load(Ordering::Acquire),
            0x0e0 => self.dfr.load(Ordering::Acquire),
            0x300 => 0,
            0x310 => self.icr_hi.load(Ordering::Acquire),
            off => {
                let msr = 0x800 + ((off >> 4) as u32 & 0xff);
                self.try_rdmsr(msr).unwrap_or(0) as u32
            }
        }
    }

    pub fn xapic_mmio_write(&self, offset: u64, val: u32) -> IpiAction {
        match offset & 0xff0 {
            0x020 => IpiAction::None,
            0x0d0 => {
                self.xapic_ldr.store(val & 0xff00_0000, Ordering::Release);
                IpiAction::None
            }
            0x0e0 => {
                self.dfr.store(val | 0x0fff_ffff, Ordering::Release);
                IpiAction::None
            }
            0x300 => {
                let dest = (self.icr_hi.load(Ordering::Acquire) >> 24) as u64;
                let combined = (dest << 32) | (val as u64);
                self.try_wrmsr(X2APIC_ICR, combined)
                    .unwrap_or(IpiAction::None)
            }
            0x310 => {
                self.icr_hi.store(val, Ordering::Release);
                IpiAction::None
            }
            off => {
                let msr = 0x800 + ((off >> 4) as u32 & 0xff);
                self.try_wrmsr(msr, val as u64).unwrap_or(IpiAction::None)
            }
        }
    }

    /// Emulates a guest xAPIC MMIO instruction faulting at `gpa` (`0xfee0_0xxx`) directly in Ring 0.
    pub fn emulate_xapic_mmio(
        &self,
        gpa: u64,
        stage2: &Stage2Mmu,
        comm: &mut VcpuCommPage,
    ) -> HvResult<IpiAction> {
        let mode64 = (comm.efer & (1 << 10)) != 0 && ((comm.cs.access >> 13) & 1) != 0;
        let hint_len = comm.exit.insn_len as usize;
        let mut buf = [0u8; 15];
        let avail = if hint_len > 0 {
            let n = hint_len.min(15);
            buf[..n].copy_from_slice(&comm.exit.insn_bytes[..n]);
            n
        } else {
            let rip_gva = if mode64 {
                comm.rip
            } else {
                comm.cs.base.wrapping_add(comm.rip) & 0xffff_ffff
            };
            fetch_guest_insn_bytes(stage2, comm, rip_gva, &mut buf)?
        };

        let mut pos = 0usize;
        let mut op_66 = false;
        let mut addr_67 = false;
        while pos < avail {
            match buf[pos] {
                0x66 => op_66 = true,
                0x67 => addr_67 = true,
                0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 => {}
                _ => break,
            }
            pos += 1;
        }

        let mut rex: u8 = 0;
        let mut rex_present = false;
        if mode64 && pos < avail && (0x40..=0x4f).contains(&buf[pos]) {
            rex = buf[pos];
            rex_present = true;
            pos += 1;
        }
        let rex_w = (rex & 0x8) != 0;
        let rex_r = (rex & 0x4) != 0;

        if pos >= avail {
            return Err(HvError::HardwareFault);
        }
        let op0 = buf[pos];
        pos += 1;

        let op_size: u8 = if rex_w {
            8
        } else if op_66 {
            2
        } else {
            4
        };
        let apic_off = gpa & 0xfff;
        let mut ipi = IpiAction::None;

        match op0 {
            0xa1 => {
                let moffs_len = if mode64 {
                    if addr_67 { 4 } else { 8 }
                } else if addr_67 {
                    2
                } else {
                    4
                };
                pos += moffs_len;
                let v = self.xapic_mmio_read(apic_off) as u64;
                write_comm_gpr(comm, 0, op_size, rex_present, v);
            }
            0xa3 => {
                let moffs_len = if mode64 {
                    if addr_67 { 4 } else { 8 }
                } else if addr_67 {
                    2
                } else {
                    4
                };
                pos += moffs_len;
                let v = read_comm_gpr(comm, 0, op_size, rex_present) as u32;
                ipi = self.xapic_mmio_write(apic_off, v);
            }
            0x88 | 0x89 | 0x8a | 0x8b | 0x86 | 0x87 | 0xc6 | 0xc7 | 0x0f => {
                let (is_ext, opcode) = if op0 == 0x0f {
                    if pos >= avail {
                        return Err(HvError::HardwareFault);
                    }
                    let b1 = buf[pos];
                    pos += 1;
                    (true, b1)
                } else {
                    (false, op0)
                };

                if pos >= avail {
                    return Err(HvError::HardwareFault);
                }
                let modrm = buf[pos];
                pos += 1;
                let mod_bits = modrm >> 6;
                let reg = ((modrm >> 3) & 0x7) | ((rex_r as u8) << 3);
                let rm_low = modrm & 0x7;

                let has_sib = mod_bits != 3 && rm_low == 4;
                let base_low = if has_sib {
                    if pos >= avail {
                        return Err(HvError::HardwareFault);
                    }
                    let sib = buf[pos];
                    pos += 1;
                    sib & 0x7
                } else {
                    rm_low
                };
                let disp_len = match mod_bits {
                    0 if base_low == 5 => 4,
                    1 => 1,
                    2 => 4,
                    _ => 0,
                };
                pos += disp_len;

                if is_ext {
                    match opcode {
                        0xb6 => {
                            let v = (self.xapic_mmio_read(apic_off) & 0xff) as u64;
                            write_comm_gpr(comm, reg, op_size, rex_present, v);
                        }
                        0xb7 => {
                            let v = (self.xapic_mmio_read(apic_off) & 0xffff) as u64;
                            write_comm_gpr(comm, reg, op_size, rex_present, v);
                        }
                        _ => {
                            log::error!(
                                "xAPIC unhandled 0F {opcode:#04x} at rip={:#x} gpa={gpa:#x}",
                                comm.rip
                            );
                            return Err(HvError::Unsupported);
                        }
                    }
                } else {
                    match opcode {
                        0x88 => {
                            let v = read_comm_gpr(comm, reg, 1, rex_present) as u32;
                            ipi = self.xapic_mmio_write(apic_off, v);
                        }
                        0x89 => {
                            let v = read_comm_gpr(comm, reg, op_size, rex_present) as u32;
                            ipi = self.xapic_mmio_write(apic_off, v);
                        }
                        0x8a => {
                            let v = (self.xapic_mmio_read(apic_off) & 0xff) as u64;
                            write_comm_gpr(comm, reg, 1, rex_present, v);
                        }
                        0x8b => {
                            let v = self.xapic_mmio_read(apic_off) as u64;
                            write_comm_gpr(comm, reg, op_size, rex_present, v);
                        }
                        0x86 => {
                            let old = (self.xapic_mmio_read(apic_off) & 0xff) as u64;
                            let new_v = read_comm_gpr(comm, reg, 1, rex_present) as u32;
                            ipi = self.xapic_mmio_write(apic_off, new_v);
                            write_comm_gpr(comm, reg, 1, rex_present, old);
                        }
                        0x87 => {
                            let old = self.xapic_mmio_read(apic_off) as u64;
                            let new_v = read_comm_gpr(comm, reg, op_size, rex_present) as u32;
                            ipi = self.xapic_mmio_write(apic_off, new_v);
                            write_comm_gpr(comm, reg, op_size, rex_present, old);
                        }
                        0xc6 if (reg & 0x7) == 0 => {
                            if pos >= avail {
                                return Err(HvError::HardwareFault);
                            }
                            let imm = buf[pos] as u32;
                            pos += 1;
                            ipi = self.xapic_mmio_write(apic_off, imm);
                        }
                        0xc7 if (reg & 0x7) == 0 => {
                            let imm_len = if op_size == 2 { 2 } else { 4 };
                            if pos + imm_len > avail {
                                return Err(HvError::HardwareFault);
                            }
                            let imm = if imm_len == 2 {
                                u16::from_le_bytes([buf[pos], buf[pos + 1]]) as u32
                            } else {
                                u32::from_le_bytes([
                                    buf[pos],
                                    buf[pos + 1],
                                    buf[pos + 2],
                                    buf[pos + 3],
                                ])
                            };
                            pos += imm_len;
                            ipi = self.xapic_mmio_write(apic_off, imm);
                        }
                        _ => {
                            log::error!(
                                "xAPIC unhandled op {opcode:#04x} at rip={:#x} gpa={gpa:#x}",
                                comm.rip
                            );
                            return Err(HvError::Unsupported);
                        }
                    }
                }
            }
            _ => {
                log::error!(
                    "xAPIC unhandled op {op0:#04x} at rip={:#x} gpa={gpa:#x}",
                    comm.rip
                );
                return Err(HvError::Unsupported);
            }
        }

        let step = if hint_len > 0 { hint_len } else { pos };
        comm.rip = comm.rip.wrapping_add(step as u64);
        comm.dirty_regs |= SYNC_REG_RIP_RFLAGS;
        comm.exit = RawVmExit::default();
        Ok(ipi)
    }
}

fn read_comm_gpr(comm: &VcpuCommPage, reg: u8, size: u8, rex_present: bool) -> u64 {
    match size {
        1 => {
            if !rex_present && (4..8).contains(&reg) {
                (comm.gprs[(reg - 4) as usize] >> 8) & 0xff
            } else {
                comm.gprs[reg as usize] & 0xff
            }
        }
        2 => comm.gprs[reg as usize] & 0xffff,
        4 => comm.gprs[reg as usize] & 0xffff_ffff,
        _ => comm.gprs[reg as usize],
    }
}

fn write_comm_gpr(comm: &mut VcpuCommPage, reg: u8, size: u8, rex_present: bool, val: u64) {
    match size {
        1 => {
            if !rex_present && (4..8).contains(&reg) {
                let dst = &mut comm.gprs[(reg - 4) as usize];
                *dst = (*dst & !0xff00) | ((val & 0xff) << 8);
            } else {
                let dst = &mut comm.gprs[reg as usize];
                *dst = (*dst & !0xff) | (val & 0xff);
            }
        }
        2 => {
            let dst = &mut comm.gprs[reg as usize];
            *dst = (*dst & !0xffff) | (val & 0xffff);
        }
        4 => {
            comm.gprs[reg as usize] = val & 0xffff_ffff;
        }
        _ => {
            comm.gprs[reg as usize] = val;
        }
    }
    comm.dirty_regs |= SYNC_REG_GPRS;
}

fn translate_guest_gva(stage2: &Stage2Mmu, comm: &VcpuCommPage, gva: u64) -> HvResult<u64> {
    const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
    if (comm.cr0 & (1 << 31)) == 0 {
        return Ok(gva & 0xffff_ffff);
    }
    let read_u64 = |gpa: u64| -> HvResult<u64> {
        let hpa = stage2.gpa_to_hpa(gpa, false).ok_or(HvError::HardwareFault)?;
        Ok(unsafe { *((hpa + PAGING_DIRECT_MAP_OFFSET) as *const u64) })
    };
    if (comm.efer & (1 << 10)) != 0 {
        let mut table = comm.cr3 & PTE_ADDR_MASK;
        if (comm.cr4 & (1 << 12)) != 0 {
            let e = read_u64(table + ((gva >> 48) & 0x1ff) * 8)?;
            if (e & 1) == 0 {
                return Err(HvError::HardwareFault);
            }
            table = e & PTE_ADDR_MASK;
        }
        let pml4e = read_u64(table + ((gva >> 39) & 0x1ff) * 8)?;
        if (pml4e & 1) == 0 {
            return Err(HvError::HardwareFault);
        }
        let pdpte = read_u64((pml4e & PTE_ADDR_MASK) + ((gva >> 30) & 0x1ff) * 8)?;
        if (pdpte & 1) == 0 {
            return Err(HvError::HardwareFault);
        }
        if (pdpte & 0x80) != 0 {
            return Ok((pdpte & 0x000f_ffff_c000_0000) | (gva & 0x3fff_ffff));
        }
        let pde = read_u64((pdpte & PTE_ADDR_MASK) + ((gva >> 21) & 0x1ff) * 8)?;
        if (pde & 1) == 0 {
            return Err(HvError::HardwareFault);
        }
        if (pde & 0x80) != 0 {
            return Ok((pde & 0x000f_ffff_ffe0_0000) | (gva & 0x001f_ffff));
        }
        let pte = read_u64((pde & PTE_ADDR_MASK) + ((gva >> 12) & 0x1ff) * 8)?;
        if (pte & 1) == 0 {
            return Err(HvError::HardwareFault);
        }
        return Ok((pte & PTE_ADDR_MASK) | (gva & 0xfff));
    }
    Err(HvError::Unsupported)
}

fn fetch_guest_insn_bytes(
    stage2: &Stage2Mmu,
    comm: &VcpuCommPage,
    rip_gva: u64,
    out: &mut [u8; 15],
) -> HvResult<usize> {
    let first = (0x1000 - ((rip_gva & 0xfff) as usize)).min(15);
    let gpa0 = translate_guest_gva(stage2, comm, rip_gva)?;
    let hpa0 = stage2.gpa_to_hpa(gpa0, false).ok_or(HvError::HardwareFault)?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            (hpa0 + PAGING_DIRECT_MAP_OFFSET) as *const u8,
            out.as_mut_ptr(),
            first,
        );
    }
    if first < 15 {
        if let Ok(gpa1) = translate_guest_gva(stage2, comm, rip_gva.wrapping_add(first as u64)) {
            if let Some(hpa1) = stage2.gpa_to_hpa(gpa1, false) {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (hpa1 + PAGING_DIRECT_MAP_OFFSET) as *const u8,
                        out[first..].as_mut_ptr(),
                        15 - first,
                    );
                }
                return Ok(15);
            }
        }
    }
    Ok(first)
}
