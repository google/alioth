// Thin Ring-0 per-vCPU x2APIC + TSC-deadline timer + INIT/SIPI state machine.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use vmm_core::host::MpState;

use crate::arch::time::{rdtsc_now, Instant};
use crate::uspace::SysObject;

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
const LVT_TIMER_MODE_TSC_DEADLINE: u32 = 0b10 << 17;
const SVR_APIC_ENABLED: u32 = 1 << 8;

pub const DEFAULT_APIC_BASE: u64 = 0xfee0_0000;
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_EN: u64 = 1 << 11;

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
    lvt_timer: AtomicU32,
    lvt_lint0: AtomicU32,
    lvt_lint1: AtomicU32,
    lvt_error: AtomicU32,
    lvt_pmi: AtomicU32,
    lvt_thermal: AtomicU32,
    init_count: AtomicU32,
    div_conf: AtomicU32,
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
            lvt_timer: AtomicU32::new(LVT_MASKED),
            lvt_lint0: AtomicU32::new(LVT_MASKED),
            lvt_lint1: AtomicU32::new(LVT_MASKED),
            lvt_error: AtomicU32::new(LVT_MASKED),
            lvt_pmi: AtomicU32::new(LVT_MASKED),
            lvt_thermal: AtomicU32::new(LVT_MASKED),
            init_count: AtomicU32::new(0),
            div_conf: AtomicU32::new(0),
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

    /// Checks whether the armed TSC-deadline timer has expired, latching its vector into `IRR`.
    pub fn poll_timer(&self) {
        let dl = self.tsc_deadline.load(Ordering::Acquire);
        if dl == 0 {
            return;
        }
        if rdtsc_now() >= dl
            && self
                .tsc_deadline
                .compare_exchange(dl, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            let lvt = self.lvt_timer.load(Ordering::Acquire);
            if (lvt & LVT_MASKED) == 0 && (lvt & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_TSC_DEADLINE
            {
                let vec = (lvt & 0xff) as u8;
                if vec >= 16 {
                    let word = (vec >> 6) as usize;
                    self.irr[word].fetch_or(1u64 << (vec & 63), Ordering::AcqRel);
                }
            }
        }
    }

    /// Returns the active future `TSC_DEADLINE` as a host `Instant` for `HLT` sleep.
    pub fn active_deadline_instant(&self) -> Option<Instant> {
        self.poll_timer();
        let dl = self.tsc_deadline.load(Ordering::Acquire);
        if dl == 0 {
            return None;
        }
        let lvt = self.lvt_timer.load(Ordering::Acquire);
        if (lvt & LVT_MASKED) != 0 || (lvt & LVT_TIMER_MODE_MASK) != LVT_TIMER_MODE_TSC_DEADLINE {
            return None;
        }
        Some(Instant::from_u64(dl))
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
            X2APIC_CUR_COUNT => Some(0),
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
                if (new_lvt & LVT_TIMER_MODE_MASK) != old_mode {
                    self.tsc_deadline.store(0, Ordering::Release);
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
                self.init_count.store(val as u32, Ordering::Release);
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

    /// Services legacy xAPIC MMIO (`0xfee0_0000..0xfee0_1000`) accesses (such as
    /// Motor OS's `lapic_init()` writes to `SVR`/`TPR`/`EOI`/`LVT_*`).
    pub fn mmio_access(&self, offset: u64, write_val: Option<u64>) -> u64 {
        let msr = 0x800 + ((offset >> 4) as u32 & 0xff);
        if let Some(val) = write_val {
            let _ = self.try_wrmsr(msr, val & 0xffff_ffff);
            0
        } else {
            self.try_rdmsr(msr).unwrap_or(0) & 0xffff_ffff
        }
    }
}
