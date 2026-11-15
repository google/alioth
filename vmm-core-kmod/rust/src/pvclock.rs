// SPDX-License-Identifier: GPL-2.0
// Ring-0 KVM pvclock MSR emulation backed by Linux `ktime_get_ns` & `tsc_khz`.

use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use crate::kapi::{airlock_kapi_phys_to_virt, pvclock_snapshot};
use crate::stage2::Stage2Mmu;

pub const MSR_KVM_WALL_CLOCK_OLD: u32 = 0x11;
pub const MSR_KVM_SYSTEM_TIME_OLD: u32 = 0x12;
pub const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
pub const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;

const PVCLOCK_TSC_STABLE_BIT: u8 = 1 << 0;
const NSEC_PER_SEC: u64 = 1_000_000_000;

#[repr(C)]
struct RawWallClock {
    version: AtomicU32,
    sec: u32,
    nsec: u32,
}

#[repr(C)]
struct RawVcpuTimeInfo {
    version: AtomicU32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad: [u8; 2],
}

pub struct PvClockState {
    wall_clock_msr: AtomicU64,
    system_time_msr: [AtomicU64; 64],
}

impl Default for PvClockState {
    fn default() -> Self {
        Self::new()
    }
}

impl PvClockState {
    pub const fn new() -> Self {
        Self {
            wall_clock_msr: AtomicU64::new(0),
            system_time_msr: [const { AtomicU64::new(0) }; 64],
        }
    }

    pub fn try_rdmsr(&self, vcpu_id: usize, msr: u32) -> Option<u64> {
        match msr {
            MSR_KVM_WALL_CLOCK_OLD | MSR_KVM_WALL_CLOCK_NEW => {
                Some(self.wall_clock_msr.load(Ordering::Acquire))
            }
            MSR_KVM_SYSTEM_TIME_OLD | MSR_KVM_SYSTEM_TIME_NEW => self
                .system_time_msr
                .get(vcpu_id)
                .map(|a| a.load(Ordering::Acquire)),
            _ => None,
        }
    }

    pub fn try_wrmsr(&self, vcpu_id: usize, msr: u32, val: u64, stage2: &Stage2Mmu) -> bool {
        match msr {
            MSR_KVM_WALL_CLOCK_OLD | MSR_KVM_WALL_CLOCK_NEW => {
                self.wall_clock_msr.store(val, Ordering::Release);
                let gpa = val & !0x3;
                if (gpa & 0xfff) <= (4096 - 12) {
                    if let Some(hpa) = stage2.gpa_to_hpa(gpa, true) {
                        let (base_nsec, _, _, _, _) = pvclock_snapshot();
                        let base_va = unsafe { airlock_kapi_phys_to_virt(hpa & !0xfff) };
                        let wc =
                            unsafe { &mut *(base_va.add((hpa & 0xfff) as usize) as *mut RawWallClock) };
                        let prev = wc.version.load(Ordering::Relaxed) & !1;
                        wc.version.store(prev.wrapping_add(1), Ordering::Release);
                        fence(Ordering::Release);
                        wc.sec = (base_nsec / NSEC_PER_SEC) as u32;
                        wc.nsec = (base_nsec % NSEC_PER_SEC) as u32;
                        fence(Ordering::Release);
                        wc.version.store(prev.wrapping_add(2), Ordering::Release);
                    }
                }
                true
            }
            MSR_KVM_SYSTEM_TIME_OLD | MSR_KVM_SYSTEM_TIME_NEW => {
                if let Some(slot) = self.system_time_msr.get(vcpu_id) {
                    slot.store(val, Ordering::Release);
                }
                if (val & 1) != 0 {
                    let gpa = val & !1;
                    if (gpa & 0xfff) <= (4096 - 32) {
                        if let Some(hpa) = stage2.gpa_to_hpa(gpa, true) {
                            let (_, system_time, tsc_ts, tsc_mul, tsc_shift) = pvclock_snapshot();
                            let base_va = unsafe { airlock_kapi_phys_to_virt(hpa & !0xfff) };
                            let ti = unsafe {
                                &mut *(base_va.add((hpa & 0xfff) as usize) as *mut RawVcpuTimeInfo)
                            };
                            let prev = ti.version.load(Ordering::Relaxed) & !1;
                            ti.version.store(prev.wrapping_add(1), Ordering::Release);
                            fence(Ordering::Release);
                            ti.tsc_timestamp = tsc_ts;
                            ti.system_time = system_time;
                            ti.tsc_to_system_mul = tsc_mul;
                            ti.tsc_shift = tsc_shift;
                            ti.flags = PVCLOCK_TSC_STABLE_BIT;
                            fence(Ordering::Release);
                            ti.version.store(prev.wrapping_add(2), Ordering::Release);
                        }
                    }
                }
                true
            }
            _ => false,
        }
    }
}
