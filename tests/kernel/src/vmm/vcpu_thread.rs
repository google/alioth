// Kernel-only vCPU `process::Thread` execution loop (`VcpuRunner`).

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vmm_core::host::abi::{
    BridgeShm, CoreToIoEntry, RawVmExit, VcpuCommPage, CORE_MSG_SHUTDOWN, CORE_MSG_VIRTIO_NOTIFY,
};
use vmm_core::host::{HvError, MpState, VmAction, VmExit};

use crate::uspace::process::{Thread, VcpuThreadHandler};
use crate::util::SpinLock;

use super::arch::{xsetbv_raw, FastExit};
use super::host_impl::{MotorCoreBridge, MotorHvCore, VcpuSlot};
use super::wasm_runtime::{MotorWasmRuntime, VcpuWasmWorker};

const HOST_XCR0: u64 = 0x7;

/// Field drop order is load-bearing: `vcpu_wasm` (`Store` + `Instance`) drops BEFORE `wasm`.
pub struct VcpuRunner {
    vcpu_id: u32,
    slot: Arc<VcpuSlot>,
    hv: Arc<MotorHvCore>,
    bridge: Arc<MotorCoreBridge>,
    vcpu_wasm: SpinLock<VcpuWasmWorker<MotorHvCore, MotorCoreBridge>>,
    wasm: Arc<MotorWasmRuntime<MotorHvCore, MotorCoreBridge>>,
}

impl VcpuRunner {
    pub fn new(
        vcpu_id: u32,
        slot: Arc<VcpuSlot>,
        hv: Arc<MotorHvCore>,
        bridge: Arc<MotorCoreBridge>,
        vcpu_wasm: VcpuWasmWorker<MotorHvCore, MotorCoreBridge>,
        wasm: Arc<MotorWasmRuntime<MotorHvCore, MotorCoreBridge>>,
    ) -> Self {
        Self {
            vcpu_id,
            slot,
            hv,
            bridge,
            vcpu_wasm: SpinLock::new(vcpu_wasm),
            wasm,
        }
    }

    #[inline]
    fn on_schedule_in(&self, thread: &Thread) {
        let cpu = crate::arch::current_cpu();
        thread.set_last_cpu(cpu);
        self.slot.lapic.set_on_cpu(Some(cpu as u32));
        // Always execute XRSTOR with full host XCR0 (0x7) before narrowing to guest XCR0.
        thread.tcb_xrstor();
        let gx = self.slot.arch.lock(line!()).guest_xcr0();
        if gx != HOST_XCR0 {
            unsafe { xsetbv_raw(0, gx) };
        }
    }

    #[inline]
    fn on_schedule_out(&self, thread: &Thread) {
        let gx = self.slot.arch.lock(line!()).guest_xcr0();
        if gx != HOST_XCR0 {
            unsafe { xsetbv_raw(0, HOST_XCR0) };
        }
        thread.tcb_xsave();
        self.slot.lapic.set_on_cpu(None);
    }

    fn terminate_vm_and_exit(&self, thread: &Thread) -> ! {
        if !self.hv.shutting_down.load(Ordering::Acquire) {
            let shm = self.bridge.shm_ptr as usize as *mut BridgeShm;
            let entry = CoreToIoEntry {
                msg_type: CORE_MSG_SHUTDOWN,
                ..Default::default()
            };
            unsafe {
                (*shm).shutdown_requested.store(1, Ordering::Release);
                let _ = BridgeShm::push_core_to_io(shm, entry);
            }
            self.hv.signal_shutdown();
        }
        self.on_schedule_out(thread);
        thread.finish()
    }

    fn call_wasm_exit(&self, thread: &Thread) {
        let mut worker = self.vcpu_wasm.lock(line!());
        let VcpuWasmWorker {
            store,
            on_vcpu_exit,
            ..
        } = &mut *worker;
        let res = on_vcpu_exit.call(store, self.vcpu_id);
        drop(worker);

        match res {
            Ok(rc) if rc == VmAction::Continue as i32 => {}
            Ok(rc) if rc == VmAction::Shutdown as i32 || rc == VmAction::Reboot as i32 => {
                self.terminate_vm_and_exit(thread);
            }
            Ok(rc) => {
                log::error!(
                    "vcpu {} vmm_on_vcpu_exit error: {:?}",
                    self.vcpu_id,
                    HvError::from_code(rc)
                );
                self.terminate_vm_and_exit(thread);
            }
            Err(trap) => {
                log::error!("vcpu {} vmm_on_vcpu_exit trapped: {trap}", self.vcpu_id);
                self.terminate_vm_and_exit(thread);
            }
        }
    }
}

impl VcpuThreadHandler for VcpuRunner {
    fn run(&self, thread: &Thread) -> ! {
        let comm_offset = self.vcpu_wasm.lock(line!()).comm_offset;
        self.on_schedule_in(thread);

        loop {
            if self.hv.shutting_down.load(Ordering::Acquire) {
                self.on_schedule_out(thread);
                thread.finish();
            }

            thread.check_vcpu_preempt_or_kill(
                || self.on_schedule_out(thread),
                || self.on_schedule_in(thread),
            );

            if let Some(start_page) = self.slot.lapic.take_sipi() {
                let npt_root = self.hv.stage2.root_phys();
                self.slot
                    .arch
                    .lock(line!())
                    .apply_sipi(start_page, npt_root);
            }

            match self.slot.lapic.mp_state() {
                MpState::Uninitialized | MpState::InitReceived => {
                    thread.wait_for_vcpu_kick(
                        &self.slot.lapic.kick_obj,
                        None,
                        || {
                            !self.hv.shutting_down.load(Ordering::Acquire)
                                && matches!(
                                    self.slot.lapic.mp_state(),
                                    MpState::Uninitialized | MpState::InitReceived
                                )
                        },
                        || self.on_schedule_out(thread),
                        || self.on_schedule_in(thread),
                    );
                    continue;
                }
                MpState::SipiReceived => continue,
                MpState::Halted => {
                    if self.slot.lapic.has_pending_irr() {
                        self.slot.lapic.set_mp_state(MpState::Runnable);
                    } else {
                        let deadline = self.slot.lapic.active_deadline_instant();
                        thread.wait_for_vcpu_kick(
                            &self.slot.lapic.kick_obj,
                            deadline,
                            || {
                                !self.hv.shutting_down.load(Ordering::Acquire)
                                    && self.slot.lapic.mp_state() == MpState::Halted
                                    && !self.slot.lapic.has_pending_irr()
                            },
                            || self.on_schedule_out(thread),
                            || self.on_schedule_in(thread),
                        );
                        if self.slot.lapic.has_pending_irr() {
                            self.slot.lapic.set_mp_state(MpState::Runnable);
                        }
                        continue;
                    }
                }
                MpState::Runnable => {}
            }

            // Safety: `comm_page[vcpu_id]` is 64-byte-aligned inside `SharedMemory` and
            // exclusively accessed by this vCPU thread while Wasm is not executing on `vcpu_id`.
            let comm = unsafe {
                &mut *(self.wasm.shared_memory.data().as_ptr().add(comm_offset)
                    as *mut VcpuCommPage)
            };

            let fast_exit = {
                let mut arch = self.slot.arch.lock(line!());
                arch.enter_guest(thread, &self.slot.lapic, &self.hv.stage2, comm)
            };

            let fast_exit = match fast_exit {
                Ok(ex) => ex,
                Err(err) => {
                    log::error!("vcpu {} enter_guest failed: {err:?}", self.vcpu_id);
                    self.terminate_vm_and_exit(thread);
                }
            };

            match fast_exit {
                FastExit::HostIntr | FastExit::Cpuid | FastExit::EmulateHandled => {}
                FastExit::Hlt => {
                    if !self.slot.lapic.has_pending_irr() {
                        self.slot.lapic.set_mp_state(MpState::Halted);
                    }
                }
                FastExit::Shutdown => {
                    self.terminate_vm_and_exit(thread);
                }
                FastExit::MsrRead { msr, insn_len } => {
                    if let Some(val) = self.slot.lapic.try_rdmsr(msr) {
                        self.slot.arch.lock(line!()).complete_rdmsr(val, insn_len);
                    } else if let Some(val) = self.hv.pvclock.try_rdmsr(self.vcpu_id as usize, msr)
                    {
                        self.slot.arch.lock(line!()).complete_rdmsr(val, insn_len);
                    } else {
                        self.slot.arch.lock(line!()).sync_to_comm(comm);
                        let mut raw = RawVmExit::from_exit(VmExit::MsrRead { msr });
                        raw.insn_len = insn_len;
                        comm.exit = raw;
                        self.call_wasm_exit(thread);
                    }
                }
                FastExit::MsrWrite { msr, val, insn_len } => {
                    if let Some(ipi_action) = self.slot.lapic.try_wrmsr(msr, val) {
                        self.slot.arch.lock(line!()).advance_rip(insn_len);
                        self.hv.dispatch_ipi(self.vcpu_id, ipi_action);
                    } else if self.hv.pvclock.try_wrmsr(
                        self.vcpu_id as usize,
                        msr,
                        val,
                        &self.hv.stage2,
                    ) {
                        self.slot.arch.lock(line!()).advance_rip(insn_len);
                    } else {
                        self.slot.arch.lock(line!()).sync_to_comm(comm);
                        let mut raw = RawVmExit::from_exit(VmExit::MsrWrite { msr, val });
                        raw.insn_len = insn_len;
                        comm.exit = raw;
                        self.call_wasm_exit(thread);
                    }
                }
                FastExit::Pio {
                    port,
                    write,
                    size,
                    insn_len,
                } => {
                    let matched_doorbell =
                        write.and_then(|val| self.hv.doorbells.match_pio(port, size, val as u64));
                    if let Some((dev_id, queue_idx)) = matched_doorbell {
                        comm.exit = RawVmExit::default();
                        self.slot.arch.lock(line!()).advance_rip(insn_len);
                        let notify = CoreToIoEntry {
                            msg_type: CORE_MSG_VIRTIO_NOTIFY,
                            aux_u16: queue_idx,
                            _pad: 0,
                            dev: dev_id as u64,
                            features: 0,
                            data: [0; 40],
                        };
                        let shm = self.bridge.shm_ptr as usize as *mut BridgeShm;
                        if unsafe { BridgeShm::push_core_to_io(shm, notify) } {
                            self.hv.wake_vm_obj();
                        }
                    } else {
                        self.call_wasm_exit(thread);
                    }
                }
                FastExit::MmioFault { .. } => {
                    self.call_wasm_exit(thread);
                }
            }
        }
    }
}
