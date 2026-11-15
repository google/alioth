// SPDX-License-Identifier: GPL-2.0
// Per-vCPU `airlock-vcpu` kthread run loop, `airlock-rx` control worker kthread,
// and Ring-3 -> Ring-0 `i2c_eventfd` wakeup router.

use alloc::sync::Arc;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

use vmm_core::host::abi::{
    spin_lock, spin_unlock, BridgeShm, CoreToIoEntry, RawVmExit, ShmMsiEntry, VcpuCommPage,
    CORE_MSG_SHUTDOWN, CORE_MSG_VIRTIO_NOTIFY, IO_MSG_REQUEST_SHUTDOWN, IO_MSG_SERIAL_RX,
    IO_MSG_VIRTIO_IRQ, IRQ_KIND_CONFIG, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS,
};
use vmm_core::host::{HvError, MpState, VmAction, VmExit};

use crate::arch::FastExit;
use crate::host_impl::{LinuxCoreBridge, LinuxHvCore, VcpuSlot};
use crate::kapi::{
    airlock_kapi_cond_resched, airlock_kapi_kthread_should_stop, SpinLock, WaitQueue,
    WasmCallGuard,
};
use crate::kerr;
use crate::wasm_runtime::{LinuxWasmRuntime, RxWasmWorker, VcpuWasmWorker};

/// Field drop order is load-bearing: `vcpu_wasm` (`Store` + `Instance`) drops BEFORE `wasm`.
pub struct VcpuRunner {
    vcpu_id: u32,
    slot: Arc<VcpuSlot>,
    hv: Arc<LinuxHvCore>,
    bridge: Arc<LinuxCoreBridge>,
    vcpu_wasm: SpinLock<VcpuWasmWorker<LinuxHvCore, LinuxCoreBridge>>,
    wasm: Arc<LinuxWasmRuntime<LinuxHvCore, LinuxCoreBridge>>,
}

impl VcpuRunner {
    pub fn new(
        vcpu_id: u32,
        slot: Arc<VcpuSlot>,
        hv: Arc<LinuxHvCore>,
        bridge: Arc<LinuxCoreBridge>,
        vcpu_wasm: VcpuWasmWorker<LinuxHvCore, LinuxCoreBridge>,
        wasm: Arc<LinuxWasmRuntime<LinuxHvCore, LinuxCoreBridge>>,
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

    fn terminate_vm(&self) {
        if !self.hv.shutting_down.load(Ordering::Acquire) {
            let shm = self.bridge.shm_ptr();
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
    }

    /// Returns `false` when the VM has shut down / rebooted / errored and this vCPU loop should exit.
    fn call_wasm_exit(&self, comm_offset: usize) -> bool {
        let res = {
            let mut worker = self.vcpu_wasm.lock();
            let VcpuWasmWorker {
                store,
                on_vcpu_exit,
                ..
            } = &mut *worker;
            let _ibt = WasmCallGuard::enter();
            on_vcpu_exit.call(store, self.vcpu_id)
        };

        match res {
            Ok(rc) if rc == VmAction::Continue as i32 => true,
            Ok(rc) if rc == VmAction::Shutdown as i32 || rc == VmAction::Reboot as i32 => {
                self.terminate_vm();
                false
            }
            Ok(rc) => {
                let comm = unsafe {
                    &*(self.wasm.shared_memory.data().as_ptr().add(comm_offset)
                        as *const VcpuCommPage)
                };
                let resolved_hpa = match comm.exit.to_exit() {
                    Ok(VmExit::MmioFault { gpa, .. }) => self.hv.stage2.gpa_to_hpa(gpa, false),
                    _ => None,
                };
                kerr!(
                    "vcpu {} vmm_on_vcpu_exit error: {:?} (exit={:?} hpa={resolved_hpa:#x?} rip={:#x} cr0={:#x} cr3={:#x} efer={:#x} insn_len={})",
                    self.vcpu_id,
                    HvError::from_code(rc),
                    comm.exit.to_exit(),
                    comm.rip,
                    comm.cr0,
                    comm.cr3,
                    comm.efer,
                    comm.exit.insn_len,
                );
                self.terminate_vm();
                false
            }
            Err(trap) => {
                kerr!("vcpu {} vmm_on_vcpu_exit trapped: {trap}", self.vcpu_id);
                self.terminate_vm();
                false
            }
        }
    }

    pub fn run_loop(&self) {
        let comm_offset = self.vcpu_wasm.lock().comm_offset;

        loop {
            if self.hv.shutting_down.load(Ordering::Acquire)
                || unsafe { airlock_kapi_kthread_should_stop() }
            {
                return;
            }

            unsafe { airlock_kapi_cond_resched() };

            if let Some(start_page) = self.slot.lapic.take_sipi() {
                let npt_root = self.hv.stage2.root_phys();
                self.slot.arch.lock().apply_sipi(start_page, npt_root);
            }

            match self.slot.lapic.mp_state() {
                MpState::Uninitialized | MpState::InitReceived => {
                    self.slot.lapic.kick_wq.wait_timeout_ns(None);
                    continue;
                }
                MpState::SipiReceived => continue,
                MpState::Halted => {
                    if self.slot.lapic.has_pending_irr() {
                        self.slot.lapic.set_mp_state(MpState::Runnable);
                    } else {
                        let timeout = self.slot.lapic.active_timeout_ns();
                        if timeout != Some(0) {
                            self.slot.lapic.kick_wq.wait_timeout_ns(timeout);
                        }
                        if self.slot.lapic.has_pending_irr() {
                            self.slot.lapic.set_mp_state(MpState::Runnable);
                        }
                        continue;
                    }
                }
                MpState::Runnable => {}
            }

            let comm = unsafe {
                &mut *(self.wasm.shared_memory.data().as_ptr().add(comm_offset)
                    as *mut VcpuCommPage)
            };

            let fast_exit = {
                let mut arch = self.slot.arch.lock();
                arch.enter_guest(&self.slot.lapic, &self.hv.stage2, comm)
            };

            let fast_exit = match fast_exit {
                Ok(ex) => ex,
                Err(err) => {
                    kerr!("vcpu {} enter_guest failed: {err:?}", self.vcpu_id);
                    self.terminate_vm();
                    return;
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
                    self.terminate_vm();
                    return;
                }
                FastExit::MsrRead { msr, insn_len } => {
                    if let Some(val) = self.slot.lapic.try_rdmsr(msr) {
                        self.slot.arch.lock().complete_rdmsr(val, insn_len);
                    } else if let Some(val) = self.hv.pvclock.try_rdmsr(self.vcpu_id as usize, msr)
                    {
                        self.slot.arch.lock().complete_rdmsr(val, insn_len);
                    } else {
                        self.slot.arch.lock().sync_to_comm(comm);
                        let mut raw = RawVmExit::from_exit(VmExit::MsrRead { msr });
                        raw.insn_len = insn_len;
                        comm.exit = raw;
                        if !self.call_wasm_exit(comm_offset) {
                            return;
                        }
                    }
                }
                FastExit::MsrWrite { msr, val, insn_len } => {
                    if let Some(ipi_action) = self.slot.lapic.try_wrmsr(msr, val) {
                        self.slot.arch.lock().advance_rip(insn_len);
                        self.hv.dispatch_ipi(self.vcpu_id, ipi_action);
                    } else if self.hv.pvclock.try_wrmsr(
                        self.vcpu_id as usize,
                        msr,
                        val,
                        &self.hv.stage2,
                    ) {
                        self.slot.arch.lock().advance_rip(insn_len);
                    } else {
                        self.slot.arch.lock().sync_to_comm(comm);
                        let mut raw = RawVmExit::from_exit(VmExit::MsrWrite { msr, val });
                        raw.insn_len = insn_len;
                        comm.exit = raw;
                        if !self.call_wasm_exit(comm_offset) {
                            return;
                        }
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
                        self.slot.arch.lock().advance_rip(insn_len);
                        let notify = CoreToIoEntry {
                            msg_type: CORE_MSG_VIRTIO_NOTIFY,
                            aux_u16: queue_idx,
                            _pad: 0,
                            dev: dev_id as u64,
                            features: 0,
                            data: [0; 40],
                        };
                        let shm = self.bridge.shm_ptr();
                        if unsafe { BridgeShm::push_core_to_io(shm, notify) } {
                            self.hv.wake_c2i();
                        }
                    } else if !self.call_wasm_exit(comm_offset) {
                        return;
                    }
                }
                FastExit::MmioFault { gpa, .. } => {
                    if self.slot.lapic.in_xapic_mmio_range(gpa) {
                        match self
                            .slot
                            .lapic
                            .emulate_xapic_mmio(gpa, &self.hv.stage2, comm)
                        {
                            Ok(ipi_action) => {
                                self.hv.dispatch_ipi(self.vcpu_id, ipi_action);
                            }
                            Err(err) => {
                                kerr!(
                                    "vcpu {} xAPIC MMIO emulation failed at gpa={gpa:#x}: {err:?}",
                                    self.vcpu_id
                                );
                                self.terminate_vm();
                                return;
                            }
                        }
                    } else if !self.call_wasm_exit(comm_offset) {
                        return;
                    }
                }
            }
        }
    }
}

pub unsafe extern "C" fn vcpu_kthread_main(opaque: *mut c_void) {
    let runner = unsafe { &*(opaque as *const VcpuRunner) };
    runner.run_loop();
}

/// Context shared between the `i2c_eventfd` waitqueue wakeup callback and `airlock-rx` kthread.
pub struct RxRouterCtx {
    pub hv: Arc<LinuxHvCore>,
    pub bridge: Arc<LinuxCoreBridge>,
    pub wasm: Arc<LinuxWasmRuntime<LinuxHvCore, LinuxCoreBridge>>,
    pub rx_wq: Arc<WaitQueue>,
    pub rx_pending: AtomicBool,
}

impl RxRouterCtx {
    /// Drains `BridgeShm::io_to_core` directly inside the `i2c_eventfd` wakeup callback:
    /// - `IO_MSG_VIRTIO_IRQ`: resolves MSI route from `BridgeShm::msix_routing` and injects
    ///   directly into the target `VcpuLapic` (`0` kthread hops, `0` Wasm calls)!
    /// - `IO_MSG_SERIAL_RX` / `IO_MSG_REQUEST_SHUTDOWN`: queues into `ctrl_rx` and wakes `airlock-rx`.
    pub fn drain_i2c_ring(&self) {
        let shm = self.bridge.shm_ptr();
        let mut need_rx_wasm = false;

        while let Some(entry) = unsafe { BridgeShm::pop_io_to_core(shm) } {
            match entry.msg_type {
                IO_MSG_VIRTIO_IRQ => {
                    let dev_idx = entry.dev as usize;
                    if dev_idx >= MAX_VIRTIO_DEVS {
                        continue;
                    }
                    let msi: ShmMsiEntry = {
                        let lock = unsafe { &(*shm).msix_lock };
                        spin_lock(lock);
                        let m = unsafe {
                            let routing = &(*shm).msix_routing[dev_idx];
                            if entry.irq_kind as u32 == IRQ_KIND_CONFIG {
                                routing.config_msi
                            } else if (entry.queue_index as usize) < MAX_QUEUES_PER_DEV {
                                routing.queue_msis[entry.queue_index as usize]
                            } else {
                                ShmMsiEntry::default()
                            }
                        };
                        spin_unlock(lock);
                        m
                    };
                    if msi.enabled != 0 && msi.addr != 0 {
                        let _ = self.hv.inject_msi_from_irq(msi.addr, msi.data);
                    }
                }
                IO_MSG_SERIAL_RX => {
                    self.bridge.push_ctrl_rx(entry);
                    need_rx_wasm = true;
                }
                IO_MSG_REQUEST_SHUTDOWN => {
                    self.bridge.push_ctrl_rx(entry);
                    need_rx_wasm = true;
                }
                _ => {}
            }
        }

        if need_rx_wasm {
            self.rx_pending.store(true, Ordering::Release);
            self.rx_wq.wake();
        }
    }

    pub fn run_rx_kthread(&self) {
        loop {
            if self.hv.shutting_down.load(Ordering::Acquire)
                || unsafe { airlock_kapi_kthread_should_stop() }
            {
                return;
            }

            if !self.rx_pending.swap(false, Ordering::AcqRel) {
                self.rx_wq.wait_timeout_ns(None);
                continue;
            }

            let res = {
                let mut rx = self.wasm.rx_worker.lock();
                let RxWasmWorker {
                    store,
                    on_bridge_rx,
                    ..
                } = &mut *rx;
                let _ibt = WasmCallGuard::enter();
                on_bridge_rx.call(store, ())
            };

            match res {
                Ok(rc) if rc == VmAction::Continue as i32 => {}
                Ok(rc) if rc == VmAction::Shutdown as i32 || rc == VmAction::Reboot as i32 => {
                    let shm = self.bridge.shm_ptr();
                    let entry = CoreToIoEntry {
                        msg_type: CORE_MSG_SHUTDOWN,
                        ..Default::default()
                    };
                    unsafe {
                        (*shm).shutdown_requested.store(1, Ordering::Release);
                        let _ = BridgeShm::push_core_to_io(shm, entry);
                    }
                    self.hv.signal_shutdown();
                    return;
                }
                Ok(rc) => {
                    kerr!(
                        "airlock-rx vmm_on_bridge_rx error: {:?}",
                        HvError::from_code(rc)
                    );
                    self.hv.signal_shutdown();
                    return;
                }
                Err(trap) => {
                    kerr!("airlock-rx vmm_on_bridge_rx trapped: {trap}");
                    self.hv.signal_shutdown();
                    return;
                }
            }
        }
    }
}

pub unsafe extern "C" fn on_i2c_eventfd_wakeup(opaque: *mut c_void) {
    let ctx = unsafe { &*(opaque as *const RxRouterCtx) };
    ctx.drain_i2c_ring();
}

pub unsafe extern "C" fn rx_kthread_main(opaque: *mut c_void) {
    let ctx = unsafe { &*(opaque as *const RxRouterCtx) };
    ctx.run_rx_kthread();
}
