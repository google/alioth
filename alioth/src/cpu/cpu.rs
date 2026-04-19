// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(target_arch = "aarch64")]
#[path = "cpu_aarch64.rs"]
mod aarch64;
#[cfg(target_arch = "x86_64")]
#[path = "cpu_x86_64/cpu_x86_64.rs"]
mod x86_64;

use std::sync::Arc;
use std::thread::JoinHandle;

use flume::Sender;
use parking_lot::{Condvar, Mutex, RwLock};
use snafu::{ResultExt, Snafu};

use crate::board::Board;
use crate::errors::{DebugTrace, trace_error};
use crate::hv::{Vcpu, Vm, VmEntry, VmExit};
#[cfg(target_arch = "x86_64")]
use crate::loader::xen;
use crate::loader::{Executable, InitState, linux};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Failed to configure guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("Failed to setup board"), context(false))]
    Board { source: Box<crate::board::Error> },
    #[snafu(display("Failed to reset PCI devices"))]
    ResetPci { source: Box<crate::pci::Error> },
    #[snafu(display("Firmware error"), context(false))]
    Firmware { source: Box<crate::firmware::Error> },
    #[snafu(display("Unknown firmware metadata"))]
    UnknownFirmwareMetadata,
    #[snafu(display("Missing payload"))]
    MissingPayload,
    #[snafu(display("Failed to load payload"), context(false))]
    Loader { source: Box<crate::loader::Error> },
    #[snafu(display("Failed to notify the VMM thread"))]
    NotifyVmm,
    #[snafu(display("Another VCPU thread has signaled failure"))]
    PeerFailure,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Paused,
    Running,
    Shutdown,
    RebootPending,
}

pub(crate) struct MpSync {
    pub(crate) state: State,
    fatal: bool,
    count: u16,
}

pub struct VcpuHandle {
    pub thread: JoinHandle<Result<()>>,
}

pub struct Context<V: Vm> {
    pub(crate) board: Board<V>,
    pub(crate) vcpus: RwLock<Vec<VcpuHandle>>,

    pub(crate) sync: Mutex<MpSync>,
    pub(crate) cond: Condvar,
}

impl<V: Vm> Context<V> {
    pub fn new(board: Board<V>) -> Self {
        Self {
            board,
            vcpus: RwLock::new(Vec::new()),
            sync: Mutex::new(MpSync {
                state: State::Paused,
                fatal: false,
                count: 0,
            }),
            cond: Condvar::new(),
        }
    }
}

struct VcpuThread<V: Vm> {
    ctx: Arc<Context<V>>,
    index: u16,
    event_tx: Sender<u16>,
    vcpu: <V as Vm>::Vcpu,
}

fn notify_vmm(event_tx: &Sender<u16>, index: u16) -> Result<()> {
    if event_tx.send(index).is_err() {
        error::NotifyVmm.fail()
    } else {
        Ok(())
    }
}

impl<V: Vm> VcpuThread<V> {
    pub fn new(index: u16, ctx: Arc<Context<V>>, event_tx: Sender<u16>) -> Result<Self> {
        let identity = ctx.board.encode_cpu_identity(index);
        let vcpu = ctx.board.vm.create_vcpu(index, identity)?;

        Ok(Self {
            ctx,
            index,
            event_tx,
            vcpu,
        })
    }

    fn notify_vmm(&self) -> Result<()> {
        notify_vmm(&self.event_tx, self.index)
    }

    fn sync_vcpus(&self, vcpus: &[VcpuHandle]) -> Result<()> {
        let mut sync = self.ctx.sync.lock();
        if sync.fatal {
            return error::PeerFailure.fail();
        }

        sync.count += 1;
        if sync.count == vcpus.len() as u16 {
            sync.count = 0;
            self.ctx.cond.notify_all();
        } else {
            self.ctx.cond.wait(&mut sync)
        }

        if sync.fatal {
            return error::PeerFailure.fail();
        }

        Ok(())
    }

    fn load_payload(&self) -> Result<InitState> {
        let payload = self.ctx.board.payload.read();
        let Some(payload) = payload.as_ref() else {
            return error::MissingPayload.fail();
        };

        if let Some(fw) = payload.firmware.as_ref() {
            return self.setup_firmware(fw, payload);
        }

        let Some(exec) = &payload.executable else {
            return error::MissingPayload.fail();
        };
        let mem_regions = self.ctx.board.memory.mem_region_entries();
        let init_state = match exec {
            Executable::Linux(image) => linux::load(
                &self.ctx.board.memory.ram_bus(),
                &mem_regions,
                image.as_ref(),
                payload.cmdline.as_deref(),
                payload.initramfs.as_deref(),
            ),
            #[cfg(target_arch = "x86_64")]
            Executable::Pvh(image) => xen::load(
                &self.ctx.board.memory.ram_bus(),
                &mem_regions,
                image.as_ref(),
                payload.cmdline.as_deref(),
                payload.initramfs.as_deref(),
            ),
        }?;
        Ok(init_state)
    }

    fn boot_init_sync(&mut self) -> Result<()> {
        let ctx = self.ctx.clone();
        let vcpus = ctx.vcpus.read();
        if self.index == 0 {
            self.ctx.board.init_devices()?;
            let init_state = self.load_payload()?;
            self.init_boot_vcpu(&init_state)?;
            self.ctx.board.create_firmware_data(&init_state)?;
        }
        self.init_ap(&vcpus)?;
        self.coco_finalize(&vcpus)?;
        self.sync_vcpus(&vcpus)
    }

    fn vcpu_loop(&mut self) -> Result<State> {
        let mut vm_entry = VmEntry::None;
        loop {
            let vm_exit = self.vcpu.run(vm_entry)?;
            let memory = &self.ctx.board.memory;
            vm_entry = match vm_exit {
                #[cfg(target_arch = "x86_64")]
                VmExit::Io { port, write, size } => memory.handle_io(port, write, size)?,
                VmExit::Mmio { addr, write, size } => memory.handle_mmio(addr, write, size)?,
                VmExit::Shutdown => break Ok(State::Shutdown),
                VmExit::Reboot => break Ok(State::RebootPending),
                VmExit::Paused => break Ok(State::Paused),
                VmExit::Interrupted => {
                    let state = self.ctx.sync.lock();
                    match state.state {
                        State::Shutdown => VmEntry::Shutdown,
                        State::RebootPending => VmEntry::Reboot,
                        State::Paused => VmEntry::Pause,
                        State::Running => VmEntry::None,
                    }
                }
                VmExit::ConvertMemory { gpa, size, private } => {
                    memory.mark_private_memory(gpa, size, private)?;
                    VmEntry::None
                }
            };
        }
    }

    fn run(&mut self) -> Result<()> {
        self.init_vcpu()?;

        'reboot: loop {
            let mut sync = self.ctx.sync.lock();
            loop {
                match sync.state {
                    State::Paused => self.ctx.cond.wait(&mut sync),
                    State::Running => break,
                    State::Shutdown => break 'reboot Ok(()),
                    State::RebootPending => sync.state = State::Running,
                }
            }
            drop(sync);

            self.boot_init_sync()?;

            let request = 'pause: loop {
                let request = self.vcpu_loop();

                let vcpus = self.ctx.vcpus.read();
                let mut sync = self.ctx.sync.lock();
                if sync.state == State::Running {
                    sync.state = match request {
                        Ok(State::RebootPending) => State::RebootPending,
                        Ok(State::Paused) => State::Paused,
                        _ => State::Shutdown,
                    };
                    log::trace!("VCPU-{}: change state to {:?}", self.index, sync.state);
                    stop_vcpus(&self.ctx.board, Some(self.index), &vcpus)?;
                }
                loop {
                    match sync.state {
                        State::Paused => self.ctx.cond.wait(&mut sync),
                        State::Running => break,
                        State::RebootPending | State::Shutdown => break 'pause request,
                    }
                }
            };

            if self.index == 0 {
                let board = &self.ctx.board;
                board.pci_bus.segment.reset().context(error::ResetPci)?;
                board.memory.reset()?;
            }
            self.reset_vcpu()?;

            request?;

            let vcpus = self.ctx.vcpus.read();
            self.sync_vcpus(&vcpus)?;
        }
    }
}

fn vcpu_thread_<V: Vm>(index: u16, ctx: Arc<Context<V>>, event_tx: Sender<u16>) -> Result<()> {
    let mut thread = VcpuThread::new(index, ctx, event_tx)?;
    thread.notify_vmm()?;
    thread.run()
}

pub fn vcpu_thread<V: Vm>(index: u16, ctx: Arc<Context<V>>, event_tx: Sender<u16>) -> Result<()> {
    let ret = vcpu_thread_(index, ctx.clone(), event_tx.clone());

    let _ = notify_vmm(&event_tx, index);

    if matches!(ret, Ok(_) | Err(Error::PeerFailure { .. })) {
        return Ok(());
    }

    log::warn!("VCPU-{index} reported error {ret:?}, unblocking other VCPUs...");
    let mut sync = ctx.sync.lock();
    sync.fatal = true;
    if sync.count > 0 {
        ctx.cond.notify_all();
    }
    ret
}

pub fn stop_vcpus<V: Vm>(
    board: &Board<V>,
    current: Option<u16>,
    vcpus: &[VcpuHandle],
) -> Result<()> {
    for (index, handle) in vcpus.iter().enumerate() {
        let index = index as u16;
        if let Some(current) = current {
            if current == index {
                continue;
            }
            log::info!("VCPU-{current}: stopping VCPU-{index}");
        } else {
            log::info!("Stopping VCPU-{index}");
        }
        let identity = board.encode_cpu_identity(index);
        board.vm.stop_vcpu(identity, &handle.thread)?;
    }
    Ok(())
}
