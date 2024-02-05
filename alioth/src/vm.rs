// Copyright 2024 Google LLC
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

#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Barrier, PoisonError};
use std::thread::{self, JoinHandle};

use mio::{Events, Poll, Token, Waker};
use thiserror::Error;

use crate::device::serial::Serial;
use crate::hv::{self, Vcpu, Vm, VmEntry, VmExit};
use crate::loader::{self, linux, InitState};
use crate::mem;
use crate::mem::Memory;

#[cfg(target_arch = "x86_64")]
use x86_64::ArchBoard;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(
        #[from]
        #[backtrace]
        hv::Error,
    ),

    #[error("memory: {0}")]
    Memory(
        #[from]
        #[backtrace]
        mem::Error,
    ),

    #[error("host io: {0}")]
    HostIo(
        #[from]
        #[backtrace]
        std::io::Error,
    ),

    #[error("loader: {0}")]
    Loader(
        #[from]
        #[backtrace]
        loader::Error,
    ),

    #[error("rwlock poisoned")]
    RwLockPoisoned,

    #[error("ACPI bytes exceed EBDA area")]
    AcpiTooLong,

    #[error("cannot handle {0:#x?}")]
    VmExit(String),
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::RwLockPoisoned
    }
}

#[derive(Debug)]
pub struct Payload {
    pub executable: PathBuf,
    pub exec_type: ExecType,
    pub initramfs: Option<PathBuf>,
    pub cmd_line: Option<String>,
}

pub struct BoardConfig {
    pub mem_size: usize,
    pub num_cpu: u32,
}

#[derive(Debug)]
pub enum ExecType {
    Linux,
}

pub struct Machine<H>
where
    H: crate::hv::Hypervisor,
{
    vcpu_threads: Vec<JoinHandle<Result<(), Error>>>,
    board: Arc<Board<H::Vm>>,
    // board_config: BoardConfig,
    payload: Option<Payload>,
    poll: Poll,
}

const STATE_CREATED: u8 = 0;
const STATE_RUNNING: u8 = 1;
const STATE_SHUTDOWN: u8 = 2;

struct Board<V>
where
    V: crate::hv::Vm,
{
    vm: V,
    memory: Memory,
    arch: ArchBoard,
    config: BoardConfig,
    waker: Waker,
    state: AtomicU8,
}

impl<V> Board<V>
where
    V: crate::hv::Vm,
{
    fn vcpu_loop(&self, vcpu: &mut <V as Vm>::Vcpu, id: u32) -> Result<(), Error> {
        let mut vm_entry = VmEntry::None;
        loop {
            // TODO is there any race here?
            if self.state.load(Ordering::Acquire) == STATE_SHUTDOWN {
                vm_entry = VmEntry::Shutdown;
            }
            let vm_exit = vcpu.run(vm_entry)?;
            vm_entry = match vm_exit {
                VmExit::Io { port, write, size } => self.memory.handle_io(port, write, size)?,
                VmExit::Mmio { addr, write, size } => self.memory.handle_mmio(addr, write, size)?,
                VmExit::Shutdown => {
                    log::info!("vcpu {id} requested shutdown");
                    break Ok(());
                }
                VmExit::Interrupted => VmEntry::None,
                VmExit::Unknown(msg) => break Err(Error::VmExit(msg)),
            };
        }
    }

    fn run_vcpu_inner(
        &self,
        id: u32,
        init_state: &InitState,
        barrier: &Barrier,
    ) -> Result<(), Error> {
        let mut vcpu = self.init_vcpu(id, init_state)?;
        barrier.wait();
        self.vcpu_loop(&mut vcpu, id)
    }

    fn run_vcpu(&self, id: u32, init_state: &InitState, barrier: &Barrier) -> Result<(), Error> {
        let ret = self.run_vcpu_inner(id, init_state, barrier);
        self.state.store(STATE_SHUTDOWN, Ordering::Release);
        self.waker.wake()?;
        ret
    }
}

impl<H> Machine<H>
where
    H: crate::hv::Hypervisor + 'static,
{
    pub fn new(hv: H, config: BoardConfig) -> Result<Self, Error> {
        let mut vm = hv.create_vm()?;
        let vm_mmemory = vm.create_vm_memory()?;
        let memory = Memory::new(vm_mmemory);
        let arch = ArchBoard::new(&hv)?;

        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), Token(0))?;
        let board = Board {
            vm,
            memory,
            arch,
            config,
            waker,
            state: AtomicU8::new(STATE_CREATED),
        };

        let machine = Machine {
            board: Arc::new(board),
            payload: None,
            vcpu_threads: Vec::new(),
            poll,
        };
        Ok(machine)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_com1(&self) -> Result<(), Error> {
        let com1_intx_sender = self.board.vm.create_intx_sender(4)?;
        let com1 = Serial::new(0x3f8, com1_intx_sender)?;
        self.board.memory.add_io_dev(Some(0x3f8), Arc::new(com1))?;
        Ok(())
    }

    pub fn add_payload(&mut self, payload: Payload) {
        self.payload = Some(payload)
    }

    fn load_payload(&self) -> Result<InitState, Error> {
        let Some(payload) = &self.payload else {
            return Ok(InitState::default());
        };
        let mem_regions = self.board.memory.to_mem_regions()?;
        let init_state = match payload.exec_type {
            ExecType::Linux => linux::load(
                self.board.memory.ram_bus(),
                &mem_regions,
                &payload.executable,
                payload.cmd_line.as_deref(),
                payload.initramfs.as_ref(),
            )?,
        };
        Ok(init_state)
    }

    pub fn boot(&mut self) -> Result<(), Error> {
        self.create_ram()?;
        let init_state = Arc::new(self.load_payload()?);
        self.create_firmware_data(&init_state)?;
        self.board.state.store(STATE_RUNNING, Ordering::Release);
        let barrier = Arc::new(Barrier::new(self.board.config.num_cpu as usize));
        for vcpu_id in 0..self.board.config.num_cpu {
            let init_state = init_state.clone();
            let barrier = barrier.clone();
            let board = self.board.clone();
            let handle = thread::Builder::new()
                .name(format!("vcpu_{}", vcpu_id))
                .spawn(move || board.run_vcpu(vcpu_id, &init_state, &barrier))?;
            self.vcpu_threads.push(handle);
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Vec<Result<()>> {
        let mut events = Events::with_capacity(8);
        if let Err(e) = self.poll.poll(&mut events, None) {
            return vec![Err(e.into())];
        }
        self.vcpu_threads
            .drain(..)
            .enumerate()
            .map(|(id, handle)| {
                <H::Vm>::stop_vcpu(id as u32, &handle)?;
                match handle.join() {
                    Err(e) => {
                        log::error!("cannot join vcpu {}: {:?}", id, e);
                        Ok(())
                    }
                    Ok(r) => r,
                }
            })
            .collect()
    }
}
