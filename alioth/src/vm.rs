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

use std::fmt::Debug;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use parking_lot::RwLock;
use thiserror::Error;

use crate::board::{self, ArchBoard, Board, BoardConfig, STATE_CREATED, STATE_RUNNING};
use crate::device::serial::Serial;
use crate::hv::{self, Hypervisor, Vm};
use crate::loader::{self, Payload};
use crate::mem;
use crate::mem::Memory;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] hv::Error),

    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("host io: {0}")]
    HostIo(#[from] std::io::Error),

    #[error("loader: {0}")]
    Loader(#[from] loader::Error),

    #[error("board: {0}")]
    Board(#[from] board::Error),

    #[error("ACPI bytes exceed EBDA area")]
    AcpiTooLong,

    #[error("cannot handle {0:#x?}")]
    VmExit(String),
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Machine<H>
where
    H: Hypervisor,
{
    vcpu_threads: Vec<(JoinHandle<Result<(), board::Error>>, Sender<()>)>,
    board: Arc<Board<H::Vm>>,
    event_rx: Receiver<u32>,
    event_tx: Sender<u32>,
}

impl<H> Machine<H>
where
    H: Hypervisor + 'static,
{
    pub fn new(hv: H, config: BoardConfig) -> Result<Self, Error> {
        let mut vm = hv.create_vm()?;
        let vm_memory = vm.create_vm_memory()?;
        let memory = Memory::new(vm_memory);
        let arch = ArchBoard::new(&hv)?;

        let board = Board {
            vm,
            memory,
            arch,
            config,
            state: AtomicU8::new(STATE_CREATED),
            payload: RwLock::new(None),
        };

        let (event_tx, event_rx) = mpsc::channel();
        let machine = Machine {
            board: Arc::new(board),
            vcpu_threads: Vec::new(),
            event_rx,
            event_tx,
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
        *self.board.payload.write() = Some(payload)
    }

    pub fn boot(&mut self) -> Result<(), Error> {
        for vcpu_id in 0..self.board.config.num_cpu {
            let (boot_tx, boot_rx) = mpsc::channel();
            let event_tx = self.event_tx.clone();
            let board = self.board.clone();
            let handle = thread::Builder::new()
                .name(format!("vcpu_{}", vcpu_id))
                .spawn(move || board.run_vcpu(vcpu_id, event_tx, boot_rx))?;
            self.event_rx.recv().unwrap();
            self.vcpu_threads.push((handle, boot_tx));
        }
        self.board.state.store(STATE_RUNNING, Ordering::Release);
        for (_, boot_tx) in self.vcpu_threads.iter() {
            boot_tx.send(()).unwrap();
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Vec<Result<()>> {
        self.event_rx.recv().unwrap();
        self.vcpu_threads
            .drain(..)
            .enumerate()
            .map(|(id, (handle, _))| {
                <H::Vm>::stop_vcpu(id as u32, &handle)?;
                match handle.join() {
                    Err(e) => {
                        log::error!("cannot join vcpu {}: {:?}", id, e);
                        Ok(())
                    }
                    Ok(r) => r.map_err(Error::Board),
                }
            })
            .collect()
    }
}
