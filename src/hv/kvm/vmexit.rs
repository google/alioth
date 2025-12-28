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

use crate::hv::kvm::bindings::{KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT};
use crate::hv::{Error, VmExit};

use super::vcpu::KvmVcpu;

impl KvmVcpu {
    #[cfg(target_endian = "little")]
    pub(super) fn handle_mmio(&mut self) -> Result<VmExit, Error> {
        let kvm_mmio = unsafe { &self.kvm_run.exit.mmio };
        let exit = VmExit::Mmio {
            addr: kvm_mmio.phys_addr as usize,
            write: if kvm_mmio.is_write > 0 {
                Some(u64::from_ne_bytes(kvm_mmio.data))
            } else {
                None
            },
            size: kvm_mmio.len as u8,
        };
        Ok(exit)
    }

    pub(super) fn handle_io(&mut self) -> Result<VmExit, Error> {
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        assert_eq!(count, 1);
        let write = match (kvm_io.direction, kvm_io.size) {
            (KVM_EXIT_IO_IN, _) => None,
            (KVM_EXIT_IO_OUT, 1) => {
                Some(unsafe { self.kvm_run.data_slice::<u8>(offset, count) }[0] as u32)
            }
            (KVM_EXIT_IO_OUT, 2) => {
                Some(unsafe { self.kvm_run.data_slice::<u16>(offset, count) }[0] as u32)
            }
            (KVM_EXIT_IO_OUT, 4) => {
                Some(unsafe { self.kvm_run.data_slice::<u32>(offset, count) }[0])
            }
            _ => unreachable!(
                "kvm_io.direction = {}, kvm_io.size = {}",
                kvm_io.direction, kvm_io.size
            ),
        };
        Ok(VmExit::Io {
            port: kvm_io.port,
            write,
            size: kvm_io.size,
        })
    }
}
