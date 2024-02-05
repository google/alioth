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

use crate::hv::kvm::bindings::{KVM_EXIT_IO, KVM_EXIT_IO_IN, KVM_EXIT_MMIO};

use super::vcpu::KvmVcpu;

impl KvmVcpu {
    #[cfg(target_endian = "little")]
    pub(super) fn entry_mmio(&mut self, data: u64) {
        assert_eq!(self.kvm_run.exit_reason, KVM_EXIT_MMIO);
        let kvm_mmio = unsafe { &mut self.kvm_run.exit.mmio };
        assert_eq!(kvm_mmio.is_write, 0);
        kvm_mmio.data = data.to_ne_bytes();
    }

    pub(super) fn immediate_exit(&mut self) {
        self.kvm_run.immediate_exit = 1;
    }

    pub(super) fn entry_io(&mut self, data: u32) {
        assert_eq!(self.kvm_run.exit_reason, KVM_EXIT_IO);
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        assert_eq!(kvm_io.direction, KVM_EXIT_IO_IN);
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        match kvm_io.size {
            1 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data as u8;
            },
            2 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data as u16;
            },
            4 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data;
            },
            _ => unreachable!("kvm_io.size = {}", kvm_io.size),
        }
    }
}
