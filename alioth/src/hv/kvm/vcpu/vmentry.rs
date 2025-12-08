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
use crate::hv::VmExit;
use crate::hv::kvm::vcpu::KvmVcpu;
#[cfg(target_arch = "x86_64")]
use crate::sys::kvm::{KvmExit, KvmRunExitIo};

impl KvmVcpu {
    #[cfg(target_endian = "little")]
    pub(super) fn entry_mmio(&mut self, data: u64) {
        use crate::sys::kvm::KvmExit;

        assert_eq!(self.kvm_run.exit_reason, KvmExit::MMIO);
        let kvm_mmio = unsafe { &mut self.kvm_run.exit.mmio };
        assert_eq!(kvm_mmio.is_write, 0);
        kvm_mmio.data = data.to_ne_bytes();
    }

    pub(super) fn set_immediate_exit(&mut self, enable: bool) {
        self.kvm_run.immediate_exit = enable as u8;
    }

    #[cfg(target_arch = "x86_64")]
    fn entry_io_in(&mut self, data: u32, kvm_io: KvmRunExitIo) {
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        let index = self.arch.io_index;
        match kvm_io.size {
            1 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[index] = data as u8;
            },
            2 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[index] = data as u16;
            },
            4 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[index] = data;
            },
            _ => unreachable!("kvm_io.size = {}", kvm_io.size),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn entry_io(&mut self, data: Option<u32>) -> Option<VmExit> {
        assert_eq!(self.kvm_run.exit_reason, KvmExit::IO);
        let kvm_io = unsafe { self.kvm_run.exit.io };
        if let Some(data) = data {
            self.entry_io_in(data, kvm_io);
        }
        self.arch.io_index += 1;
        if self.arch.io_index == kvm_io.count as usize {
            self.arch.io_index = 0;
            return None;
        }
        Some(self.handle_io())
    }
}
