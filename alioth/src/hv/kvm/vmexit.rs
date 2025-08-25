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

use crate::hv::kvm::bindings::{
    KVM_HC_MAP_GPA_RANGE, KvmExitIo, KvmMapGpaRangeFlag, KvmSystemEvent,
};
use crate::hv::kvm::vcpu::KvmVcpu;
use crate::hv::{Error, VmExit, error};

impl KvmVcpu {
    #[cfg(target_endian = "little")]
    pub(super) fn handle_mmio(&mut self) -> Result<VmExit, Error> {
        let kvm_mmio = unsafe { &self.kvm_run.exit.mmio };
        let exit = VmExit::Mmio {
            addr: kvm_mmio.phys_addr,
            write: if kvm_mmio.is_write > 0 {
                Some(u64::from_ne_bytes(kvm_mmio.data))
            } else {
                None
            },
            size: kvm_mmio.len as u8,
        };
        Ok(exit)
    }

    pub(super) fn handle_io(&mut self) -> VmExit {
        let kvm_io = unsafe { self.kvm_run.exit.io };
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        let index = self.io_index;
        let write = if kvm_io.direction == KvmExitIo::IN {
            None
        } else {
            let data = match kvm_io.size {
                1 => unsafe { self.kvm_run.data_slice::<u8>(offset, count)[index] as u32 },
                2 => unsafe { self.kvm_run.data_slice::<u16>(offset, count)[index] as u32 },
                4 => unsafe { self.kvm_run.data_slice::<u32>(offset, count)[index] },
                _ => unreachable!("kvm_io.size = {}", kvm_io.size),
            };
            Some(data)
        };
        VmExit::Io {
            port: kvm_io.port,
            write,
            size: kvm_io.size,
        }
    }

    pub(super) fn handle_hypercall(&mut self) -> Result<VmExit, Error> {
        let hypercall = unsafe { self.kvm_run.exit.hypercall };
        match hypercall.nr {
            KVM_HC_MAP_GPA_RANGE => {
                let flag = KvmMapGpaRangeFlag::from_bits_retain(hypercall.args[2]);
                Ok(VmExit::ConvertMemory {
                    gpa: hypercall.args[0],
                    size: hypercall.args[1] << 12,
                    private: flag.contains(KvmMapGpaRangeFlag::ENCRYPTED),
                })
            }
            _ => unimplemented!(),
        }
    }

    pub(super) fn handle_system_event(&mut self) -> Result<VmExit, Error> {
        let kvm_system_event = unsafe { &self.kvm_run.exit.system_event };
        match kvm_system_event.type_ {
            KvmSystemEvent::SHUTDOWN => Ok(VmExit::Shutdown),
            KvmSystemEvent::RESET => Ok(VmExit::Reboot),
            _ => error::VmExit {
                msg: format!("{kvm_system_event:#x?}"),
            }
            .fail(),
        }
    }
}
