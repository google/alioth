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
    KvmExitIo, KvmMapGpaRangeFlag, KvmSystemEvent, KVM_HC_MAP_GPA_RANGE,
};
use crate::hv::{Error, VmExit};

use super::vcpu::KvmVcpu;

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

    pub(super) fn handle_io(&mut self) -> Result<VmExit, Error> {
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        assert_eq!(count, 1);
        let write = match (kvm_io.direction, kvm_io.size) {
            (KvmExitIo::IN, _) => None,
            (KvmExitIo::OUT, 1) => {
                Some(unsafe { self.kvm_run.data_slice::<u8>(offset, count) }[0] as u32)
            }
            (KvmExitIo::OUT, 2) => {
                Some(unsafe { self.kvm_run.data_slice::<u16>(offset, count) }[0] as u32)
            }
            (KvmExitIo::OUT, 4) => {
                Some(unsafe { self.kvm_run.data_slice::<u32>(offset, count) }[0])
            }
            _ => unreachable!(
                "kvm_io.direction = {:?}, kvm_io.size = {}",
                kvm_io.direction, kvm_io.size
            ),
        };
        Ok(VmExit::Io {
            port: kvm_io.port,
            write,
            size: kvm_io.size,
        })
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
            _ => Ok(VmExit::Unknown(format!("{kvm_system_event:#x?}",))),
        }
    }
}
