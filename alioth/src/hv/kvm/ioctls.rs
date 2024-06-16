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
    KvmCap, KvmCpuid2, KvmCreateGuestMemfd, KvmEnableCap, KvmEncRegion, KvmIoEventFd,
    KvmIrqRouting, KvmIrqfd, KvmMemoryAttributes, KvmMsi, KvmRegs, KvmSregs, KvmSregs2,
    KvmUserspaceMemoryRegion, KvmUserspaceMemoryRegion2, KVMIO,
};
use crate::utils::ioctls::{ioctl_io, ioctl_ior, ioctl_iowr};
use crate::{
    ioctl_none, ioctl_read, ioctl_write_buf, ioctl_write_ptr, ioctl_write_val, ioctl_writeread,
    ioctl_writeread_buf,
};

ioctl_none!(kvm_get_api_version, KVMIO, 0x00, 0);
ioctl_write_val!(kvm_create_vm, ioctl_io(KVMIO, 0x01));
ioctl_write_val!(kvm_check_extension, ioctl_io(KVMIO, 0x03), KvmCap);
ioctl_none!(kvm_get_vcpu_mmap_size, KVMIO, 0x04, 0);
#[cfg(target_arch = "x86_64")]
ioctl_writeread_buf!(kvm_get_supported_cpuid, KVMIO, 0x05, KvmCpuid2);

ioctl_write_val!(kvm_create_vcpu, ioctl_io(KVMIO, 0x41), u32);
ioctl_write_ptr!(
    kvm_set_user_memory_region,
    KVMIO,
    0x46,
    KvmUserspaceMemoryRegion
);
#[cfg(target_arch = "x86_64")]
ioctl_write_val!(kvm_set_tss_addr, ioctl_io(KVMIO, 0x47));
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_identity_map_addr, KVMIO, 0x48, u64);
ioctl_write_ptr!(
    kvm_set_user_memory_region2,
    KVMIO,
    0x49,
    KvmUserspaceMemoryRegion2
);

ioctl_none!(kvm_create_irqchip, KVMIO, 0x60, 0);
ioctl_write_buf!(kvm_set_gsi_routing, KVMIO, 0x6a, KvmIrqRouting);

ioctl_write_ptr!(kvm_irqfd, KVMIO, 0x76, KvmIrqfd);
ioctl_write_ptr!(kvm_ioeventfd, KVMIO, 0x79, KvmIoEventFd);

ioctl_none!(kvm_run, KVMIO, 0x80, 0);
ioctl_read!(kvm_get_regs, KVMIO, 0x81, KvmRegs);
ioctl_write_ptr!(kvm_set_regs, KVMIO, 0x82, KvmRegs);
#[cfg(target_arch = "x86_64")]
ioctl_read!(kvm_get_sregs, KVMIO, 0x83, KvmSregs);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_sregs, KVMIO, 0x84, KvmSregs);

#[cfg(target_arch = "x86_64")]
ioctl_write_buf!(kvm_set_cpuid2, KVMIO, 0x90, KvmCpuid2);

ioctl_write_ptr!(kvm_enable_cap, KVMIO, 0xa3, KvmEnableCap);
ioctl_write_ptr!(kvm_signal_msi, KVMIO, 0xa5, KvmMsi);

ioctl_writeread!(kvm_memory_encrypt_op, ioctl_iowr::<u64>(KVMIO, 0xba));

ioctl_write_ptr!(
    kvm_memory_encrypt_reg_region,
    ioctl_ior::<KvmEncRegion>(KVMIO, 0xbb),
    KvmEncRegion
);

ioctl_write_ptr!(
    kvm_memory_encrypt_unreg_region,
    ioctl_ior::<KvmEncRegion>(KVMIO, 0xbc),
    KvmEncRegion
);

#[cfg(target_arch = "x86_64")]
ioctl_read!(kvm_get_sregs2, KVMIO, 0xcc, KvmSregs2);
#[cfg(target_arch = "x86_64")]
ioctl_write_ptr!(kvm_set_sregs2, KVMIO, 0xcd, KvmSregs2);

ioctl_write_ptr!(kvm_set_memory_attributes, KVMIO, 0xd2, KvmMemoryAttributes);

ioctl_writeread!(kvm_create_guest_memfd, KVMIO, 0xd4, KvmCreateGuestMemfd);
