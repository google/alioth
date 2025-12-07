// Copyright 2025 Google LLC
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

use std::mem::size_of_val;
use std::ptr::null_mut;

use assert_matches::assert_matches;
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE, mmap};

use crate::arch::msr::Efer;
use crate::arch::paging::Entry;
use crate::arch::reg::{Cr0, Cr4, Reg, SegAccess};
use crate::ffi;
use crate::hv::{
    DtReg, DtRegVal, Hypervisor, Kvm, MemMapOption, SReg, SegReg, SegRegVal, Vcpu, Vm, VmEntry,
    VmExit, VmMemory,
};

#[test]
#[cfg_attr(not(feature = "test-hv"), ignore)]
fn test_vcpu_regs() {
    use crate::hv::VmConfig;
    use crate::hv::kvm::KvmConfig;

    let kvm = Kvm::new(KvmConfig::default()).unwrap();
    let vm_config = VmConfig { coco: None };
    let vm = kvm.create_vm(&vm_config).unwrap();
    let mut vcpu = vm.create_vcpu(0).unwrap();
    let regs = [
        (Reg::Rax, 0xa93f90f6ce9c8040),
        (Reg::Rbx, 0xacbfb3f1f6f9cc1a),
        (Reg::Rcx, 0x885e7996751c1cd5),
        (Reg::Rdx, 0xd0fdf85b84d0cc9c),
        (Reg::Rsi, 0x3cc1f46972391c30),
        (Reg::Rdi, 0xf67783992ddc4484),
        (Reg::Rsp, 0x6363e7f07d68f992),
        (Reg::Rbp, 0x7aeb086e85756325),
        (Reg::R8, 0x72a90eeeb1f73300),
        (Reg::R9, 0x8893ba64a98de27e),
        (Reg::R10, 0x543f074b89fd6531),
        (Reg::R11, 0x5330fea600e3a98c),
        (Reg::R12, 0x5d2af23af80a0c15),
        (Reg::R13, 0x596ad2d66a74a573),
        (Reg::R14, 0x9d97437934678adb),
        (Reg::R15, 0x7ae7b06eebe1f4fc),
        (Reg::Rip, 0xdb424549231b8d3e),
        (Reg::Rflags, 1 << 1),
    ];
    vcpu.set_regs(&regs).unwrap();
    for (reg, val) in regs {
        assert_eq!(vcpu.get_reg(reg).unwrap(), val);
    }

    let sregs = [
        (SReg::Cr0, (1 << 0) | (1 << 5) | (1 << 31)),
        (SReg::Cr2, 0xffff88ac93e00000),
        (SReg::Cr3, 0x1362d001),
        (SReg::Cr4, 1 << 5),
        (SReg::Cr8, 0x0),
        (SReg::Efer, (1 << 8) | (1 << 10)),
        (SReg::ApicBase, 0xfee00900),
    ];
    let seg_regs = [
        (
            SegReg::Cs,
            SegRegVal {
                selector: 0x10,
                base: 0,
                limit: 0xffff_ffff,
                access: SegAccess(0xa09b),
            },
        ),
        (
            SegReg::Ds,
            SegRegVal {
                selector: 0x18,
                base: 0,
                limit: 0xffff_ffff,
                access: SegAccess(0xc093),
            },
        ),
        (
            SegReg::Es,
            SegRegVal {
                selector: 0x18,
                base: 0,
                limit: 0xffff_ffff,
                access: SegAccess(0xc093),
            },
        ),
        (
            SegReg::Fs,
            SegRegVal {
                selector: 0x18,
                base: 0,
                limit: 0xffff_ffff,
                access: SegAccess(0xc093),
            },
        ),
        (
            SegReg::Gs,
            SegRegVal {
                selector: 0x18,
                base: 0,
                limit: 0xffff_ffff,
                access: SegAccess(0xc093),
            },
        ),
        (
            SegReg::Ss,
            SegRegVal {
                selector: 0x18,
                base: 0,
                limit: 0xffff_ffff,
                access: SegAccess(0xc093),
            },
        ),
        (
            SegReg::Tr,
            SegRegVal {
                selector: 0x20,
                base: 0,
                limit: 0xf_ffff,
                access: SegAccess(0x8b),
            },
        ),
        (
            SegReg::Ldtr,
            SegRegVal {
                selector: 0x28,
                base: 0,
                limit: 0xf_ffff,
                access: SegAccess(0x82),
            },
        ),
    ];

    let dt_regs = [
        (
            DtReg::Gdtr,
            DtRegVal {
                base: 0xfffffe2a4aeeb000,
                limit: 0x7f,
            },
        ),
        (
            DtReg::Idtr,
            DtRegVal {
                base: 0xfffffe0000000000,
                limit: 0xfff,
            },
        ),
    ];
    vcpu.set_sregs(&sregs, &seg_regs, &dt_regs).unwrap();

    for (sreg, val) in sregs {
        assert_eq!(vcpu.get_sreg(sreg).unwrap(), val);
    }
    for (seg_reg, val) in seg_regs {
        assert_eq!(vcpu.get_seg_reg(seg_reg).unwrap(), val)
    }
    for (dt_reg, val) in dt_regs {
        assert_eq!(vcpu.get_dt_reg(dt_reg).unwrap(), val)
    }
}

#[test]
#[cfg_attr(not(feature = "test-hv"), ignore)]
fn test_kvm_run() {
    use crate::hv::VmConfig;
    use crate::hv::kvm::KvmConfig;

    let kvm = Kvm::new(KvmConfig::default()).unwrap();
    let vm_config = VmConfig { coco: None };
    let mut vm = kvm.create_vm(&vm_config).unwrap();
    let memory = vm.create_vm_memory().unwrap();

    let prot = PROT_WRITE | PROT_EXEC | PROT_READ;
    let flag = MAP_ANONYMOUS | MAP_SHARED;
    let user_mem = ffi!(
        unsafe { mmap(null_mut(), 0x5000, prot, flag, -1, 0,) },
        MAP_FAILED
    )
    .unwrap();
    let mmap_option = MemMapOption {
        read: true,
        write: true,
        exec: true,
        ..Default::default()
    };
    memory
        .mem_map(0, 0x5000, user_mem as usize, mmap_option)
        .unwrap();

    // layout
    // 0x1000 - 0x1f00 code
    // 0x1f00 - 0x2000 GDT
    // 0x2000 - 0x3000 PML4
    // 0x3000 - 0x4000 PDPT
    // 0x4000 - 0x5000 PD

    #[rustfmt::skip]
    const CODE: [u8; 29] = [
        // mov dx, 0x3f8
        0x66, 0xba, 0xf8, 0x03,
        // in al, dx
        0xec,
        // add eax, 0x1
        0x83, 0xc0, 0x01,
        // out dx, al
        0xee,
        // mov rax, [0x5000]
        0x48, 0x8b, 0x04, 0x25, 0x00, 0x50, 0x00,
        0x00,
        // add rax, 0x11
        0x48, 0x83, 0xc0, 0x11,
        // mov [0x5004], rax
        0x48, 0x89, 0x04, 0x25, 0x04, 0x50, 0x00,
        0x00,
    ];
    unsafe { ((user_mem as usize + 0x1000) as *mut [u8; 29]).write(CODE) };

    let pml4e = (Entry::P | Entry::RW).bits() as u64 | 0x3000;
    unsafe { ((user_mem as usize + 0x2000) as *mut u64).write(pml4e) }
    let pdpte = (Entry::P | Entry::RW).bits() as u64 | 0x4000;
    unsafe { ((user_mem as usize + 0x3000) as *mut u64).write(pdpte) }
    let pde = (Entry::P | Entry::RW | Entry::PS).bits() as u64;
    unsafe { ((user_mem as usize + 0x4000) as *mut u64).write(pde) }

    let mut vcpu = vm.create_vcpu(0).unwrap();
    let cs = SegRegVal {
        selector: 0x10,
        base: 0,
        limit: 0xffff_ffff,
        access: SegAccess(0xa09b),
    };
    let ds = SegRegVal {
        selector: 0x18,
        base: 0,
        limit: 0xffff_ffff,
        access: SegAccess(0xc093),
    };
    let tr = SegRegVal {
        selector: 0x20,
        base: 0,
        limit: 0,
        access: SegAccess(0x8b),
    };
    let ldtr = SegRegVal {
        selector: 0x28,
        base: 0,
        limit: 0,
        access: SegAccess(0x82),
    };
    let gdt = [
        0,
        0,
        cs.to_desc(),
        ds.to_desc(),
        tr.to_desc(),
        ldtr.to_desc(),
    ];
    assert!(size_of_val(&gdt) < 0x100);
    unsafe { ((user_mem as usize + 0x1f00) as *mut [u64; 6]).write(gdt) };
    let gdtr = DtRegVal {
        base: 0x1f00,
        limit: size_of_val(&gdt) as u16 - 1,
    };
    let idtr = DtRegVal { base: 0, limit: 0 };
    vcpu.set_sregs(
        &[
            (SReg::Efer, (Efer::LMA | Efer::LME).bits() as u64),
            (SReg::Cr0, (Cr0::NE | Cr0::PE | Cr0::PG).bits() as u64),
            (SReg::Cr3, 0x2000),
            (SReg::Cr4, Cr4::PAE.bits() as u64),
        ],
        &[
            (SegReg::Cs, cs),
            (SegReg::Ds, ds),
            (SegReg::Es, ds),
            (SegReg::Fs, ds),
            (SegReg::Gs, ds),
            (SegReg::Ss, ds),
            (SegReg::Tr, tr),
            (SegReg::Ldtr, ldtr),
        ],
        &[(DtReg::Gdtr, gdtr), (DtReg::Idtr, idtr)],
    )
    .unwrap();
    vcpu.set_regs(&[
        (Reg::Rip, 0x1000),
        (Reg::Rax, 0x2),
        (Reg::Rbx, 0x2),
        (Reg::Rdx, 0x3f8),
        (Reg::Rsi, 0x1000),
        (Reg::Rflags, 0x2),
    ])
    .unwrap();
    assert_matches!(
        vcpu.run(VmEntry::None),
        Ok(VmExit::Io {
            port: 0x3f8,
            write: None,
            size: 1
        })
    );
    assert_matches!(
        vcpu.run(VmEntry::Io { data: Some(0x10) }),
        Ok(VmExit::Io {
            port: 0x3f8,
            write: Some(0x11),
            size: 1
        })
    );
    assert_matches!(
        vcpu.run(VmEntry::None),
        Ok(VmExit::Mmio {
            addr: 0x5000,
            write: None,
            size: 8
        })
    );
    assert_matches!(
        vcpu.run(VmEntry::Mmio { data: 0x0000_ffff }),
        Ok(VmExit::Mmio {
            addr: 0x5004,
            write: Some(0x0001_0010),
            size: 8
        })
    );
}
