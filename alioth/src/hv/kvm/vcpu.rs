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

use std::io::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::os::fd::{OwnedFd, RawFd};
use std::ptr::null_mut;

use libc::{mmap, munmap, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};

use crate::ffi;
use crate::hv::arch::Reg;
use crate::hv::kvm::bindings::{KvmRun, KVM_EXIT_IO, KVM_EXIT_MMIO};
use crate::hv::kvm::ioctls::kvm_run;
#[cfg(target_arch = "x86_64")]
use crate::hv::{Cpuid, DtReg, DtRegVal, SReg, SegReg, SegRegVal};
use crate::hv::{Error, Vcpu, VmEntry, VmExit};

use super::bindings::KVM_EXIT_SHUTDOWN;

pub(super) struct KvmRunBlock {
    addr: usize,
    size: usize,
}

impl KvmRunBlock {
    pub unsafe fn new(fd: RawFd, mmap_size: usize) -> Result<KvmRunBlock, Error> {
        let prot = PROT_READ | PROT_WRITE;
        let addr = ffi!(
            unsafe { mmap(null_mut(), mmap_size, prot, MAP_SHARED, fd, 0,) },
            MAP_FAILED
        )?;
        Ok(KvmRunBlock {
            addr: addr as usize,
            size: mmap_size,
        })
    }

    pub(super) unsafe fn data_slice<T>(&self, offset: usize, count: usize) -> &[T] {
        std::slice::from_raw_parts((self.addr + offset) as *const T, count)
    }

    pub(super) unsafe fn data_slice_mut<T>(&mut self, offset: usize, count: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut((self.addr + offset) as *mut T, count)
    }
}

impl Deref for KvmRunBlock {
    type Target = KvmRun;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.addr as *const Self::Target) }
    }
}

impl DerefMut for KvmRunBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.addr as *mut Self::Target) }
    }
}

impl Drop for KvmRunBlock {
    fn drop(&mut self) {
        if let Err(e) = ffi!(unsafe { munmap(self.addr as _, self.size) }) {
            log::error!("unmap kvm_run: {}", e)
        }
    }
}

pub struct KvmVcpu {
    pub(super) kvm_run: KvmRunBlock,
    pub(super) fd: OwnedFd,
}

impl Vcpu for KvmVcpu {
    fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        self.kvm_get_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        self.kvm_get_dt_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        self.kvm_get_seg_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        self.kvm_get_sreg(reg)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        self.kvm_set_regs(vals)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        self.kvm_set_sregs(sregs, seg_regs, dt_regs)
    }

    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
        match entry {
            VmEntry::None => {}
            VmEntry::Io { data } => self.entry_io(data),
            VmEntry::Mmio { data } => self.entry_mmio(data),
            VmEntry::Shutdown => self.immediate_exit(),
        };
        let ret = unsafe { kvm_run(&self.fd) };
        match ret {
            Err(e) => match (e.kind(), entry) {
                (ErrorKind::WouldBlock, _) => Ok(VmExit::Interrupted),
                (ErrorKind::Interrupted, VmEntry::Shutdown) => Ok(VmExit::Shutdown),
                (ErrorKind::Interrupted, _) => Ok(VmExit::Interrupted),
                _ => Err(e.into()),
            },
            Ok(_) => match self.kvm_run.exit_reason {
                KVM_EXIT_IO => self.handle_io(),
                KVM_EXIT_MMIO => self.handle_mmio(),
                KVM_EXIT_SHUTDOWN => Ok(VmExit::Shutdown),
                reason => Ok(VmExit::Unknown(format!("unkown kvm exit: {:#x}", reason))),
            },
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        self.kvm_set_cpuids(cpuids)
    }

    fn dump(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use std::mem::size_of_val;
    use std::ptr::null_mut;

    use libc::{mmap, MAP_ANONYMOUS, MAP_FAILED, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE};

    #[cfg(target_arch = "x86_64")]
    use crate::arch::msr::Efer;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::paging::Entry;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::reg::SegAccess;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::reg::{Cr0, Cr4};
    use crate::ffi;
    use crate::hv::arch::Reg;
    #[cfg(target_arch = "x86_64")]
    use crate::hv::{DtReg, DtRegVal, SReg, SegReg, SegRegVal};
    use crate::hv::{Hypervisor, Kvm, MemMapOption, Vcpu, Vm, VmEntry, VmExit, VmMemory};

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_vcpu_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
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
            (SReg::Cr0, 1 << 0 | 1 << 5 | 1 << 31),
            (SReg::Cr2, 0xffff88ac93e00000),
            (SReg::Cr3, 0x1362d001),
            (SReg::Cr4, 1 << 5),
            (SReg::Cr8, 0x0),
            (SReg::Efer, 1 << 8 | 1 << 10),
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
    #[cfg(target_arch = "x86_64")]
    fn test_kvm_run() {
        let kvm = Kvm::new().unwrap();
        let mut vm = kvm.create_vm().unwrap();
        let memory = vm.create_vm_memory().unwrap();

        let prot = PROT_WRITE | PROT_EXEC | PROT_READ;
        let flag = MAP_ANONYMOUS | MAP_SHARED;
        let user_mem = ffi!(
            unsafe { mmap(null_mut(), 0x4000, prot, flag, -1, 0,) },
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
            .mem_map(0, 0, 0x4000, user_mem as usize, mmap_option)
            .unwrap();

        // layout
        // 0x1000 - 0x1f00 code
        // 0x1f00 - 0x2000 GDT
        // 0x2000 - 0x3000 PML4
        // 0x3000 - 0x4000 PDPT

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
        let ptpte = (Entry::P | Entry::RW | Entry::PS).bits() as u64;
        unsafe { ((user_mem as usize + 0x3000) as *mut u64).write(ptpte) }

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
            vcpu.run(VmEntry::Io { data: 0x10 }),
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
}
