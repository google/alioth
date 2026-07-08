// Copyright 2026 Google LLC
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

use std::iter::zip;
use std::sync::atomic::Ordering;

use zerocopy::FromZeros;

use crate::arch::layout::MEM_64_START;
use crate::arch::reg::{Reg, SegAccess, SegReg, SegRegVal};
use crate::arch::sev::{SevPolicy, SnpPageType};
use crate::cpu::{Result, VcpuThread};
use crate::firmware::ovmf::sev::{
    SevDescType, SevMetadataDesc, SnpCpuidFunc, SnpCpuidInfo, parse_desc, parse_sev_ap_eip,
};
use crate::hv::{Vcpu, Vm};
use crate::mem::mapped::ArcMemPages;

impl<V> VcpuThread<V>
where
    V: Vm,
{
    fn fill_snp_cpuid(&self, entries: &mut [SnpCpuidFunc]) {
        for ((in_, out), dst) in zip(self.ctx.board.arch.cpuids.iter(), entries.iter_mut()) {
            dst.eax_in = in_.func;
            dst.ecx_in = in_.index.unwrap_or(0);
            dst.eax = out.eax;
            dst.ebx = out.ebx;
            dst.ecx = out.ecx;
            dst.edx = out.edx;
            if dst.eax_in == 0xd && (dst.ecx_in == 0x0 || dst.ecx_in == 0x1) {
                dst.ebx = 0x240;
                dst.xcr0_in = 1;
                dst.xss_in = 0;
            }
        }
    }

    fn parse_sev_ap_eip(&self, data: &[u8]) -> Result<()> {
        let ap_eip = parse_sev_ap_eip(data)?;
        let sev_ap_eip = &self.ctx.board.arch.sev_ap_eip;
        sev_ap_eip.store(ap_eip, Ordering::Release);
        Ok(())
    }

    fn update_snp_desc(&self, desc: &SevMetadataDesc) -> Result<()> {
        let mut cpuid_table = SnpCpuidInfo::new_zeroed();
        let ram_bus = self.ctx.board.memory.ram_bus();
        let ram = ram_bus.lock_layout();
        let page_type = match desc.type_ {
            SevDescType::SNP_DESC_MEM => SnpPageType::UNMEASURED,
            SevDescType::SNP_SECRETS => SnpPageType::SECRETS,
            SevDescType::CPUID => {
                assert!(desc.len as usize >= size_of::<SnpCpuidInfo>());
                assert!(cpuid_table.entries.len() >= self.ctx.board.arch.cpuids.len());
                cpuid_table.count = self.ctx.board.arch.cpuids.len() as u32;
                self.fill_snp_cpuid(&mut cpuid_table.entries);
                ram.write_t(desc.base as _, &cpuid_table)?;
                SnpPageType::CPUID
            }
            _ => SnpPageType::ZERO,
        };
        let range_ref = ram.get_slice::<u8>(desc.base as u64, desc.len as u64)?;
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(range_ref.as_ptr() as _, range_ref.len()) };
        let memory = &self.ctx.board.memory;
        memory.mark_private_memory(desc.base as _, desc.len as _, true)?;
        let vm = &self.ctx.board.vm;
        let ret = vm.snp_launch_update(bytes, desc.base as _, page_type);
        if ret.is_err() && desc.type_ == SevDescType::CPUID {
            let updated_cpuid: SnpCpuidInfo = ram.read_t(desc.base as _)?;
            for (set, got) in zip(&cpuid_table.entries, &updated_cpuid.entries) {
                if set != got {
                    log::error!("set {set:#x?}, but firmware expects {got:#x?}");
                }
            }
        }
        ret?;
        Ok(())
    }

    pub(crate) fn setup_sev(&self, fw: &mut ArcMemPages, policy: SevPolicy) -> Result<()> {
        let board = &self.ctx.board;

        board.memory.register_encrypted_pages(fw)?;

        let data = fw.as_slice_mut();
        if policy.es() {
            self.parse_sev_ap_eip(data)?;
        }
        self.ctx.board.vm.sev_launch_update_data(data)?;
        Ok(())
    }

    pub(crate) fn setup_snp(&self, fw: &mut ArcMemPages) -> Result<()> {
        let memory = &self.ctx.board.memory;
        memory.register_encrypted_pages(fw)?;

        let data = fw.as_slice_mut();
        self.parse_sev_ap_eip(data)?;
        for desc in parse_desc(data)? {
            self.update_snp_desc(desc)?;
        }
        let fw_gpa = MEM_64_START - data.len() as u64;

        memory.mark_private_memory(fw_gpa, data.len() as _, true)?;
        let vm = &self.ctx.board.vm;
        vm.snp_launch_update(data, fw_gpa, SnpPageType::NORMAL)?;
        Ok(())
    }

    pub(crate) fn sev_finalize(&self, policy: SevPolicy) -> Result<()> {
        if policy.es() {
            self.ctx.board.vm.sev_launch_update_vmsa()?;
        }
        self.ctx.board.vm.sev_launch_measure()?;
        self.ctx.board.vm.sev_launch_finish()?;
        Ok(())
    }

    pub(crate) fn snp_finalize(&self) -> Result<()> {
        self.ctx.board.vm.snp_launch_finish()?;
        Ok(())
    }

    pub(crate) fn sev_init_ap(&mut self) -> Result<()> {
        let eip = self.ctx.board.arch.sev_ap_eip.load(Ordering::Acquire);
        self.vcpu.set_regs(&[(Reg::Rip, eip as u64 & 0xffff)])?;
        self.vcpu.set_sregs(
            &[],
            &[(
                SegReg::Cs,
                SegRegVal {
                    selector: 0xf000,
                    base: eip as u64 & 0xffff_0000,
                    limit: 0xffff,
                    access: SegAccess(0x9b),
                },
            )],
            &[],
        )?;
        Ok(())
    }
}
