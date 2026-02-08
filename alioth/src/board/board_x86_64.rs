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

use std::arch::x86_64::{__cpuid, CpuidResult};
use std::collections::HashMap;
use std::iter::zip;
use std::mem::{offset_of, size_of, size_of_val};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::Mutex;
use snafu::ResultExt;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use crate::arch::cpuid::CpuidIn;
use crate::arch::layout::{
    BIOS_DATA_END, EBDA_END, EBDA_START, IOAPIC_START, MEM_64_START, PORT_ACPI_RESET,
    PORT_ACPI_SLEEP_CONTROL, RAM_32_SIZE,
};
use crate::arch::msr::{IA32_MISC_ENABLE, MiscEnable};
use crate::arch::reg::{Reg, SegAccess, SegReg, SegRegVal};
use crate::arch::sev::SnpPageType;
use crate::board::{Board, BoardConfig, CpuTopology, PCIE_MMIO_64_SIZE, Result, VcpuGuard, error};
use crate::device::ioapic::IoApic;
use crate::firmware::acpi::bindings::{
    AcpiTableFadt, AcpiTableHeader, AcpiTableRsdp, AcpiTableXsdt3,
};
use crate::firmware::acpi::reg::{FadtReset, FadtSleepControl};
use crate::firmware::acpi::{
    AcpiTable, create_fadt, create_madt, create_mcfg, create_rsdp, create_xsdt,
};
use crate::firmware::ovmf::parse_data;
use crate::firmware::ovmf::sev::{
    GUID_SEV_ES_RESET_BLOCK, GUID_SEV_METADATA, SevDescType, SevMetaData, SevMetadataDesc,
    SnpCpuidFunc, SnpCpuidInfo,
};
use crate::hv::{Coco, Hypervisor, Vcpu, Vm};
use crate::loader::{Executable, InitState, Payload, firmware};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{MemRange, MemRegion, MemRegionEntry, MemRegionType};
use crate::utils::wrapping_sum;

pub struct ArchBoard<V>
where
    V: Vm,
{
    cpuids: HashMap<CpuidIn, CpuidResult>,
    sev_ap_eip: AtomicU32,
    pub(crate) io_apic: Arc<IoApic<V::MsiSender>>,
}

fn add_topology(cpuids: &mut HashMap<CpuidIn, CpuidResult>, func: u32, levels: &[(u8, u16)]) {
    let edx = 0; // patched later in init_vcpu()
    for (index, (level, count)) in levels.iter().chain(&[(0, 0)]).enumerate() {
        let eax = count.next_power_of_two().trailing_zeros();
        let ebx = *count as u32;
        let ecx = ((*level as u32) << 8) | (index as u32);
        cpuids.insert(
            CpuidIn {
                func,
                index: Some(index as u32),
            },
            CpuidResult { eax, ebx, ecx, edx },
        );
    }
}

impl<V: Vm> ArchBoard<V> {
    pub fn new<H>(hv: &H, vm: &V, config: &BoardConfig) -> Result<Self>
    where
        H: Hypervisor<Vm = V>,
    {
        let mut cpuids = hv.get_supported_cpuids()?;

        let threads_per_core = 1 + config.cpu.topology.smt as u16;
        let threads_per_socket = config.cpu.topology.cores * threads_per_core;

        add_topology(
            &mut cpuids,
            0xb,
            &[(1, threads_per_core), (2, threads_per_socket)],
        );

        let leaf0 = CpuidIn {
            func: 0,
            index: None,
        };
        let Some(out) = cpuids.get_mut(&leaf0) else {
            return error::MissingCpuid { leaf: leaf0 }.fail();
        };
        let vendor = [out.ebx, out.edx, out.ecx];
        match vendor.as_bytes() {
            b"GenuineIntel" => add_topology(
                &mut cpuids,
                0x1f,
                &[(1, threads_per_core), (2, threads_per_socket)],
            ),
            b"AuthenticAMD" => add_topology(
                &mut cpuids,
                0x8000_0026,
                &[
                    (1, threads_per_core),
                    (2, threads_per_socket),
                    (3, threads_per_socket),
                    (4, threads_per_socket),
                ],
            ),
            _ => {}
        }

        let leaf1 = CpuidIn {
            func: 0x1,
            index: None,
        };
        let Some(out) = cpuids.get_mut(&leaf1) else {
            return error::MissingCpuid { leaf: leaf1 }.fail();
        };
        out.ecx |= (1 << 24) | (1 << 31);

        let leaf_8000_0000 = unsafe { __cpuid(0x8000_0000) };
        cpuids.insert(
            CpuidIn {
                func: 0x8000_0000,
                index: None,
            },
            leaf_8000_0000,
        );
        // 0x8000_0002 to 0x8000_0004: processor name
        // 0x8000_0005: L1 cache/LTB
        // 0x8000_0006: L2 cache/TLB and L3 cache
        for func in 0x8000_0002..=0x8000_0006 {
            let host_cpuid = unsafe { __cpuid(func) };
            cpuids.insert(CpuidIn { func, index: None }, host_cpuid);
        }

        if matches!(
            &config.coco,
            Some(Coco::AmdSev { .. } | Coco::AmdSnp { .. })
        ) {
            // AMD Volume 3, section E.4.17.
            let leaf = CpuidIn {
                func: 0x8000_001f,
                index: None,
            };
            let Some(out) = cpuids.get_mut(&leaf) else {
                return error::MissingCpuid { leaf }.fail();
            };
            let host_ebx = unsafe { __cpuid(leaf.func) }.ebx;
            // set PhysAddrReduction to 1
            out.ebx = (1 << 6) | (host_ebx & 0x3f);
            out.ecx = 0;
            out.edx = 0;
            if let Some(Coco::AmdSev { policy }) = &config.coco {
                out.eax = if policy.es() { 0x2 | 0x8 } else { 0x2 };
            } else if let Some(Coco::AmdSnp { .. }) = &config.coco {
                out.eax = 0x2 | 0x8 | 0x10;
            }
        }

        Ok(Self {
            cpuids,
            sev_ap_eip: AtomicU32::new(0),
            io_apic: Arc::new(IoApic::new(vm.create_msi_sender()?)),
        })
    }
}

fn encode_x2apic_id(topology: &CpuTopology, index: u16) -> u32 {
    let (socket_id, core_id, thread_id) = topology.encode(index);

    let thread_width = topology.smt as u32;
    let cores_per_socket = topology.cores as u32;
    let core_width = cores_per_socket.next_power_of_two().trailing_zeros();

    (socket_id as u32) << (core_width + thread_width)
        | (core_id as u32) << thread_width
        | (thread_id as u32)
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn encode_cpu_identity(&self, index: u16) -> u64 {
        encode_x2apic_id(&self.config.cpu.topology, index) as u64
    }

    fn fill_snp_cpuid(&self, entries: &mut [SnpCpuidFunc]) {
        for ((in_, out), dst) in zip(self.arch.cpuids.iter(), entries.iter_mut()) {
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

    fn parse_sev_es_ap(&self, coco: &Coco, fw: &ArcMemPages) {
        match coco {
            Coco::AmdSev { policy } if policy.es() => {}
            Coco::AmdSnp { .. } => {}
            _ => return,
        }
        let ap_eip = parse_data(fw.as_slice(), &GUID_SEV_ES_RESET_BLOCK).unwrap();
        let ap_eip = u32::read_from_bytes(ap_eip).unwrap();
        self.arch.sev_ap_eip.store(ap_eip, Ordering::Release);
    }

    fn update_snp_desc(&self, offset: usize, fw_range: &mut [u8]) -> Result<()> {
        let mut cpuid_table = SnpCpuidInfo::new_zeroed();
        let ram_bus = self.memory.ram_bus();
        let ram = ram_bus.lock_layout();
        let (desc, _) = SevMetadataDesc::read_from_prefix(&fw_range[offset..]).unwrap();
        let snp_page_type = match desc.type_ {
            SevDescType::SNP_DESC_MEM => SnpPageType::Unmeasured,
            SevDescType::SNP_SECRETS => SnpPageType::Secrets,
            SevDescType::CPUID => {
                assert!(desc.len as usize >= size_of::<SnpCpuidInfo>());
                assert!(cpuid_table.entries.len() >= self.arch.cpuids.len());
                cpuid_table.count = self.arch.cpuids.len() as u32;
                self.fill_snp_cpuid(&mut cpuid_table.entries);
                ram.write_t(desc.base as _, &cpuid_table)?;
                SnpPageType::Cpuid
            }
            _ => unimplemented!(),
        };
        let range_ref = ram.get_slice::<u8>(desc.base as u64, desc.len as u64)?;
        let range_bytes =
            unsafe { std::slice::from_raw_parts_mut(range_ref.as_ptr() as _, range_ref.len()) };
        self.memory
            .mark_private_memory(desc.base as _, desc.len as _, true)?;
        let mut ret = self
            .vm
            .snp_launch_update(range_bytes, desc.base as _, snp_page_type);
        if ret.is_err() && desc.type_ == SevDescType::CPUID {
            let updated_cpuid: SnpCpuidInfo = ram.read_t(desc.base as _)?;
            for (set, got) in zip(cpuid_table.entries.iter(), updated_cpuid.entries.iter()) {
                if set != got {
                    log::error!("set {set:#x?}, but firmware expects {got:#x?}");
                }
            }
            ram.write_t(desc.base as _, &updated_cpuid)?;
            ret = self
                .vm
                .snp_launch_update(range_bytes, desc.base as _, snp_page_type);
        }
        ret?;
        Ok(())
    }

    fn setup_fw_cfg(&self, payload: &Payload) -> Result<()> {
        let Some(dev) = &*self.fw_cfg.lock() else {
            return Ok(());
        };
        let mut dev = dev.lock();
        if let Some(Executable::Linux(image)) = &payload.executable {
            dev.add_kernel_data(image).context(error::Firmware)?;
        };
        if let Some(cmdline) = &payload.cmdline {
            dev.add_kernel_cmdline(cmdline.to_owned());
        };
        if let Some(initramfs) = &payload.initramfs {
            dev.add_initramfs_data(initramfs).context(error::Firmware)?;
        };
        Ok(())
    }

    fn setup_coco(&self, fw: &mut ArcMemPages) -> Result<()> {
        let Some(coco) = &self.config.coco else {
            return Ok(());
        };
        self.memory.register_encrypted_pages(fw)?;
        self.parse_sev_es_ap(coco, fw);
        match coco {
            Coco::AmdSev { .. } => {
                self.vm.sev_launch_update_data(fw.as_slice_mut())?;
            }
            Coco::AmdSnp { .. } => {
                let fw_range = fw.as_slice_mut();
                let metadata_offset_r = parse_data(fw_range, &GUID_SEV_METADATA).unwrap();
                let metadata_offset =
                    fw_range.len() - u32::read_from_bytes(metadata_offset_r).unwrap() as usize;
                let (metadata, _) =
                    SevMetaData::read_from_prefix(&fw_range[metadata_offset..]).unwrap();
                let desc_offset = metadata_offset + size_of::<SevMetaData>();
                for i in 0..metadata.num_desc as usize {
                    let offset = desc_offset + i * size_of::<SevMetadataDesc>();
                    self.update_snp_desc(offset, fw_range)?;
                }
                let fw_gpa = MEM_64_START - fw_range.len() as u64;
                self.memory
                    .mark_private_memory(fw_gpa, fw_range.len() as _, true)?;
                self.vm
                    .snp_launch_update(fw_range, fw_gpa, SnpPageType::Normal)
                    .unwrap();
            }
            Coco::IntelTdx { attr } => todo!("Intel TDX {attr:?}"),
        }
        Ok(())
    }

    pub fn setup_firmware(&self, fw: &Path, payload: &Payload) -> Result<InitState> {
        let (init_state, mut rom) = firmware::load(&self.memory, fw)?;
        self.setup_coco(&mut rom)?;
        self.setup_fw_cfg(payload)?;
        Ok(init_state)
    }

    pub fn init_ap(&self, index: u16, vcpu: &mut V::Vcpu, vcpus: &VcpuGuard) -> Result<()> {
        match &self.config.coco {
            Some(Coco::AmdSev { policy }) if policy.es() => {}
            Some(Coco::AmdSnp { .. }) => {}
            _ => return Ok(()),
        }
        self.sync_vcpus(vcpus)?;
        if index == 0 {
            return Ok(());
        }
        let eip = self.arch.sev_ap_eip.load(Ordering::Acquire);
        vcpu.set_regs(&[(Reg::Rip, eip as u64 & 0xffff)])?;
        vcpu.set_sregs(
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

    pub fn init_boot_vcpu(&self, vcpu: &mut V::Vcpu, init_state: &InitState) -> Result<()> {
        vcpu.set_sregs(&init_state.sregs, &init_state.seg_regs, &init_state.dt_regs)?;
        vcpu.set_regs(&init_state.regs)?;
        Ok(())
    }

    pub fn init_vcpu(&self, index: u16, vcpu: &mut V::Vcpu) -> Result<()> {
        let mut cpuids = self.arch.cpuids.clone();
        let apic_id = self.encode_cpu_identity(index) as u32;
        for (in_, out) in &mut cpuids {
            if in_.func == 0x1 {
                out.ebx &= 0x00ff_ffff;
                out.ebx |= apic_id << 24;
            } else if in_.func == 0xb || in_.func == 0x1f || in_.func == 0x80000026 {
                out.edx = apic_id;
            }
        }
        vcpu.set_cpuids(cpuids)?;
        vcpu.set_msrs(&[(IA32_MISC_ENABLE, MiscEnable::FAST_STRINGS.bits())])?;
        Ok(())
    }

    pub fn reset_vcpu(&self, _index: u16, _vcpu: &mut V::Vcpu) -> Result<()> {
        Ok(())
    }

    pub fn create_ram(&self) -> Result<()> {
        let config = &self.config;
        let memory = &self.memory;

        let low_mem_size = std::cmp::min(config.mem.size, RAM_32_SIZE);
        let pages_low = self.create_ram_pages(low_mem_size, c"ram-low")?;
        let region_low = MemRegion {
            ranges: vec![MemRange::Ram(pages_low.clone())],
            entries: vec![
                MemRegionEntry {
                    size: BIOS_DATA_END,
                    type_: MemRegionType::Reserved,
                },
                MemRegionEntry {
                    size: EBDA_START - BIOS_DATA_END,
                    type_: MemRegionType::Ram,
                },
                MemRegionEntry {
                    size: EBDA_END - EBDA_START,
                    type_: MemRegionType::Acpi,
                },
                MemRegionEntry {
                    size: low_mem_size - EBDA_END,
                    type_: MemRegionType::Ram,
                },
            ],
            callbacks: Mutex::new(vec![]),
        };
        memory.add_region(0, Arc::new(region_low))?;
        if let Some(coco) = &self.config.coco {
            memory.register_encrypted_pages(&pages_low)?;
            if let Coco::AmdSnp { .. } = coco {
                memory.mark_private_memory(0, low_mem_size as _, true)?;
            }
        }
        if config.mem.size > RAM_32_SIZE {
            let mem_hi_size = config.mem.size - RAM_32_SIZE;
            let mem_hi = self.create_ram_pages(mem_hi_size, c"ram-high")?;
            let region_hi = MemRegion::with_ram(mem_hi.clone(), MemRegionType::Ram);
            memory.add_region(MEM_64_START, Arc::new(region_hi))?;
            if let Some(coco) = &self.config.coco {
                memory.register_encrypted_pages(&mem_hi)?;
                if let Coco::AmdSnp { .. } = coco {
                    memory.mark_private_memory(MEM_64_START as _, mem_hi_size as _, true)?;
                }
            }
        }
        Ok(())
    }

    pub fn coco_init(&self, index: u16) -> Result<()> {
        if index != 0 {
            return Ok(());
        }
        if let Some(coco) = &self.config.coco {
            match coco {
                Coco::AmdSev { policy } => self.vm.sev_launch_start(*policy)?,
                Coco::AmdSnp { policy } => self.vm.snp_launch_start(*policy)?,
                Coco::IntelTdx { attr } => todo!("Intel TDX {attr:?}"),
            }
        }
        Ok(())
    }

    pub fn coco_finalize(&self, index: u16, vcpus: &VcpuGuard) -> Result<()> {
        if let Some(coco) = &self.config.coco {
            self.sync_vcpus(vcpus)?;
            if index == 0 {
                match coco {
                    Coco::AmdSev { policy } => {
                        if policy.es() {
                            self.vm.sev_launch_update_vmsa()?;
                        }
                        self.vm.sev_launch_measure()?;
                        self.vm.sev_launch_finish()?;
                    }
                    Coco::AmdSnp { .. } => {
                        self.vm.snp_launch_finish()?;
                    }
                    Coco::IntelTdx { attr } => todo!("Intel TDX {attr:?}"),
                }
            }
            self.sync_vcpus(vcpus)?;
        }
        Ok(())
    }

    fn patch_dsdt(&self, data: &mut [u8; 352]) {
        let pcie_mmio_64_start = self.config.pcie_mmio_64_start();
        let pcei_mmio_64_max = pcie_mmio_64_start - 1 + PCIE_MMIO_64_SIZE;
        data[DSDT_OFFSET_PCI_QWORD_MEM..(DSDT_OFFSET_PCI_QWORD_MEM + 8)]
            .copy_from_slice(&pcie_mmio_64_start.to_le_bytes());
        data[(DSDT_OFFSET_PCI_QWORD_MEM + 8)..(DSDT_OFFSET_PCI_QWORD_MEM + 16)]
            .copy_from_slice(&pcei_mmio_64_max.to_le_bytes());
        let sum = wrapping_sum(&*data);
        let checksum = &mut data[offset_of!(AcpiTableHeader, checksum)];
        *checksum = checksum.wrapping_sub(sum);
    }

    fn create_acpi(&self) -> AcpiTable {
        let mut table_bytes = Vec::new();
        let mut pointers = vec![];
        let mut checksums = vec![];

        let mut xsdt: AcpiTableXsdt3 = AcpiTableXsdt3::new_zeroed();
        let offset_xsdt = 0;
        table_bytes.extend(xsdt.as_bytes());

        let offset_dsdt = offset_xsdt + size_of_val(&xsdt);
        let mut dsdt = DSDT_TEMPLATE;
        self.patch_dsdt(&mut dsdt);
        table_bytes.extend(dsdt);

        let offset_fadt = offset_dsdt + size_of_val(&DSDT_TEMPLATE);
        debug_assert_eq!(offset_fadt % 4, 0);
        let fadt = create_fadt(offset_dsdt as u64);
        let pointer_fadt_to_dsdt = offset_fadt + offset_of!(AcpiTableFadt, xdsdt);
        table_bytes.extend(fadt.as_bytes());
        pointers.push(pointer_fadt_to_dsdt);
        checksums.push((offset_fadt, size_of_val(&fadt)));

        let offset_madt = offset_fadt + size_of_val(&fadt);
        debug_assert_eq!(offset_madt % 4, 0);
        let apic_ids: Vec<u32> = (0..self.config.cpu.count)
            .map(|index| self.encode_cpu_identity(index) as u32)
            .collect();
        let (madt, madt_ioapic, madt_apics) = create_madt(&apic_ids);
        table_bytes.extend(madt.as_bytes());
        table_bytes.extend(madt_ioapic.as_bytes());
        for apic in madt_apics {
            table_bytes.extend(apic.as_bytes());
        }

        let offset_mcfg = offset_madt + madt.header.length as usize;
        debug_assert_eq!(offset_mcfg % 4, 0);
        let mcfg = create_mcfg();
        table_bytes.extend(mcfg.as_bytes());

        debug_assert_eq!(offset_xsdt % 4, 0);
        let xsdt_entries = [offset_fadt as u64, offset_madt as u64, offset_mcfg as u64];
        xsdt = create_xsdt(xsdt_entries);
        xsdt.write_to_prefix(&mut table_bytes).unwrap();
        for index in 0..xsdt_entries.len() {
            pointers.push(offset_xsdt + offset_of!(AcpiTableXsdt3, entries) + index * 8);
        }
        checksums.push((offset_xsdt, size_of_val(&xsdt)));

        let rsdp = create_rsdp(offset_xsdt as u64);

        AcpiTable {
            rsdp,
            tables: table_bytes,
            table_checksums: checksums,
            table_pointers: pointers,
        }
    }

    pub fn create_firmware_data(&self, _init_state: &InitState) -> Result<()> {
        let mut acpi_table = self.create_acpi();
        let memory = &self.memory;
        memory.add_io_dev(PORT_ACPI_RESET, Arc::new(FadtReset))?;
        memory.add_io_dev(PORT_ACPI_SLEEP_CONTROL, Arc::new(FadtSleepControl))?;
        if self.config.coco.is_none() {
            let ram = memory.ram_bus();
            acpi_table.relocate(EBDA_START + size_of::<AcpiTableRsdp>() as u64);
            ram.write_range(
                EBDA_START,
                size_of::<AcpiTableRsdp>() as u64,
                acpi_table.rsdp().as_bytes(),
            )?;
            ram.write_range(
                EBDA_START + size_of::<AcpiTableRsdp>() as u64,
                acpi_table.tables().len() as u64,
                acpi_table.tables(),
            )?;
        }
        if let Some(fw_cfg) = &*self.fw_cfg.lock() {
            let mut dev = fw_cfg.lock();
            dev.add_acpi(acpi_table).context(error::Firmware)?;
            let mem_regions = memory.mem_region_entries();
            dev.add_e820(&mem_regions).context(error::Firmware)?;
        }
        Ok(())
    }

    pub fn arch_init(&self) -> Result<()> {
        let io_apic = self.arch.io_apic.clone();
        self.mmio_devs.write().push((IOAPIC_START, io_apic));
        Ok(())
    }
}

const DSDT_TEMPLATE: [u8; 352] = [
    0x44, 0x53, 0x44, 0x54, 0x5D, 0x01, 0x00, 0x00, 0x02, 0x5D, 0x41, 0x4C, 0x49, 0x4F, 0x54, 0x48,
    0x41, 0x4C, 0x49, 0x4F, 0x54, 0x48, 0x56, 0x4D, 0x01, 0x00, 0x00, 0x00, 0x49, 0x4E, 0x54, 0x4C,
    0x28, 0x06, 0x23, 0x20, 0x5B, 0x82, 0x37, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x43, 0x4F, 0x4D, 0x31,
    0x08, 0x5F, 0x48, 0x49, 0x44, 0x0C, 0x41, 0xD0, 0x05, 0x01, 0x08, 0x5F, 0x55, 0x49, 0x44, 0x01,
    0x08, 0x5F, 0x53, 0x54, 0x41, 0x0A, 0x0F, 0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x10, 0x0A, 0x0D,
    0x47, 0x01, 0xF8, 0x03, 0xF8, 0x03, 0x00, 0x08, 0x22, 0x10, 0x00, 0x79, 0x00, 0x08, 0x5F, 0x53,
    0x35, 0x5F, 0x12, 0x04, 0x01, 0x0A, 0x05, 0x5B, 0x82, 0x44, 0x0F, 0x2E, 0x5F, 0x53, 0x42, 0x5F,
    0x50, 0x43, 0x49, 0x30, 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0C, 0x41, 0xD0, 0x0A, 0x08, 0x08, 0x5F,
    0x43, 0x49, 0x44, 0x0C, 0x41, 0xD0, 0x0A, 0x03, 0x08, 0x5F, 0x53, 0x45, 0x47, 0x00, 0x08, 0x5F,
    0x55, 0x49, 0x44, 0x00, 0x14, 0x32, 0x5F, 0x44, 0x53, 0x4D, 0x04, 0xA0, 0x29, 0x93, 0x68, 0x11,
    0x13, 0x0A, 0x10, 0xD0, 0x37, 0xC9, 0xE5, 0x53, 0x35, 0x7A, 0x4D, 0x91, 0x17, 0xEA, 0x4D, 0x19,
    0xC3, 0x43, 0x4D, 0xA0, 0x09, 0x93, 0x6A, 0x00, 0xA4, 0x11, 0x03, 0x01, 0x21, 0xA0, 0x07, 0x93,
    0x6A, 0x0A, 0x05, 0xA4, 0x00, 0xA4, 0x00, 0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x40, 0x09, 0x0A,
    0x8C, 0x88, 0x0D, 0x00, 0x02, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x47, 0x01, 0xF8, 0x0C, 0xF8, 0x0C, 0x01, 0x08, 0x87, 0x17, 0x00, 0x00, 0x0C, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x87, 0x17, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xA0, 0xFF, 0xFF, 0xFF, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x8A, 0x2B, 0x00,
    0x00, 0x0C, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x88, 0x0D, 0x00, 0x01, 0x0C,
    0x03, 0x00, 0x00, 0x00, 0x10, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x79, 0x00, 0x00, 0x00, 0x00,
];

const DSDT_OFFSET_PCI_QWORD_MEM: usize = 0x12b;

#[cfg(test)]
#[path = "board_x86_64_test.rs"]
mod tests;
