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

use std::collections::HashMap;
use std::mem::{offset_of, size_of, size_of_val};
use std::sync::Arc;

use parking_lot::Mutex;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, transmute};

use crate::arch::layout::{
    ACPI_LIMIT, ACPI_START, DEVICE_TREE_LIMIT, DEVICE_TREE_START, GIC_DIST_START, GIC_MSI_START,
    GIC_V2_CPU_INTERFACE_START, GIC_V3_REDIST_START, IO_END, IO_START, KERNEL_IMAGE_START,
    MEM_64_START, PCIE_CONFIG_START, PCIE_MMIO_32_NON_PREFETCHABLE_END,
    PCIE_MMIO_32_NON_PREFETCHABLE_START, PCIE_MMIO_32_PREFETCHABLE_END,
    PCIE_MMIO_32_PREFETCHABLE_START, PL011_START, PL031_START, RAM_32_SIZE, RAM_32_START,
    UEFI_LIMIT, UEFI_START,
};
use crate::arch::reg::MpidrEl1;
use crate::board::{Board, BoardSpec, CpuTopology, PCIE_MMIO_64_SIZE, Result, default_acpi_header};
use crate::firmware::acpi::AcpiTable;
use crate::firmware::acpi::bindings::{
    AcpiAccessWidth, AcpiFadtArmBootFlag, AcpiFadtFlag, AcpiGenericAddress, AcpiGtdtFlag,
    AcpiIortIdMapping, AcpiIortItsGroup1, AcpiIortMemoryAccess, AcpiIortNode, AcpiIortNodeType,
    AcpiIortRootComplex1, AcpiMadtGenericDistributor, AcpiMadtGenericInterrupt,
    AcpiMadtGenericMsiFrame, AcpiMadtGenericRedistributor, AcpiMadtGenericTranslator,
    AcpiMadtGiccFlag, AcpiMadtType, AcpiPpttFlag, AcpiPpttProcessor, AcpiPpttType, AcpiSignature,
    AcpiSpaceId, AcpiSpcrInterruptType, AcpiSubtableHeader, AcpiTableFadt, AcpiTableGtdt,
    AcpiTableHeader, AcpiTableIort, AcpiTableMadt, AcpiTablePptt, AcpiTableRsdp, AcpiTableSpcr,
    AcpiTableXsdt6, AcpiTableXsdt7, FADT_MAJOR_VERSION, FADT_MINOR_VERSION, GTDT_REVISION,
    IORT_REVISION, MADT_REVISION, PPTT_REVISION, SPCR_INTERFACE_ARM_PL011, SPCR_REVISION,
    XSDT_REVISION,
};
use crate::firmware::dt::{DeviceTree, Node, PropVal};
use crate::firmware::uefi::{
    EFI_2_100_SYSTEM_TABLE_REVISION, EFI_MEMORY_DESCRIPTOR_VERSION,
    EFI_RT_PROPERTIES_TABLE_VERSION, EFI_SYSTEM_TABLE_SIGNATURE, EfiConfigTable64,
    EfiMemoryAttribute, EfiMemoryDesc, EfiMemoryType, EfiRtPropertiesTable, EfiSystemTable64,
    EfiTableHeader, GUID_ACPI_20_TABLE, GUID_EFI_RT_PROPERTIES_TABLE,
    GUID_LINUX_EFI_MEMRESERVE_TABLE, LinuxEfiMemreserve,
};
use crate::hv::{GicV2, GicV2m, GicV3, Hypervisor, Its, Vm};
use crate::loader::{Executable, InitState};
use crate::mem::{MemRange, MemRegion, MemRegionEntry, MemRegionType};
use crate::utils::wrapping_sum;

#[repr(C)]
#[derive(Debug, Clone, FromBytes, Immutable, IntoBytes)]
struct StaticUefiTables {
    systab: EfiSystemTable64,
    rt_prop: EfiRtPropertiesTable,
    fw_vendor: [u16; 8],
    memreserve: LinuxEfiMemreserve,
    config_tables: [EfiConfigTable64; 3],
}

enum Gic<V>
where
    V: Vm,
{
    V2(V::GicV2),
    V3(V::GicV3),
}

enum Msi<V>
where
    V: Vm,
{
    V2m(V::GicV2m),
    Its(V::Its),
}

pub struct ArchBoard<V>
where
    V: Vm,
{
    gic: Gic<V>,
    msi: Option<Msi<V>>,
}

impl<V: Vm> ArchBoard<V> {
    pub fn new<H>(_hv: &H, vm: &V, spec: &BoardSpec) -> Result<Self>
    where
        H: Hypervisor<Vm = V>,
    {
        let gic = match vm.create_gic_v3(GIC_DIST_START, GIC_V3_REDIST_START, spec.cpu.count) {
            Ok(v3) => Gic::V3(v3),
            Err(e) => {
                log::error!("Cannot create GIC v3: {e:?}trying v2...");
                Gic::V2(vm.create_gic_v2(GIC_DIST_START, GIC_V2_CPU_INTERFACE_START)?)
            }
        };

        let create_gic_v2m = || match vm.create_gic_v2m(GIC_MSI_START) {
            Ok(v2m) => Some(Msi::V2m(v2m)),
            Err(e) => {
                log::error!("Cannot create GIC v2m: {e:?}");
                None
            }
        };

        let msi = if matches!(gic, Gic::V3(_)) {
            match vm.create_its(GIC_MSI_START) {
                Ok(its) => Some(Msi::Its(its)),
                Err(e) => {
                    log::error!("Cannot create ITS: {e:?}trying v2m...");
                    create_gic_v2m()
                }
            }
        } else {
            create_gic_v2m()
        };

        Ok(ArchBoard { gic, msi })
    }
}

fn encode_mpidr(topology: &CpuTopology, index: u16) -> MpidrEl1 {
    let (socket_id, core_id, thread_id) = topology.encode(index);
    let mut mpidr = MpidrEl1(0);
    mpidr.set_aff0(thread_id);
    mpidr.set_aff1(core_id as u8);
    mpidr.set_aff2(socket_id);
    mpidr
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn encode_cpu_identity(&self, index: u16) -> u64 {
        encode_mpidr(&self.spec.cpu.topology, index).0
    }

    pub fn create_ram(&self) -> Result<()> {
        let mem_size = self.spec.mem.size;
        let memory = &self.memory;

        let low_mem_size = std::cmp::min(mem_size, RAM_32_SIZE);
        let pages_low = self.create_ram_pages(low_mem_size, c"ram-low")?;
        let acpi_size = KERNEL_IMAGE_START - RAM_32_START;
        let region_low = if self.spec.platform.acpi && low_mem_size > acpi_size {
            MemRegion {
                ranges: vec![MemRange::Ram(pages_low)],
                entries: vec![
                    MemRegionEntry {
                        size: acpi_size,
                        type_: MemRegionType::Acpi,
                    },
                    MemRegionEntry {
                        size: low_mem_size - acpi_size,
                        type_: MemRegionType::Ram,
                    },
                ],
                callbacks: Mutex::new(vec![]),
            }
        } else {
            MemRegion::with_ram(pages_low, MemRegionType::Ram)
        };
        memory.add_region(RAM_32_START, Arc::new(region_low))?;

        let high_mem_size = mem_size.saturating_sub(RAM_32_SIZE);
        if high_mem_size > 0 {
            let pages_high = self.create_ram_pages(high_mem_size, c"ram-high")?;
            memory.add_region(
                MEM_64_START,
                Arc::new(MemRegion::with_ram(pages_high, MemRegionType::Ram)),
            )?;
        }

        Ok(())
    }

    pub fn coco_init(&self) -> Result<()> {
        Ok(())
    }

    pub fn arch_init(&self) -> Result<()> {
        match &self.arch.gic {
            Gic::V2(v2) => v2.init(),
            Gic::V3(v3) => v3.init(),
        }?;
        match &self.arch.msi {
            Some(Msi::V2m(v2m)) => v2m.init(),
            Some(Msi::Its(its)) => its.init(),
            None => Ok(()),
        }?;
        Ok(())
    }

    fn create_xsdt6(&self, entries: [u64; 6]) -> AcpiTableXsdt6 {
        let total_length = size_of::<AcpiTableHeader>() + size_of::<u64>() * 6;
        let entries = entries.map(|e| transmute!(e));
        AcpiTableXsdt6 {
            header: AcpiTableHeader {
                signature: AcpiSignature::XSDT,
                length: total_length as u32,
                revision: XSDT_REVISION,
                ..default_acpi_header()
            },
            entries,
        }
    }

    fn create_xsdt7(&self, entries: [u64; 7]) -> AcpiTableXsdt7 {
        let total_length = size_of::<AcpiTableHeader>() + size_of::<u64>() * 7;
        let entries = entries.map(|e| transmute!(e));
        AcpiTableXsdt7 {
            header: AcpiTableHeader {
                signature: AcpiSignature::XSDT,
                length: total_length as u32,
                revision: XSDT_REVISION,
                ..default_acpi_header()
            },
            entries,
        }
    }

    fn create_fadt(&self, dsdt_addr: u64) -> AcpiTableFadt {
        AcpiTableFadt {
            header: AcpiTableHeader {
                signature: AcpiSignature::FADT,
                revision: FADT_MAJOR_VERSION,
                length: size_of::<AcpiTableFadt>() as u32,
                ..default_acpi_header()
            },
            flags: AcpiFadtFlag::HW_REDUCED_ACPI,
            arm_boot_flags: (AcpiFadtArmBootFlag::PSCI_COMPLIANT
                | AcpiFadtArmBootFlag::PSCI_USE_HVC)
                .bits(),
            minor_revision: FADT_MINOR_VERSION,
            hypervisor_id: *b"ALIOTH  ",
            xdsdt: transmute!(dsdt_addr),
            ..Default::default()
        }
    }

    fn create_madt(&self) -> (AcpiTableMadt, Vec<u8>) {
        let mut subtables = Vec::new();

        let (gic_version, cpu_base) = match self.arch.gic {
            Gic::V2(_) => (2, GIC_V2_CPU_INTERFACE_START),
            Gic::V3(_) => (3, 0),
        };
        let gicd = AcpiMadtGenericDistributor {
            header: AcpiSubtableHeader {
                r#type: AcpiMadtType::GENERIC_DISTRIBUTOR,
                length: size_of::<AcpiMadtGenericDistributor>() as u8,
            },
            base_address: transmute!(GIC_DIST_START),
            version: gic_version,
            ..Default::default()
        };
        subtables.extend_from_slice(gicd.as_bytes());

        if matches!(self.arch.gic, Gic::V3(_)) {
            let gicr = AcpiMadtGenericRedistributor {
                header: AcpiSubtableHeader {
                    r#type: AcpiMadtType::GENERIC_REDISTRIBUTOR,
                    length: size_of::<AcpiMadtGenericRedistributor>() as u8,
                },
                base_address: transmute!(GIC_V3_REDIST_START),
                length: (self.spec.cpu.count as u32) * (128 << 10),
                ..Default::default()
            };
            subtables.extend_from_slice(gicr.as_bytes());
        }

        match &self.arch.msi {
            Some(Msi::Its(_)) => {
                let its = AcpiMadtGenericTranslator {
                    header: AcpiSubtableHeader {
                        r#type: AcpiMadtType::GENERIC_TRANSLATOR,
                        length: size_of::<AcpiMadtGenericTranslator>() as u8,
                    },
                    translation_id: 0,
                    base_address: transmute!(GIC_MSI_START),
                    ..Default::default()
                };
                subtables.extend_from_slice(its.as_bytes());
            }
            Some(Msi::V2m(_)) => {
                let v2m = AcpiMadtGenericMsiFrame {
                    header: AcpiSubtableHeader {
                        r#type: AcpiMadtType::GENERIC_MSI_FRAME,
                        length: size_of::<AcpiMadtGenericMsiFrame>() as u8,
                    },
                    msi_frame_id: 0,
                    base_address: transmute!(GIC_MSI_START),
                    ..Default::default()
                };
                subtables.extend_from_slice(v2m.as_bytes());
            }
            None => {}
        }

        for index in 0..self.spec.cpu.count {
            let mpidr = self.encode_cpu_identity(index);
            let gicc = AcpiMadtGenericInterrupt {
                header: AcpiSubtableHeader {
                    r#type: AcpiMadtType::GENERIC_INTERRUPT,
                    length: size_of::<AcpiMadtGenericInterrupt>() as u8,
                },
                cpu_interface_number: index as u32,
                uid: index as u32,
                flags: AcpiMadtGiccFlag::ENABLED,
                base_address: transmute!(cpu_base),
                arm_mpidr: transmute!(mpidr),
                ..Default::default()
            };
            subtables.extend_from_slice(gicc.as_bytes());
        }

        let total_length = size_of::<AcpiTableMadt>() + subtables.len();
        let mut madt = AcpiTableMadt {
            header: AcpiTableHeader {
                signature: AcpiSignature::MADT,
                length: total_length as u32,
                revision: MADT_REVISION,
                ..default_acpi_header()
            },
            address: 0,
            flags: 0,
        };
        let checksum = wrapping_sum(madt.as_bytes()).wrapping_add(wrapping_sum(&subtables));
        madt.header.checksum = 0u8.wrapping_sub(checksum);

        (madt, subtables)
    }

    fn create_gtdt(&self) -> AcpiTableGtdt {
        let flags = AcpiGtdtFlag::INTERRUPT_POLARITY_ACTIVE_LOW | AcpiGtdtFlag::ALWAYS_ON;
        let mut gtdt = AcpiTableGtdt {
            header: AcpiTableHeader {
                signature: AcpiSignature::GTDT,
                length: size_of::<AcpiTableGtdt>() as u32,
                revision: GTDT_REVISION,
                ..default_acpi_header()
            },
            counter_block_address: [u32::MAX; 2],
            secure_el1_interrupt: ppi_to_gsiv(PPI_TIMER_SECURE_EL1_PHYS),
            secure_el1_flags: flags,
            non_secure_el1_interrupt: ppi_to_gsiv(PPI_TIMER_NON_SECURE_EL1_PHYS),
            non_secure_el1_flags: flags,
            virtual_timer_interrupt: ppi_to_gsiv(PPI_TIMER_VIRTUAL_EL1),
            virtual_timer_flags: flags,
            non_secure_el2_interrupt: ppi_to_gsiv(PPI_TIMER_NON_SECURE_EL2_PHYS),
            non_secure_el2_flags: flags,
            counter_read_block_address: [u32::MAX; 2],
            virtual_el2_timer_gsiv: ppi_to_gsiv(PPI_TIMER_VIRTUAL_EL2),
            virtual_el2_timer_flags: flags,
            ..Default::default()
        };
        gtdt.header.checksum = 0u8.wrapping_sub(wrapping_sum(gtdt.as_bytes()));
        gtdt
    }

    fn create_spcr(&self) -> AcpiTableSpcr {
        let mut spcr = AcpiTableSpcr {
            header: AcpiTableHeader {
                signature: AcpiSignature::SPCR,
                length: size_of::<AcpiTableSpcr>() as u32,
                revision: SPCR_REVISION,
                ..default_acpi_header()
            },
            interface_type: SPCR_INTERFACE_ARM_PL011,
            serial_port: AcpiGenericAddress {
                space_id: AcpiSpaceId::SYSTEM_MEMORY,
                bit_width: 32,
                bit_offset: 0,
                access_width: AcpiAccessWidth::DWORD,
                address: transmute!(PL011_START),
            },
            interrupt_type: AcpiSpcrInterruptType::GIC,
            interrupt: (32u32 + 1).to_le_bytes(),
            baud_rate: 7,
            stop_bits: 1,
            flow_control: 0,
            terminal_type: 3,
            pci_device_id: 0xffff,
            pci_vendor_id: 0xffff,
            ..Default::default()
        };
        spcr.header.checksum = 0u8.wrapping_sub(wrapping_sum(spcr.as_bytes()));
        spcr
    }

    fn create_iort(&self) -> (AcpiTableIort, AcpiIortItsGroup1, AcpiIortRootComplex1) {
        let total_length = size_of::<AcpiTableIort>()
            + size_of::<AcpiIortItsGroup1>()
            + size_of::<AcpiIortRootComplex1>();
        let offset_its = size_of::<AcpiTableIort>() as u32;
        let its_group = AcpiIortItsGroup1 {
            node: AcpiIortNode {
                type_: AcpiIortNodeType::ITS_GROUP,
                length: (size_of::<AcpiIortItsGroup1>() as u16).to_le_bytes(),
                revision: 1,
                identifier: 0,
                mapping_count: 0,
                mapping_offset: 0,
            },
            its_count: 1,
            identifiers: [0],
        };
        let rc = AcpiIortRootComplex1 {
            node: AcpiIortNode {
                type_: AcpiIortNodeType::PCI_ROOT_COMPLEX,
                length: (size_of::<AcpiIortRootComplex1>() as u16).to_le_bytes(),
                revision: 4,
                identifier: 1,
                mapping_count: 1,
                mapping_offset: offset_of!(AcpiIortRootComplex1, mappings) as u32,
            },
            memory_properties: AcpiIortMemoryAccess {
                cache_coherency: 1,
                hints: 0,
                reserved: [0; 2],
                memory_flags: 0x3,
            },
            ats_attribute: 0,
            pci_segment_number: 0,
            memory_address_limit: 64,
            pasid_capabilities: [0; 2],
            reserved: 0,
            flags: 0,
            mappings: [AcpiIortIdMapping {
                input_base: 0,
                id_count: 0xffff,
                output_base: 0,
                output_reference: offset_its,
                flags: 0,
            }],
        };
        let mut iort = AcpiTableIort {
            header: AcpiTableHeader {
                signature: AcpiSignature::IORT,
                length: total_length as u32,
                revision: IORT_REVISION,
                ..default_acpi_header()
            },
            node_count: 2,
            node_offset: offset_its,
            reserved: 0,
        };
        let checksum = wrapping_sum(iort.as_bytes())
            .wrapping_add(wrapping_sum(its_group.as_bytes()))
            .wrapping_add(wrapping_sum(rc.as_bytes()));
        iort.header.checksum = 0u8.wrapping_sub(checksum);
        (iort, its_group, rc)
    }

    fn create_pptt(&self) -> (AcpiTablePptt, Vec<AcpiPpttProcessor>) {
        let topology = &self.spec.cpu.topology;
        let mut nodes = Vec::new();
        let mut current_offset = size_of::<AcpiTablePptt>() as u32;
        let node_size = size_of::<AcpiPpttProcessor>() as u32;

        for socket_id in 0..topology.sockets {
            let socket_offset = current_offset;
            nodes.push(AcpiPpttProcessor {
                header: AcpiSubtableHeader {
                    r#type: AcpiPpttType::PROCESSOR,
                    length: node_size as u8,
                },
                flags: AcpiPpttFlag::PHYSICAL_PACKAGE | AcpiPpttFlag::ACPI_IDENTICAL,
                parent: 0,
                acpi_processor_id: socket_id as u32,
                ..Default::default()
            });
            current_offset += node_size;

            for core_id in 0..topology.cores {
                if topology.smt {
                    let core_offset = current_offset;
                    nodes.push(AcpiPpttProcessor {
                        header: AcpiSubtableHeader {
                            r#type: AcpiPpttType::PROCESSOR,
                            length: node_size as u8,
                        },
                        flags: AcpiPpttFlag::ACPI_IDENTICAL,
                        parent: socket_offset,
                        acpi_processor_id: core_id as u32,
                        ..Default::default()
                    });
                    current_offset += node_size;

                    for thread_id in 0..2 {
                        let uid = topology.decode(socket_id, core_id, thread_id) as u32;
                        nodes.push(AcpiPpttProcessor {
                            header: AcpiSubtableHeader {
                                r#type: AcpiPpttType::PROCESSOR,
                                length: node_size as u8,
                            },
                            flags: AcpiPpttFlag::ACPI_PROCESSOR_ID_VALID
                                | AcpiPpttFlag::ACPI_PROCESSOR_IS_THREAD
                                | AcpiPpttFlag::ACPI_LEAF_NODE
                                | AcpiPpttFlag::ACPI_IDENTICAL,
                            parent: core_offset,
                            acpi_processor_id: uid,
                            ..Default::default()
                        });
                        current_offset += node_size;
                    }
                } else {
                    let uid = topology.decode(socket_id, core_id, 0) as u32;
                    nodes.push(AcpiPpttProcessor {
                        header: AcpiSubtableHeader {
                            r#type: AcpiPpttType::PROCESSOR,
                            length: node_size as u8,
                        },
                        flags: AcpiPpttFlag::ACPI_PROCESSOR_ID_VALID
                            | AcpiPpttFlag::ACPI_LEAF_NODE
                            | AcpiPpttFlag::ACPI_IDENTICAL,
                        parent: socket_offset,
                        acpi_processor_id: uid,
                        ..Default::default()
                    });
                    current_offset += node_size;
                }
            }
        }

        let mut pptt = AcpiTablePptt {
            header: AcpiTableHeader {
                signature: AcpiSignature::PPTT,
                length: current_offset,
                revision: PPTT_REVISION,
                ..default_acpi_header()
            },
        };
        let checksum = wrapping_sum(pptt.as_bytes()).wrapping_add(wrapping_sum(nodes.as_bytes()));
        pptt.header.checksum = 0u8.wrapping_sub(checksum);
        (pptt, nodes)
    }

    fn create_dsdt(&self) -> Vec<u8> {
        let mut dsdt = Vec::from(DSDT_TEMPLATE);
        let pcie_mmio_64_start = self.spec.pcie_mmio_64_start();
        let pcie_mmio_64_max = pcie_mmio_64_start - 1 + PCIE_MMIO_64_SIZE;
        dsdt[DSDT_OFFSET_PCI_QWORD_MEM..(DSDT_OFFSET_PCI_QWORD_MEM + 8)]
            .copy_from_slice(&pcie_mmio_64_start.to_le_bytes());
        dsdt[(DSDT_OFFSET_PCI_QWORD_MEM + 8)..(DSDT_OFFSET_PCI_QWORD_MEM + 16)]
            .copy_from_slice(&pcie_mmio_64_max.to_le_bytes());
        for index in 0..self.spec.cpu.count {
            let mut cpu_aml = AML_CPU_TEMPLATE;
            let name = format!("C{index:03X}");
            cpu_aml[8..12].copy_from_slice(name.as_bytes());
            cpu_aml[33..35].copy_from_slice(&index.to_le_bytes());
            dsdt.extend_from_slice(&cpu_aml);
        }
        let len = dsdt.len() as u32;
        let len_offset = offset_of!(AcpiTableHeader, length);
        dsdt[len_offset..(len_offset + 4)].copy_from_slice(&len.to_le_bytes());
        let checksum_offset = offset_of!(AcpiTableHeader, checksum);
        dsdt[checksum_offset] = 0;
        let sum = wrapping_sum(&dsdt);
        dsdt[checksum_offset] = 0u8.wrapping_sub(sum);
        dsdt
    }

    fn create_acpi(&self) -> AcpiTable {
        let mut table_bytes = Vec::new();
        let mut pointers = vec![];
        let mut checksums = vec![];
        let has_its = matches!(self.arch.msi, Some(Msi::Its(_)));

        let offset_xsdt = 0;
        if has_its {
            let xsdt = AcpiTableXsdt7::new_zeroed();
            table_bytes.extend(xsdt.as_bytes());
        } else {
            let xsdt = AcpiTableXsdt6::new_zeroed();
            table_bytes.extend(xsdt.as_bytes());
        }

        let offset_dsdt = table_bytes.len();
        let dsdt = self.create_dsdt();
        table_bytes.extend(dsdt);
        table_bytes.resize(table_bytes.len().next_multiple_of(4), 0);

        let offset_fadt = table_bytes.len();
        debug_assert_eq!(offset_fadt % 4, 0);
        let fadt = self.create_fadt(offset_dsdt as u64);
        let pointer_fadt_to_dsdt = offset_fadt + offset_of!(AcpiTableFadt, xdsdt);
        table_bytes.extend(fadt.as_bytes());
        pointers.push(pointer_fadt_to_dsdt);
        checksums.push((offset_fadt, size_of_val(&fadt)));

        let offset_madt = table_bytes.len();
        debug_assert_eq!(offset_madt % 4, 0);
        let (madt, madt_subtables) = self.create_madt();
        table_bytes.extend(madt.as_bytes());
        table_bytes.extend(madt_subtables);

        let offset_mcfg = table_bytes.len();
        debug_assert_eq!(offset_mcfg % 4, 0);
        let mcfg = self.create_mcfg();
        table_bytes.extend(mcfg.as_bytes());

        let offset_gtdt = table_bytes.len();
        debug_assert_eq!(offset_gtdt % 4, 0);
        let gtdt = self.create_gtdt();
        table_bytes.extend(gtdt.as_bytes());

        let offset_spcr = table_bytes.len();
        debug_assert_eq!(offset_spcr % 4, 0);
        let spcr = self.create_spcr();
        table_bytes.extend(spcr.as_bytes());

        let offset_pptt = table_bytes.len();
        debug_assert_eq!(offset_pptt % 4, 0);
        let (pptt, pptt_nodes) = self.create_pptt();
        table_bytes.extend(pptt.as_bytes());
        for node in pptt_nodes {
            table_bytes.extend(node.as_bytes());
        }

        if has_its {
            let offset_iort = table_bytes.len();
            debug_assert_eq!(offset_iort % 4, 0);
            let (iort, its_group, rc) = self.create_iort();
            table_bytes.extend(iort.as_bytes());
            table_bytes.extend(its_group.as_bytes());
            table_bytes.extend(rc.as_bytes());

            let xsdt_entries = [
                offset_fadt as u64,
                offset_madt as u64,
                offset_mcfg as u64,
                offset_gtdt as u64,
                offset_spcr as u64,
                offset_pptt as u64,
                offset_iort as u64,
            ];
            let xsdt = self.create_xsdt7(xsdt_entries);
            xsdt.write_to_prefix(&mut table_bytes).unwrap();
            for index in 0..xsdt_entries.len() {
                pointers.push(offset_xsdt + offset_of!(AcpiTableXsdt7, entries) + index * 8);
            }
            checksums.push((offset_xsdt, size_of_val(&xsdt)));
        } else {
            let xsdt_entries = [
                offset_fadt as u64,
                offset_madt as u64,
                offset_mcfg as u64,
                offset_gtdt as u64,
                offset_spcr as u64,
                offset_pptt as u64,
            ];
            let xsdt = self.create_xsdt6(xsdt_entries);
            xsdt.write_to_prefix(&mut table_bytes).unwrap();
            for index in 0..xsdt_entries.len() {
                pointers.push(offset_xsdt + offset_of!(AcpiTableXsdt6, entries) + index * 8);
            }
            checksums.push((offset_xsdt, size_of_val(&xsdt)));
        }

        let rsdp = self.create_rsdp(offset_xsdt as u64);

        AcpiTable {
            rsdp,
            tables: table_bytes,
            table_checksums: checksums,
            table_pointers: pointers,
        }
    }

    fn create_uefi(&self) -> (StaticUefiTables, Vec<EfiMemoryDesc>) {
        let tables = StaticUefiTables {
            systab: EfiSystemTable64 {
                hdr: EfiTableHeader {
                    signature: EFI_SYSTEM_TABLE_SIGNATURE,
                    revision: EFI_2_100_SYSTEM_TABLE_REVISION,
                    headersize: size_of::<EfiSystemTable64>() as u32,
                    crc32: 0,
                    reserved: 0,
                },
                fw_vendor: UEFI_START + offset_of!(StaticUefiTables, fw_vendor) as u64,
                fw_revision: 1,
                _pad: 0,
                con_in_handle: 0,
                con_in: 0,
                con_out_handle: 0,
                con_out: 0,
                stderr_handle: 0,
                stderr: 0,
                runtime: 0,
                boottime: 0,
                nr_tables: 3,
                tables: UEFI_START + offset_of!(StaticUefiTables, config_tables) as u64,
            },
            rt_prop: EfiRtPropertiesTable {
                version: EFI_RT_PROPERTIES_TABLE_VERSION,
                length: size_of::<EfiRtPropertiesTable>() as u16,
                runtime_services_supported: 0,
            },
            fw_vendor: [
                b'A' as u16,
                b'l' as u16,
                b'i' as u16,
                b'o' as u16,
                b't' as u16,
                b'h' as u16,
                0,
                0,
            ],
            memreserve: LinuxEfiMemreserve {
                size: 0,
                count: 0,
                next: 0,
            },
            config_tables: [
                EfiConfigTable64 {
                    guid: GUID_ACPI_20_TABLE,
                    table: ACPI_START,
                },
                EfiConfigTable64 {
                    guid: GUID_EFI_RT_PROPERTIES_TABLE,
                    table: UEFI_START + offset_of!(StaticUefiTables, rt_prop) as u64,
                },
                EfiConfigTable64 {
                    guid: GUID_LINUX_EFI_MEMRESERVE_TABLE,
                    table: UEFI_START + offset_of!(StaticUefiTables, memreserve) as u64,
                },
            ],
        };

        let mem_regions = self.memory.mem_region_entries();
        let mut mmap = Vec::new();
        for (start, entry) in mem_regions {
            let ty = match entry.type_ {
                MemRegionType::Ram => EfiMemoryType::CONVENTIONAL_MEMORY,
                MemRegionType::Acpi => EfiMemoryType::ACPI_RECLAIM_MEMORY,
                _ => continue,
            };
            mmap.push(EfiMemoryDesc {
                ty,
                pad: 0,
                phys_addr: start,
                virt_addr: start,
                num_pages: entry.size >> 12,
                attribute: EfiMemoryAttribute::WB,
            });
        }

        (tables, mmap)
    }

    fn create_chosen_node(
        &self,
        init_state: &InitState,
        uefi_mmap_size: Option<usize>,
        root: &mut Node,
    ) {
        let payload = self.payload.read();
        let Some(payload) = payload.as_ref() else {
            return;
        };
        if !matches!(payload.executable, Some(Executable::Linux(_))) {
            return;
        }
        let mut node = Node::default();
        if let Some(cmdline) = &payload.cmdline {
            let cmdline = cmdline.to_string();
            node.props.insert("bootargs", PropVal::String(cmdline));
        }
        if let Some(initramfs_range) = &init_state.initramfs {
            node.props
                .insert("linux,initrd-start", PropVal::U64(initramfs_range.start));
            node.props
                .insert("linux,initrd-end", PropVal::U64(initramfs_range.end));
        }
        if let Some(mmap_size) = uefi_mmap_size {
            let mmap_start = UEFI_START + size_of::<StaticUefiTables>() as u64;
            node.props
                .insert("linux,uefi-system-table", PropVal::U64(UEFI_START));
            node.props
                .insert("linux,uefi-mmap-start", PropVal::U64(mmap_start));
            node.props
                .insert("linux,uefi-mmap-size", PropVal::U32(mmap_size as u32));
            node.props.insert(
                "linux,uefi-mmap-desc-size",
                PropVal::U32(size_of::<EfiMemoryDesc>() as u32),
            );
            node.props.insert(
                "linux,uefi-mmap-desc-ver",
                PropVal::U32(EFI_MEMORY_DESCRIPTOR_VERSION),
            );
        } else {
            node.props.insert(
                "stdout-path",
                PropVal::String(format!("/pl011@{PL011_START:x}")),
            );
        }
        root.nodes.push(("chosen".to_owned(), node));
    }

    pub fn create_memory_node(&self, root: &mut Node) {
        let regions = self.memory.mem_region_entries();
        for (start, region) in regions {
            if region.type_ != MemRegionType::Ram {
                continue;
            };
            let node = Node {
                props: HashMap::from([
                    ("device_type", PropVal::Str("memory")),
                    ("reg", PropVal::U64List(vec![start, region.size])),
                ]),
                nodes: Vec::new(),
            };
            root.nodes.push((format!("memory@{start:x}"), node));
        }
    }

    pub fn create_cpu_nodes(&self, root: &mut Node) {
        let topology = &self.spec.cpu.topology;

        let thread_node = |socket_id: u8, core_id: u16, thread_id: u8| {
            let phandle = PHANDLE_CPU | topology.decode(socket_id, core_id, thread_id) as u32;
            Node {
                props: HashMap::from([("cpu", PropVal::PHandle(phandle))]),
                nodes: Vec::new(),
            }
        };
        let core_node = |socket_id: u8, core_id: u16| {
            if topology.smt {
                Node {
                    props: HashMap::new(),
                    nodes: vec![
                        ("thread0".to_owned(), thread_node(socket_id, core_id, 0)),
                        ("thread1".to_owned(), thread_node(socket_id, core_id, 1)),
                    ],
                }
            } else {
                thread_node(socket_id, core_id, 0)
            }
        };
        let socket_node = |socket_id: u8| Node {
            props: HashMap::new(),
            nodes: vec![(
                "cluster0".to_owned(),
                Node {
                    props: HashMap::new(),
                    nodes: (0..topology.cores)
                        .map(|core_id| (format!("core{core_id}"), core_node(socket_id, core_id)))
                        .collect(),
                },
            )],
        };
        let cpu_map_node = Node {
            props: HashMap::new(),
            nodes: (0..topology.sockets)
                .map(|socket_id| (format!("socket{socket_id}"), socket_node(socket_id)))
                .collect(),
        };

        let cpus_nodes = (0..(self.spec.cpu.count))
            .map(|index| {
                let mpidr = self.encode_cpu_identity(index);
                (
                    format!("cpu@{mpidr:x}"),
                    Node {
                        props: HashMap::from([
                            ("device_type", PropVal::Str("cpu")),
                            ("compatible", PropVal::Str("arm,arm-v8")),
                            ("enable-method", PropVal::Str("psci")),
                            ("reg", PropVal::U64(mpidr)),
                            ("phandle", PropVal::PHandle(PHANDLE_CPU | index as u32)),
                        ]),
                        nodes: Vec::new(),
                    },
                )
            })
            .chain([("cpu-map".to_owned(), cpu_map_node)])
            .collect();

        let cpus = Node {
            props: HashMap::from([
                ("#address-cells", PropVal::U32(2)),
                ("#size-cells", PropVal::U32(0)),
            ]),
            nodes: cpus_nodes,
        };
        root.nodes.push(("cpus".to_owned(), cpus));
    }

    fn create_clock_node(&self, root: &mut Node) {
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("fixed-clock")),
                ("clock-frequency", PropVal::U32(24000000)),
                ("clock-output-names", PropVal::Str("clk24mhz")),
                ("phandle", PropVal::PHandle(PHANDLE_CLOCK)),
                ("#clock-cells", PropVal::U32(0)),
            ]),
            nodes: Vec::new(),
        };
        root.nodes.push(("apb-pclk".to_owned(), node));
    }

    fn create_pl011_node(&self, root: &mut Node) {
        let pin = 1;
        let edge_trigger = 1;
        let spi = 0;
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("arm,primecell\0arm,pl011")),
                ("reg", PropVal::U64List(vec![PL011_START, 0x1000])),
                ("interrupts", PropVal::U32List(vec![spi, pin, edge_trigger])),
                ("clock-names", PropVal::Str("uartclk\0apb_pclk")),
                (
                    "clocks",
                    PropVal::U32List(vec![PHANDLE_CLOCK, PHANDLE_CLOCK]),
                ),
            ]),
            nodes: Vec::new(),
        };
        root.nodes.push((format!("pl011@{PL011_START:x}"), node));
    }

    fn create_pl031_node(&self, root: &mut Node) {
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("arm,primecell\0arm,pl031")),
                ("reg", PropVal::U64List(vec![PL031_START, 0x1000])),
                ("clock-names", PropVal::Str("apb_pclk")),
                ("clocks", PropVal::U32List(vec![PHANDLE_CLOCK])),
            ]),
            nodes: Vec::new(),
        };
        root.nodes.push((format!("pl031@{PL031_START:x}"), node));
    }

    // Documentation/devicetree/bindings/timer/arm,arch_timer.yaml
    fn create_timer_node(&self, root: &mut Node) {
        let mut interrupts = vec![];
        let irq_pins = [
            PPI_TIMER_SECURE_EL1_PHYS,
            PPI_TIMER_NON_SECURE_EL1_PHYS,
            PPI_TIMER_VIRTUAL_EL1,
            PPI_TIMER_NON_SECURE_EL2_PHYS,
        ];
        let ppi = 1;
        let level_trigger = 4;
        let cpu_mask = match self.arch.gic {
            Gic::V2(_) => (1 << self.spec.cpu.count) - 1,
            Gic::V3 { .. } => 0,
        };
        for pin in irq_pins {
            interrupts.extend([ppi, pin, (cpu_mask << 8) | level_trigger]);
        }
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("arm,armv8-timer")),
                ("interrupts", PropVal::U32List(interrupts)),
                ("always-on", PropVal::Empty),
            ]),
            nodes: Vec::new(),
        };
        root.nodes.push(("timer".to_owned(), node));
    }

    fn create_gic_msi_node(&self) -> Vec<(String, Node)> {
        let Some(msi) = &self.arch.msi else {
            return Vec::new();
        };
        match msi {
            Msi::Its(_) => {
                let node = Node {
                    props: HashMap::from([
                        ("compatible", PropVal::Str("arm,gic-v3-its")),
                        ("msi-controller", PropVal::Empty),
                        ("#msi-cells", PropVal::U32(1)),
                        ("reg", PropVal::U64List(vec![GIC_MSI_START, 128 << 10])),
                        ("phandle", PropVal::PHandle(PHANDLE_MSI)),
                    ]),
                    nodes: Vec::new(),
                };
                vec![(format!("its@{GIC_MSI_START:x}"), node)]
            }
            Msi::V2m(_) => {
                let node = Node {
                    props: HashMap::from([
                        ("compatible", PropVal::Str("arm,gic-v2m-frame")),
                        ("msi-controller", PropVal::Empty),
                        ("reg", PropVal::U64List(vec![GIC_MSI_START, 64 << 10])),
                        ("phandle", PropVal::PHandle(PHANDLE_MSI)),
                    ]),
                    nodes: Vec::new(),
                };
                vec![(format!("v2m@{GIC_MSI_START:x}"), node)]
            }
        }
    }

    fn create_gic_node(&self, root: &mut Node) {
        let msi = self.create_gic_msi_node();
        let node = match self.arch.gic {
            // Documentation/devicetree/bindings/interrupt-controller/arm,gic.yaml
            Gic::V2(_) => Node {
                props: HashMap::from([
                    ("compatible", PropVal::Str("arm,cortex-a15-gic")),
                    ("#interrupt-cells", PropVal::U32(3)),
                    (
                        "reg",
                        PropVal::U64List(vec![
                            GIC_DIST_START,
                            0x1000,
                            GIC_V2_CPU_INTERFACE_START,
                            0x2000,
                        ]),
                    ),
                    ("phandle", PropVal::U32(PHANDLE_GIC)),
                    ("interrupt-controller", PropVal::Empty),
                ]),
                nodes: msi,
            },
            // Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.yaml
            Gic::V3(_) => Node {
                props: HashMap::from([
                    ("compatible", PropVal::Str("arm,gic-v3")),
                    ("#interrupt-cells", PropVal::U32(3)),
                    ("#address-cells", PropVal::U32(2)),
                    ("#size-cells", PropVal::U32(2)),
                    ("interrupt-controller", PropVal::Empty),
                    ("ranges", PropVal::Empty),
                    (
                        "reg",
                        PropVal::U64List(vec![
                            GIC_DIST_START,
                            64 << 10,
                            GIC_V3_REDIST_START,
                            self.spec.cpu.count as u64 * (128 << 10),
                        ]),
                    ),
                    ("phandle", PropVal::U32(PHANDLE_GIC)),
                ]),
                nodes: msi,
            },
        };
        root.nodes.push((format!("intc@{GIC_DIST_START:x}"), node));
    }

    // Documentation/devicetree/bindings/arm/psci.yaml
    fn create_psci_node(&self, root: &mut Node) {
        let node = Node {
            props: HashMap::from([
                ("method", PropVal::Str("hvc")),
                ("compatible", PropVal::Str("arm,psci-0.2\0arm,psci")),
            ]),
            nodes: Vec::new(),
        };
        root.nodes.push(("psci".to_owned(), node));
    }

    // https://elinux.org/Device_Tree_Usage#PCI_Host_Bridge
    // Documentation/devicetree/bindings/pci/host-generic-pci.yaml
    // IEEE Std 1275-1994
    fn create_pci_bridge_node(&self, root: &mut Node) {
        let Some(max_bus) = self.pci_bus.segment.max_bus() else {
            return;
        };
        let pcie_mmio_64_start = self.spec.pcie_mmio_64_start();
        let prefetchable = 1 << 30;
        let io = 0b01 << 24;
        let mem_32 = 0b10 << 24;
        let mem_64 = 0b11 << 24;
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("pci-host-ecam-generic")),
                ("device_type", PropVal::Str("pci")),
                ("reg", PropVal::U64List(vec![PCIE_CONFIG_START, 256 << 20])),
                ("bus-range", PropVal::U32List(vec![0, max_bus as u32])),
                ("#address-cells", PropVal::U32(3)),
                ("#size-cells", PropVal::U32(2)),
                (
                    "ranges",
                    PropVal::U32List(vec![
                        io,
                        0,
                        0,
                        0,
                        IO_START as u32,
                        0,
                        (IO_END - IO_START) as u32,
                        mem_32 | prefetchable,
                        0,
                        PCIE_MMIO_32_PREFETCHABLE_START as u32,
                        0,
                        PCIE_MMIO_32_PREFETCHABLE_START as u32,
                        0,
                        (PCIE_MMIO_32_PREFETCHABLE_END - PCIE_MMIO_32_PREFETCHABLE_START) as u32,
                        mem_32,
                        0,
                        PCIE_MMIO_32_NON_PREFETCHABLE_START as u32,
                        0,
                        PCIE_MMIO_32_NON_PREFETCHABLE_START as u32,
                        0,
                        (PCIE_MMIO_32_NON_PREFETCHABLE_END - PCIE_MMIO_32_NON_PREFETCHABLE_START)
                            as u32,
                        mem_64 | prefetchable,
                        (pcie_mmio_64_start >> 32) as u32,
                        pcie_mmio_64_start as u32,
                        (pcie_mmio_64_start >> 32) as u32,
                        pcie_mmio_64_start as u32,
                        (PCIE_MMIO_64_SIZE >> 32) as u32,
                        PCIE_MMIO_64_SIZE as u32,
                    ]),
                ),
                (
                    "msi-map",
                    // Identity map from RID (BDF) to msi-specifier.
                    // Documentation/devicetree/bindings/pci/pci-msi.txt
                    PropVal::U32List(vec![0, PHANDLE_MSI, 0, 0x10000]),
                ),
            ]),
            nodes: Vec::new(),
        };
        root.nodes
            .push((format!("pci@{PCIE_CONFIG_START:x}"), node));
    }

    pub fn create_firmware_data(&self, init_state: &InitState) -> Result<()> {
        let ram = self.memory.ram_bus();
        let mut device_tree = DeviceTree::new();
        let root = &mut device_tree.root;
        root.props.insert("#address-cells", PropVal::U32(2));
        root.props.insert("#size-cells", PropVal::U32(2));

        if self.spec.platform.acpi {
            let mut acpi_table = self.create_acpi();
            let rsdp_size = size_of::<AcpiTableRsdp>();
            let tables_len = acpi_table.tables().len();
            assert!((rsdp_size + tables_len) as u64 <= ACPI_LIMIT);
            let tables_gpa = ACPI_START + rsdp_size as u64;
            acpi_table.relocate(tables_gpa);
            acpi_table.update_checksums();
            ram.write_range(ACPI_START, rsdp_size as u64, acpi_table.rsdp().as_bytes())?;
            ram.write_range(tables_gpa, tables_len as u64, acpi_table.tables())?;

            let (uefi_tables, mmap) = self.create_uefi();
            let uefi_tables_size = size_of::<StaticUefiTables>();
            let mmap_bytes = mmap.as_bytes();
            assert!((uefi_tables_size + mmap_bytes.len()) as u64 <= UEFI_LIMIT);
            let mmap_gpa = UEFI_START + uefi_tables_size as u64;
            ram.write_range(UEFI_START, uefi_tables_size as u64, uefi_tables.as_bytes())?;
            ram.write_range(mmap_gpa, mmap_bytes.len() as u64, mmap_bytes)?;

            self.create_chosen_node(init_state, Some(mmap_bytes.len()), root);
        } else {
            root.props.insert("model", PropVal::Str("linux,dummy-virt"));
            root.props
                .insert("compatible", PropVal::Str("linux,dummy-virt"));
            root.props
                .insert("interrupt-parent", PropVal::PHandle(PHANDLE_GIC));

            self.create_chosen_node(init_state, None, root);
            self.create_pl011_node(root);
            self.create_pl031_node(root);
            self.create_memory_node(root);
            self.create_cpu_nodes(root);
            self.create_gic_node(root);
            if self.arch.msi.is_some() {
                self.create_pci_bridge_node(root);
            }
            self.create_clock_node(root);
            self.create_timer_node(root);
            self.create_psci_node(root);
        }

        log::debug!("device tree: {device_tree:#x?}");
        let blob = device_tree.to_blob();
        assert!(blob.len() as u64 <= DEVICE_TREE_LIMIT);
        ram.write_range(DEVICE_TREE_START, blob.len() as u64, &*blob)?;
        Ok(())
    }
}

const PHANDLE_GIC: u32 = 1;
const PHANDLE_CLOCK: u32 = 2;
const PHANDLE_MSI: u32 = 3;
const PHANDLE_CPU: u32 = 1 << 31;

// ARMv8 Generic Timer PPI (Private Peripheral Interrupt) numbers (0-based within PPI range),
// as specified by Arm Server Base System Architecture (SBSA) and
// Documentation/devicetree/bindings/timer/arm,arch_timer.yaml.
const PPI_TIMER_NON_SECURE_EL2_PHYS: u32 = 10; // CNTHP (hyp-phys)
const PPI_TIMER_VIRTUAL_EL1: u32 = 11; // CNTV (virt)
const PPI_TIMER_VIRTUAL_EL2: u32 = 12; // CNTHV (hyp-virt, ARMv8.1 FEAT_VHE)
const PPI_TIMER_SECURE_EL1_PHYS: u32 = 13; // CNTPS (sec-phys)
const PPI_TIMER_NON_SECURE_EL1_PHYS: u32 = 14; // CNTP (phys)

// Converts a 0-based PPI index (0..16) to an ARM GIC hardware INTID / ACPI GSIV (16..32).
// In ARM GIC, INTIDs 0..16 are SGIs, 16..32 are PPIs, and 32..1020 are SPIs.
const fn ppi_to_gsiv(ppi: u32) -> u32 {
    16 + ppi
}

const DSDT_TEMPLATE: [u8; 403] = [
    0x44, 0x53, 0x44, 0x54, 0x93, 0x01, 0x00, 0x00, 0x02, 0x54, 0x41, 0x4C, 0x49, 0x4F, 0x54, 0x48,
    0x41, 0x4C, 0x49, 0x4F, 0x54, 0x48, 0x56, 0x4D, 0x01, 0x00, 0x00, 0x00, 0x49, 0x4E, 0x54, 0x4C,
    0x12, 0x12, 0x25, 0x20, 0x5B, 0x82, 0x47, 0x04, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x43, 0x4F, 0x4D,
    0x30, 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 0x41, 0x52, 0x4D, 0x48, 0x30, 0x30, 0x31, 0x31, 0x00,
    0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, 0x08, 0x5F, 0x53, 0x54, 0x41, 0x0A, 0x0F, 0x08, 0x5F, 0x43,
    0x52, 0x53, 0x11, 0x1A, 0x0A, 0x17, 0x86, 0x09, 0x00, 0x01, 0x00, 0xF0, 0xFF, 0x2F, 0x00, 0x10,
    0x00, 0x00, 0x89, 0x06, 0x00, 0x03, 0x01, 0x21, 0x00, 0x00, 0x00, 0x79, 0x00, 0x5B, 0x82, 0x44,
    0x12, 0x2E, 0x5F, 0x53, 0x42, 0x5F, 0x50, 0x43, 0x49, 0x30, 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0C,
    0x41, 0xD0, 0x0A, 0x08, 0x08, 0x5F, 0x43, 0x49, 0x44, 0x0C, 0x41, 0xD0, 0x0A, 0x03, 0x08, 0x5F,
    0x53, 0x45, 0x47, 0x00, 0x08, 0x5F, 0x55, 0x49, 0x44, 0x00, 0x08, 0x5F, 0x43, 0x43, 0x41, 0x01,
    0x14, 0x32, 0x5F, 0x44, 0x53, 0x4D, 0x04, 0xA0, 0x29, 0x93, 0x68, 0x11, 0x13, 0x0A, 0x10, 0xD0,
    0x37, 0xC9, 0xE5, 0x53, 0x35, 0x7A, 0x4D, 0x91, 0x17, 0xEA, 0x4D, 0x19, 0xC3, 0x43, 0x4D, 0xA0,
    0x09, 0x93, 0x6A, 0x00, 0xA4, 0x11, 0x03, 0x01, 0x21, 0xA0, 0x07, 0x93, 0x6A, 0x0A, 0x05, 0xA4,
    0x00, 0xA4, 0x00, 0x08, 0x5F, 0x43, 0x52, 0x53, 0x11, 0x42, 0x09, 0x0A, 0x8E, 0x88, 0x0D, 0x00,
    0x02, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x87, 0x17, 0x00,
    0x00, 0x0C, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xFF, 0xFF, 0xFF, 0xDF, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x87, 0x17, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x8A, 0x2B, 0x00, 0x00, 0x0C, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x87,
    0x17, 0x00, 0x01, 0x0C, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0x0F, 0x00, 0x00, 0x01, 0x00, 0x79, 0x00, 0x5B, 0x82, 0x26, 0x52, 0x45,
    0x53, 0x30, 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0C, 0x41, 0xD0, 0x0C, 0x02, 0x08, 0x5F, 0x43, 0x52,
    0x53, 0x11, 0x11, 0x0A, 0x0E, 0x86, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x10, 0x79, 0x00,
];

const DSDT_OFFSET_PCI_QWORD_MEM: usize = 0x12f;

const AML_CPU_TEMPLATE: [u8; 42] = [
    0x5B, 0x82, 0x28, 0x2E, 0x5F, 0x53, 0x42, 0x5F, // Device (_SB.C000)
    0x43, 0x30, 0x30, 0x30, // "C000"
    0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 0x41, 0x43, 0x50, 0x49, 0x30, 0x30, 0x30, 0x37,
    0x00, // Name (_HID, "ACPI0007")
    0x08, 0x5F, 0x55, 0x49, 0x44, 0x0B, 0x00, 0x00, // Name (_UID, 0x0000)
    0x08, 0x5F, 0x53, 0x54, 0x41, 0x0A, 0x0F, // Name (_STA, 0x0F)
];

#[cfg(test)]
#[path = "board_arm64_test.rs"]
mod tests;
