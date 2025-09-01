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
use std::sync::Arc;

use parking_lot::Mutex;

use crate::arch::layout::{
    DEVICE_TREE_LIMIT, DEVICE_TREE_START, GIC_DIST_START, GIC_MSI_START,
    GIC_V2_CPU_INTERFACE_START, GIC_V3_REDIST_START, MEM_64_START, PCIE_CONFIG_START,
    PCIE_MMIO_32_NON_PREFETCHABLE_END, PCIE_MMIO_32_NON_PREFETCHABLE_START,
    PCIE_MMIO_32_PREFETCHABLE_END, PCIE_MMIO_32_PREFETCHABLE_START, PL011_START, RAM_32_SIZE,
    RAM_32_START,
};
use crate::arch::reg::SReg;
use crate::board::{Board, BoardConfig, PCIE_MMIO_64_SIZE, Result, VcpuGuard};
use crate::firmware::dt::{DeviceTree, Node, PropVal};
use crate::hv::{GicV2, GicV2m, GicV3, Hypervisor, Its, Vcpu, Vm};
use crate::loader::{ExecType, InitState};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{MemRegion, MemRegionType};

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
    mpidrs: Mutex<Vec<u64>>,
}

impl<V: Vm> ArchBoard<V> {
    pub fn new<H>(_hv: &H, vm: &V, config: &BoardConfig) -> Result<Self>
    where
        H: Hypervisor<Vm = V>,
    {
        let gic = match vm.create_gic_v3(GIC_DIST_START, GIC_V3_REDIST_START, config.num_cpu) {
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

        let mpidrs = Mutex::new(vec![u64::MAX; config.num_cpu as usize]);
        Ok(ArchBoard { gic, msi, mpidrs })
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn setup_firmware(&self, _fw: &mut ArcMemPages) -> Result<()> {
        unimplemented!()
    }

    pub fn init_ap(&self, _id: u32, _vcpu: &mut V::Vcpu, _vcpus: &VcpuGuard) -> Result<()> {
        Ok(())
    }

    pub fn init_boot_vcpu(&self, vcpu: &mut V::Vcpu, init_state: &InitState) -> Result<()> {
        vcpu.set_regs(&init_state.regs)?;
        vcpu.set_sregs(&init_state.sregs)?;
        Ok(())
    }

    pub fn init_vcpu(&self, id: u32, vcpu: &mut V::Vcpu) -> Result<()> {
        vcpu.reset(id == 0)?;
        self.arch.mpidrs.lock()[id as usize] = vcpu.get_sreg(SReg::MPIDR_EL1)?;
        Ok(())
    }

    pub fn reset_vcpu(&self, id: u32, vcpu: &mut V::Vcpu) -> Result<()> {
        vcpu.reset(id == 0)?;
        Ok(())
    }

    pub fn create_ram(&self) -> Result<()> {
        let mem_size = self.config.mem.size;
        let memory = &self.memory;

        let low_mem_size = std::cmp::min(mem_size, RAM_32_SIZE);
        let pages_low = self.create_ram_pages(low_mem_size, c"ram-low")?;
        memory.add_region(
            RAM_32_START,
            Arc::new(MemRegion::with_ram(pages_low, MemRegionType::Ram)),
        )?;

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

    pub fn coco_init(&self, _id: u32) -> Result<()> {
        Ok(())
    }

    pub fn coco_finalize(&self, _id: u32, _vcpus: &VcpuGuard) -> Result<()> {
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

    fn create_chosen_node(&self, init_state: &InitState, root: &mut Node) {
        let payload = self.payload.read();
        let Some(payload) = payload.as_ref() else {
            return;
        };
        if !matches!(payload.exec_type, ExecType::Linux) {
            return;
        }
        let mut node = Node::default();
        if let Some(cmd_line) = &payload.cmd_line {
            node.props
                .insert("bootargs", PropVal::String(cmd_line.clone()));
        }
        if let Some(initramfs_range) = &init_state.initramfs {
            node.props.insert(
                "linux,initrd-start",
                PropVal::U32(initramfs_range.start as u32),
            );
            node.props
                .insert("linux,initrd-end", PropVal::U32(initramfs_range.end as u32));
        }
        node.props.insert(
            "stdout-path",
            PropVal::String(format!("/pl011@{PL011_START:x}")),
        );
        root.nodes.insert("chosen".to_owned(), node);
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
                nodes: HashMap::new(),
            };
            root.nodes.insert(format!("memory@{start:x}"), node);
        }
    }

    pub fn create_cpu_nodes(&self, root: &mut Node) {
        let mpidrs = self.arch.mpidrs.lock();

        let mut cpu_nodes = mpidrs
            .iter()
            .map(|mpidr| {
                let reg = mpidr & 0xff_00ff_ffff;
                (
                    format!("cpu@{reg}"),
                    Node {
                        props: HashMap::from([
                            ("device_type", PropVal::Str("cpu")),
                            ("compatible", PropVal::Str("arm,arm-v8")),
                            ("enable-method", PropVal::Str("psci")),
                            ("reg", PropVal::U32(reg as u32)),
                            ("phandle", PropVal::PHandle(reg as u32 | (1 << 16))),
                        ]),
                        nodes: HashMap::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let cores = mpidrs
            .iter()
            .map(|mpidr| {
                let reg = mpidr & 0xff_00ff_ffff;
                (
                    format!("core{reg}"),
                    Node {
                        props: HashMap::from([("cpu", PropVal::PHandle(reg as u32 | (1 << 16)))]),
                        nodes: HashMap::new(),
                    },
                )
            })
            .collect();
        let cpu_map = Node {
            props: HashMap::new(),
            nodes: HashMap::from([(
                "socket0".to_owned(),
                Node {
                    props: HashMap::new(),
                    nodes: HashMap::from([(
                        "cluster0".to_owned(),
                        Node {
                            props: HashMap::new(),
                            nodes: cores,
                        },
                    )]),
                },
            )]),
        };
        cpu_nodes.insert("cpu-map".to_owned(), cpu_map);
        let cpus = Node {
            props: HashMap::from([
                ("#address-cells", PropVal::U32(1)),
                ("#size-cells", PropVal::U32(0)),
            ]),
            nodes: cpu_nodes,
        };
        root.nodes.insert("cpus".to_owned(), cpus);
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
            nodes: HashMap::new(),
        };
        root.nodes.insert("apb-pclk".to_owned(), node);
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
            nodes: HashMap::new(),
        };
        root.nodes.insert(format!("pl011@{PL011_START:x}"), node);
    }

    // Documentation/devicetree/bindings/timer/arm,arch_timer.yaml
    fn create_timer_node(&self, root: &mut Node) {
        let mut interrupts = vec![];
        let irq_pins = [13, 14, 11, 10];
        let ppi = 1;
        let level_trigger = 4;
        let cpu_mask = match self.arch.gic {
            Gic::V2(_) => (1 << self.config.num_cpu) - 1,
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
            nodes: HashMap::new(),
        };
        root.nodes.insert("timer".to_owned(), node);
    }

    fn create_gic_msi_node(&self) -> HashMap<String, Node> {
        let Some(msi) = &self.arch.msi else {
            return HashMap::new();
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
                    nodes: HashMap::new(),
                };
                HashMap::from([(format!("its@{GIC_MSI_START:x}"), node)])
            }
            Msi::V2m(_) => {
                let node = Node {
                    props: HashMap::from([
                        ("compatible", PropVal::Str("arm,gic-v2m-frame")),
                        ("msi-controller", PropVal::Empty),
                        ("reg", PropVal::U64List(vec![GIC_MSI_START, 64 << 10])),
                        ("phandle", PropVal::PHandle(PHANDLE_MSI)),
                    ]),
                    nodes: HashMap::new(),
                };
                HashMap::from([(format!("v2m@{GIC_MSI_START:x}"), node)])
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
                            self.config.num_cpu as u64 * (128 << 10),
                        ]),
                    ),
                    ("phandle", PropVal::U32(PHANDLE_GIC)),
                ]),
                nodes: msi,
            },
        };
        root.nodes.insert(format!("intc@{GIC_DIST_START:x}"), node);
    }

    // Documentation/devicetree/bindings/arm/psci.yaml
    fn create_psci_node(&self, root: &mut Node) {
        let node = Node {
            props: HashMap::from([
                ("method", PropVal::Str("hvc")),
                ("compatible", PropVal::Str("arm,psci-0.2\0arm,psci")),
            ]),
            nodes: HashMap::new(),
        };
        root.nodes.insert("psci".to_owned(), node);
    }

    // https://elinux.org/Device_Tree_Usage#PCI_Host_Bridge
    // Documentation/devicetree/bindings/pci/host-generic-pci.yaml
    // IEEE Std 1275-1994
    fn create_pci_bridge_node(&self, root: &mut Node) {
        let devices = self.pci_bus.segment.devices.read();
        let Some(max_bus) = devices.keys().map(|bdf| bdf.bus()).max() else {
            return;
        };
        let pcie_mmio_64_start = self.config.pcie_mmio_64_start();
        let prefetchable = 1 << 30;
        let mem_32 = 0b10 << 24;
        let mem_64 = 0b11 << 24;
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("pci-host-ecam-generic")),
                ("device_type", PropVal::Str("pci")),
                ("reg", PropVal::U64List(vec![PCIE_CONFIG_START, 256 << 20])),
                ("bus-range", PropVal::U64List(vec![0, max_bus as u64])),
                ("#address-cells", PropVal::U32(3)),
                ("#size-cells", PropVal::U32(2)),
                (
                    "ranges",
                    PropVal::U32List(vec![
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
                ("msi-parent", PropVal::PHandle(PHANDLE_MSI)),
            ]),
            nodes: HashMap::new(),
        };
        root.nodes
            .insert(format!("pci@{PCIE_CONFIG_START:x}"), node);
    }

    pub fn create_firmware_data(&self, init_state: &InitState) -> Result<()> {
        let mut device_tree = DeviceTree::new();
        let root = &mut device_tree.root;
        root.props.insert("#address-cells", PropVal::U32(2));
        root.props.insert("#size-cells", PropVal::U32(2));
        root.props.insert("model", PropVal::Str("linux,dummy-virt"));
        root.props
            .insert("compatible", PropVal::Str("linux,dummy-virt"));
        root.props
            .insert("interrupt-parent", PropVal::PHandle(PHANDLE_GIC));

        self.create_chosen_node(init_state, root);
        self.create_pl011_node(root);
        self.create_memory_node(root);
        self.create_cpu_nodes(root);
        self.create_gic_node(root);
        if self.arch.msi.is_some() {
            self.create_pci_bridge_node(root);
        }
        self.create_clock_node(root);
        self.create_timer_node(root);
        self.create_psci_node(root);
        log::debug!("device tree: {device_tree:#x?}");
        let blob = device_tree.to_blob();
        let ram = self.memory.ram_bus();
        assert!(blob.len() as u64 <= DEVICE_TREE_LIMIT);
        ram.write_range(DEVICE_TREE_START, blob.len() as u64, &*blob)?;
        Ok(())
    }
}

const PHANDLE_GIC: u32 = 1;
const PHANDLE_CLOCK: u32 = 2;
const PHANDLE_MSI: u32 = 3;
