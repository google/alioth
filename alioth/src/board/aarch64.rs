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
    DEVICE_TREE_LIMIT, DEVICE_TREE_START, GIC_V2_CPU_INTERFACE_START, GIC_V2_DIST_START,
    MEM_64_START, PL011_START, RAM_32_SIZE, RAM_32_START,
};
use crate::arch::reg::SReg;
use crate::board::{Board, BoardConfig, Result, VcpuGuard};
use crate::firmware::dt::{DeviceTree, Node, PropVal};
use crate::hv::{GicV2, Hypervisor, Vcpu, Vm};
use crate::loader::{ExecType, InitState};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{AddrOpt, MemRegion, MemRegionType};

pub struct ArchBoard<V>
where
    V: Vm,
{
    gic_v2: V::GicV2,
    mpidrs: Mutex<Vec<u64>>,
}

impl<V: Vm> ArchBoard<V> {
    pub fn new<H>(_hv: &H, vm: &V, config: &BoardConfig) -> Result<Self>
    where
        H: Hypervisor<Vm = V>,
    {
        let gic_v2 = vm.create_gic_v2(GIC_V2_DIST_START, GIC_V2_CPU_INTERFACE_START)?;
        let mpidrs = Mutex::new(vec![u64::MAX; config.num_cpu as usize]);
        Ok(ArchBoard { gic_v2, mpidrs })
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
        let mem_size = self.config.mem_size;
        let memory = &self.memory;
        if mem_size > RAM_32_SIZE {
            memory.add_region(
                AddrOpt::Fixed(RAM_32_START),
                Arc::new(MemRegion::with_mapped(
                    ArcMemPages::from_anonymous(RAM_32_SIZE as usize, None)?,
                    MemRegionType::Ram,
                )),
            )?;
            memory.add_region(
                AddrOpt::Fixed(MEM_64_START),
                Arc::new(MemRegion::with_mapped(
                    ArcMemPages::from_anonymous((mem_size - RAM_32_SIZE) as usize, None)?,
                    MemRegionType::Ram,
                )),
            )?;
        } else {
            memory.add_region(
                AddrOpt::Fixed(RAM_32_START),
                Arc::new(MemRegion::with_mapped(
                    ArcMemPages::from_anonymous(mem_size as usize, None)?,
                    MemRegionType::Ram,
                )),
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
        self.arch.gic_v2.init()?;
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
            PropVal::String(format!("/pl011@{:x}", PL011_START)),
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
        root.nodes.insert(format!("pl011@{:x}", PL011_START), node);
    }

    // Documentation/devicetree/bindings/timer/arm,arch_timer.yaml
    fn create_timer_node(&self, root: &mut Node) {
        let mut interrupts = vec![];
        let irq_pins = [13, 14, 11, 10];
        let ppi = 1;
        let level_trigger = 4;
        let cpu_mask = (1 << self.config.num_cpu) - 1;
        for pin in irq_pins {
            interrupts.extend([ppi, pin, cpu_mask << 8 | level_trigger]);
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

    // Documentation/devicetree/bindings/interrupt-controller/arm,gic.yaml
    fn create_gicv2_node(&self, root: &mut Node) {
        let node = Node {
            props: HashMap::from([
                ("compatible", PropVal::Str("arm,cortex-a15-gic")),
                ("#interrupt-cells", PropVal::U32(3)),
                (
                    "reg",
                    PropVal::U64List(vec![
                        GIC_V2_DIST_START,
                        0x1000,
                        GIC_V2_CPU_INTERFACE_START,
                        0x2000,
                    ]),
                ),
                ("phandle", PropVal::U32(PHANDLE_GIC)),
                ("interrupt-controller", PropVal::Empty),
            ]),
            nodes: HashMap::new(),
        };
        root.nodes
            .insert(format!("intc@{GIC_V2_DIST_START:x}"), node);
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
        self.create_gicv2_node(root);
        self.create_clock_node(root);
        self.create_timer_node(root);
        self.create_psci_node(root);
        log::debug!("device tree: {:#x?}", device_tree);
        let blob = device_tree.to_blob();
        let ram = self.memory.ram_bus();
        assert!(blob.len() as u64 <= DEVICE_TREE_LIMIT);
        ram.write_range(DEVICE_TREE_START, blob.len() as u64, &*blob)?;
        Ok(())
    }
}

const PHANDLE_GIC: u32 = 1;
const PHANDLE_CLOCK: u32 = 2;
