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

mod config;

use std::collections::HashMap;
use std::mem;
use std::path::{Path, PathBuf};

use alioth::board::{BoardSpec, CpuSpec};
#[cfg(target_arch = "x86_64")]
use alioth::device::fw_cfg::FwCfgItemSpec;
use alioth::errors::{DebugTrace, trace_error};
#[cfg(target_os = "macos")]
use alioth::hv::Hvf;
#[cfg(target_os = "linux")]
use alioth::hv::Kvm;
use alioth::hv::{CocoSpec, HvSpec, Hypervisor};
use alioth::loader::{Executable, PayloadSpec};
use alioth::mem::{MemBackend, MemSpec};
#[cfg(target_os = "linux")]
use alioth::vfio::{VfioCdevSpec, VfioContainerSpec, VfioGroupSpec, VfioIoasSpec};
#[cfg(target_os = "linux")]
use alioth::virtio::DeviceId;
use alioth::virtio::dev::balloon::BalloonSpec;
use alioth::virtio::dev::blk::BlkFileSpec;
use alioth::virtio::dev::entropy::EntropySpec;
#[cfg(target_os = "linux")]
use alioth::virtio::vu::frontend::VuFrontendSpec;
use alioth::virtio::worker::WorkerApi;
use alioth::vm::Machine;
use clap::Args;
use serde_aco::help_text;
use snafu::{ResultExt, Snafu};

use crate::objects::{DOC_OBJECTS, parse_objects};

use self::config::{BlkSpec, FsSpec, NetSpec, VmSpec, VsockSpec};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to parse {arg}"))]
    ParseArg {
        arg: String,
        error: serde_aco::Error,
    },
    #[snafu(display("Failed to parse objects"), context(false))]
    ParseObjects { source: crate::objects::Error },
    #[cfg(target_os = "linux")]
    #[snafu(display("Failed to access system hypervisor"))]
    Hypervisor { source: alioth::hv::Error },
    #[snafu(display("Failed to create a VM"))]
    CreateVm { source: alioth::vm::Error },
    #[snafu(display("Failed to boot a VM"))]
    BootVm { source: alioth::vm::Error },
    #[snafu(display("VM did not shutdown peacefully"))]
    WaitVm { source: alioth::vm::Error },
}

#[derive(Args, Debug, Clone, Default)]
#[command(arg_required_else_help = true, alias("run"))]
pub struct BootArgs {
    #[arg(long, help(
        help_text::<HvSpec>("Specify the Hypervisor to run on.")
    ), value_name = "HV")]
    hypervisor: Option<String>,

    /// Path to a Linux kernel image.
    #[arg(short, long, value_name = "PATH")]
    kernel: Option<Box<Path>>,

    /// Path to an ELF kernel with PVH note.
    #[cfg(target_arch = "x86_64")]
    #[arg(long, value_name = "PATH")]
    pvh: Option<Box<Path>>,

    /// Path to a firmware image.
    #[arg(long, short, value_name = "PATH")]
    firmware: Option<Box<Path>>,

    /// Command line to pass to the kernel, e.g. `console=ttyS0`.
    #[arg(short, long, alias = "cmd-line", value_name = "ARGS")]
    cmdline: Option<Box<str>>,

    /// Path to an initramfs image.
    #[arg(short, long, value_name = "PATH")]
    initramfs: Option<Box<Path>>,

    /// DEPRECATED: Use --cpu instead.
    #[arg(long, default_value_t = 1)]
    num_cpu: u16,

    #[arg(short('p'), long, help(
        help_text::<CpuSpec>("Configure the VCPUs of the guest.")
    ))]
    cpu: Option<Box<str>>,

    /// DEPRECATED: Use --memory instead.
    #[arg(long, default_value = "1G")]
    mem_size: String,

    #[arg(short, long, help(
        help_text::<MemSpec>("Specify the memory of the guest.")
    ))]
    memory: Option<String>,

    /// Add a pvpanic device.
    #[arg(long)]
    pvpanic: bool,

    #[cfg(target_arch = "x86_64")]
    #[arg(long, help(
        help_text::<FwCfgItemSpec>("Add an extra item to the fw_cfg device.")
    ), value_name = "ITEM")]
    fw_cfg: Vec<String>,

    /// Add a VirtIO entropy device.
    #[arg(long)]
    entropy: bool,

    #[arg(long, help(
        help_text::<NetSpec>("Add a VirtIO net device.")
    ))]
    net: Vec<String>,

    #[arg(long, help(
        help_text::<BlkSpec>("Add a VirtIO block device.")
    ))]
    blk: Vec<String>,

    #[arg(long, help(
        help_text::<CocoSpec>("Enable confidential compute supported by host platform.")
    ))]
    coco: Option<String>,

    #[arg(long, help(
        help_text::<FsSpec>("Add a VirtIO filesystem device.")
    ))]
    fs: Vec<String>,

    #[arg(long, help(
        help_text::<VsockSpec>("Add a VirtIO vsock device.")
    ))]
    vsock: Option<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<VfioCdevSpec>(
        "Assign a host PCI device to the guest using IOMMUFD API."
    ) ))]
    vfio_cdev: Vec<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<VfioIoasSpec>("Create a new IO address space.")))]
    vfio_ioas: Vec<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<VfioGroupSpec>(
        "Assign a host PCI device to the guest using legacy VFIO API."
    )))]
    vfio_group: Vec<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<VfioContainerSpec>("Add a new VFIO container.")))]
    vfio_container: Vec<String>,

    #[arg(long)]
    #[arg(long, help(help_text::<BalloonSpec>("Add a VirtIO balloon device.")))]
    balloon: Option<String>,

    #[arg(short, long("object"), help = DOC_OBJECTS, value_name = "OBJECT")]
    objects: Vec<String>,
}

fn parse_net_arg(arg: &str, objects: &HashMap<&str, &str>) -> serde_aco::Result<NetSpec> {
    #[cfg(target_os = "linux")]
    if let Ok(param) = serde_aco::from_args(arg, objects) {
        Ok(param)
    } else {
        let param = serde_aco::from_args(arg, objects)?;
        Ok(NetSpec::Tap(param))
    }

    #[cfg(target_os = "macos")]
    serde_aco::from_args(arg, objects)
}

fn parse_blk_arg(arg: &str, objects: &HashMap<&str, &str>) -> BlkSpec {
    if let Ok(param) = serde_aco::from_args(arg, objects) {
        param
    } else if let Ok(param) = serde_aco::from_args(arg, objects) {
        BlkSpec::File(param)
    } else {
        eprintln!("Please update the cmd line to --blk file,path={arg}");
        BlkSpec::File(BlkFileSpec {
            path: PathBuf::from(arg).into(),
            readonly: false,
            api: WorkerApi::Mio,
        })
    }
}

fn parse_mem_arg(
    arg: Option<String>,
    mem_size: String,
    objects: &HashMap<&str, &str>,
) -> Result<MemSpec, Error> {
    let spec = if let Some(arg) = arg {
        serde_aco::from_args(&arg, objects).context(error::ParseArg { arg })?
    } else {
        #[cfg(target_os = "linux")]
        eprintln!("Please update the cmd line to --memory size={mem_size},backend=memfd");
        MemSpec {
            size: serde_aco::from_args(&mem_size, objects)
                .context(error::ParseArg { arg: mem_size })?,
            #[cfg(target_os = "linux")]
            backend: MemBackend::Memfd,
            #[cfg(not(target_os = "linux"))]
            backend: MemBackend::Anonymous,
            ..Default::default()
        }
    };
    Ok(spec)
}

fn parse_cpu_arg(
    arg: Option<Box<str>>,
    num_cpu: u16,
    objects: &HashMap<&str, &str>,
) -> Result<CpuSpec, Error> {
    let mut spec = if let Some(arg) = arg {
        serde_aco::from_args(&arg, objects).context(error::ParseArg { arg })?
    } else {
        eprintln!("Please update the cmd line to --cpu count={num_cpu}");
        CpuSpec {
            count: num_cpu,
            ..Default::default()
        }
    };
    if spec.topology.sockets == 0 {
        spec.topology.sockets = 1;
    }
    let vcpus_per_core = 1 + spec.topology.smt as u16;
    if spec.topology.cores == 0 {
        spec.topology.cores = spec.count / spec.topology.sockets as u16 / vcpus_per_core;
    }
    Ok(spec)
}

fn parse_payload_arg(args: &mut BootArgs) -> PayloadSpec {
    let mut payload = PayloadSpec {
        firmware: args.firmware.take(),
        initramfs: args.initramfs.take(),
        cmdline: args.cmdline.take(),
        ..Default::default()
    };
    payload.executable = args.kernel.take().map(Executable::Linux);
    #[cfg(target_arch = "x86_64")]
    if payload.executable.is_none() {
        payload.executable = args.pvh.take().map(Executable::Pvh);
    }
    payload
}

fn parse_args(mut args: BootArgs, objects: HashMap<&str, &str>) -> Result<VmSpec, Error> {
    let payload = parse_payload_arg(&mut args);

    let mut board_spec = BoardSpec::default();
    if let Some(arg) = args.coco {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        board_spec.coco = Some(param);
    };
    board_spec.mem = parse_mem_arg(args.memory, args.mem_size, &objects)?;
    board_spec.cpu = parse_cpu_arg(args.cpu, args.num_cpu, &objects)?;

    let mut spec = VmSpec {
        board: board_spec,
        pvpanic: args.pvpanic,
        payload,
        ..Default::default()
    };

    #[cfg(target_arch = "x86_64")]
    for arg in args.fw_cfg {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.fw_cfg.push(param);
    }

    if args.entropy {
        spec.entropy = Some(EntropySpec::default());
    }

    for arg in args.net {
        let param = parse_net_arg(&arg, &objects).context(error::ParseArg { arg })?;
        spec.net.push(param);
    }

    for arg in args.blk {
        let param = parse_blk_arg(&arg, &objects);
        spec.blk.push(param);
    }

    for arg in args.fs {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.fs.push(param);
    }

    if let Some(arg) = args.vsock {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.vsock = Some(param);
    }

    if let Some(arg) = args.balloon {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.balloon = Some(param);
    }

    #[cfg(target_os = "linux")]
    for arg in args.vfio_ioas {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.vfio_ioas.push(param);
    }
    #[cfg(target_os = "linux")]
    for arg in args.vfio_cdev {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.vfio_cdev.push(param);
    }
    #[cfg(target_os = "linux")]
    for arg in args.vfio_container {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.vfio_container.push(param);
    }
    #[cfg(target_os = "linux")]
    for arg in args.vfio_group {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        spec.vfio_group.push(param);
    }

    Ok(spec)
}

fn create<H: Hypervisor>(hypervisor: &H, spec: VmSpec) -> Result<Machine<H>, alioth::vm::Error> {
    let vm = Machine::new(hypervisor, spec.board)?;

    #[cfg(target_arch = "x86_64")]
    vm.add_com1()?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl011()?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl031();

    if spec.pvpanic {
        vm.add_pvpanic()?;
    }

    #[cfg(target_arch = "x86_64")]
    if spec.payload.firmware.is_some() {
        vm.add_cmos()?;
        vm.add_fw_dbg()?;
    }

    #[cfg(target_arch = "x86_64")]
    if spec.payload.firmware.is_some() || !spec.fw_cfg.is_empty() {
        vm.add_fw_cfg(spec.fw_cfg.into_iter())?;
    };

    if let Some(entropy_spec) = spec.entropy {
        vm.add_virtio_dev("virtio-entropy", entropy_spec)?;
    }

    for (index, net_spec) in spec.net.into_iter().enumerate() {
        match net_spec {
            #[cfg(target_os = "linux")]
            NetSpec::Tap(tap_spec) => vm.add_virtio_dev(format!("virtio-net-{index}"), tap_spec),
            #[cfg(target_os = "linux")]
            NetSpec::Vu(sock) => {
                let vu_spec = VuFrontendSpec {
                    id: DeviceId::NET,
                    socket: sock.socket,
                };
                vm.add_virtio_dev(format!("vu-net-{index}"), vu_spec)
            }
            #[cfg(target_os = "macos")]
            NetSpec::Vmnet(vmnet_spec) => {
                vm.add_virtio_dev(format!("virtio-net-{index}"), vmnet_spec)
            }
        }?;
    }

    for (index, blk_spec) in spec.blk.into_iter().enumerate() {
        match blk_spec {
            BlkSpec::File(file_spec) => vm.add_virtio_dev(format!("virtio-blk-{index}"), file_spec),
            #[cfg(target_os = "linux")]
            BlkSpec::Vu(s) => {
                let vu_spec = VuFrontendSpec {
                    id: DeviceId::BLOCK,
                    socket: s.socket,
                };
                vm.add_virtio_dev(format!("vu-net-{index}"), vu_spec)
            }
        }?;
    }

    for (index, fs_spec) in spec.fs.into_iter().enumerate() {
        match fs_spec {
            FsSpec::Dir(dir_spec) => vm.add_virtio_dev(format!("virtio-fs-{index}"), dir_spec),
            #[cfg(target_os = "linux")]
            FsSpec::Vu(vu_fs_spec) => vm.add_virtio_dev(format!("vu-fs-{index}"), vu_fs_spec),
        }?;
    }

    if let Some(vsock_spec) = spec.vsock {
        match vsock_spec {
            #[cfg(target_os = "linux")]
            VsockSpec::Vhost(vhost_spec) => vm.add_virtio_dev("vhost-vsock", vhost_spec),
            VsockSpec::Uds(uds_spec) => vm.add_virtio_dev("uds-vsock", uds_spec),
            #[cfg(target_os = "linux")]
            VsockSpec::Vu(s) => {
                let vu_spec = VuFrontendSpec {
                    id: DeviceId::SOCKET,
                    socket: s.socket,
                };
                vm.add_virtio_dev("vu-vsock", vu_spec)
            }
        }?;
    }

    if let Some(balloon_spec) = spec.balloon {
        vm.add_virtio_dev("virtio-balloon", balloon_spec)?;
    }

    #[cfg(target_os = "linux")]
    for ioas_spec in spec.vfio_ioas.into_iter() {
        vm.add_vfio_ioas(ioas_spec)?;
    }
    #[cfg(target_os = "linux")]
    for (index, cdev_spec) in spec.vfio_cdev.into_iter().enumerate() {
        vm.add_vfio_cdev(format!("vfio-{index}").into(), cdev_spec)?;
    }

    #[cfg(target_os = "linux")]
    for container_spec in spec.vfio_container.into_iter() {
        vm.add_vfio_container(container_spec)?;
    }
    #[cfg(target_os = "linux")]
    for (index, group_spec) in spec.vfio_group.into_iter().enumerate() {
        vm.add_vfio_devs_in_group(&index.to_string(), group_spec)?;
    }

    vm.add_payload(spec.payload);

    Ok(vm)
}

pub fn boot(mut args: BootArgs) -> Result<(), Error> {
    let object_args = mem::take(&mut args.objects);
    let objects = parse_objects(&object_args)?;

    let hv_spec = if let Some(arg) = args.hypervisor.take() {
        serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?
    } else {
        HvSpec::default()
    };
    let hypervisor = match hv_spec {
        #[cfg(target_os = "linux")]
        HvSpec::Kvm(kvm_spec) => Kvm::new(kvm_spec).context(error::Hypervisor)?,
        #[cfg(target_os = "macos")]
        HvSpec::Hvf => Hvf {},
    };

    let spec = parse_args(args, objects)?;

    let vm = create(&hypervisor, spec).context(error::CreateVm)?;

    vm.boot().context(error::BootVm)?;
    vm.wait().context(error::WaitVm)?;
    Ok(())
}

#[cfg(test)]
#[path = "boot_test.rs"]
mod tests;
