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
use std::ffi::CString;
use std::mem;
use std::path::{Path, PathBuf};

use alioth::board::{BoardConfig, CpuConfig};
#[cfg(target_arch = "x86_64")]
use alioth::device::fw_cfg::FwCfgItemParam;
use alioth::errors::{DebugTrace, trace_error};
#[cfg(target_os = "macos")]
use alioth::hv::Hvf;
#[cfg(target_os = "linux")]
use alioth::hv::Kvm;
use alioth::hv::{Coco, HvConfig, Hypervisor};
use alioth::loader::{Executable, Payload};
use alioth::mem::{MemBackend, MemConfig};
#[cfg(target_os = "linux")]
use alioth::vfio::{CdevParam, ContainerParam, GroupParam, IoasParam};
#[cfg(target_os = "linux")]
use alioth::virtio::DeviceId;
use alioth::virtio::dev::balloon::BalloonParam;
use alioth::virtio::dev::blk::BlkFileParam;
use alioth::virtio::dev::entropy::EntropyParam;
#[cfg(target_os = "linux")]
use alioth::virtio::vu::frontend::VuFrontendParam;
use alioth::virtio::worker::WorkerApi;
use alioth::vm::Machine;
use clap::Args;
use serde_aco::help_text;
use snafu::{ResultExt, Snafu};

use crate::objects::{DOC_OBJECTS, parse_objects};

use self::config::{BlkParam, Config, FsParam, NetParam, VsockParam};

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
        help_text::<HvConfig>("Specify the Hypervisor to run on.")
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
    cmdline: Option<CString>,

    /// Path to an initramfs image.
    #[arg(short, long, value_name = "PATH")]
    initramfs: Option<Box<Path>>,

    /// DEPRECATED: Use --cpu instead.
    #[arg(long, default_value_t = 1)]
    num_cpu: u16,

    #[arg(short('p'), long, help(
        help_text::<CpuConfig>("Configure the VCPUs of the guest.")
    ))]
    cpu: Option<Box<str>>,

    /// DEPRECATED: Use --memory instead.
    #[arg(long, default_value = "1G")]
    mem_size: String,

    #[arg(short, long, help(
        help_text::<MemConfig>("Specify the memory of the guest.")
    ))]
    memory: Option<String>,

    /// Add a pvpanic device.
    #[arg(long)]
    pvpanic: bool,

    #[cfg(target_arch = "x86_64")]
    #[arg(long, help(
        help_text::<FwCfgItemParam>("Add an extra item to the fw_cfg device.")
    ), value_name = "ITEM")]
    fw_cfg: Vec<String>,

    /// Add a VirtIO entropy device.
    #[arg(long)]
    entropy: bool,

    #[arg(long, help(
        help_text::<NetParam>("Add a VirtIO net device.")
    ))]
    net: Vec<String>,

    #[arg(long, help(
        help_text::<BlkParam>("Add a VirtIO block device.")
    ))]
    blk: Vec<String>,

    #[arg(long, help(
        help_text::<Coco>("Enable confidential compute supported by host platform.")
    ))]
    coco: Option<String>,

    #[arg(long, help(
        help_text::<FsParam>("Add a VirtIO filesystem device.")
    ))]
    fs: Vec<String>,

    #[arg(long, help(
        help_text::<VsockParam>("Add a VirtIO vsock device.")
    ))]
    vsock: Option<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<CdevParam>(
        "Assign a host PCI device to the guest using IOMMUFD API."
    ) ))]
    vfio_cdev: Vec<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<IoasParam>("Create a new IO address space.")))]
    vfio_ioas: Vec<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<GroupParam>(
        "Assign a host PCI device to the guest using legacy VFIO API."
    )))]
    vfio_group: Vec<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(help_text::<ContainerParam>("Add a new VFIO container.")))]
    vfio_container: Vec<String>,

    #[arg(long)]
    #[arg(long, help(help_text::<BalloonParam>("Add a VirtIO balloon device.")))]
    balloon: Option<String>,

    #[arg(short, long("object"), help = DOC_OBJECTS, value_name = "OBJECT")]
    objects: Vec<String>,
}

fn parse_net_arg(arg: &str, objects: &HashMap<&str, &str>) -> serde_aco::Result<NetParam> {
    #[cfg(target_os = "linux")]
    if let Ok(param) = serde_aco::from_args(arg, objects) {
        Ok(param)
    } else {
        let param = serde_aco::from_args(arg, objects)?;
        Ok(NetParam::Tap(param))
    }

    #[cfg(target_os = "macos")]
    serde_aco::from_args(arg, objects)
}

fn parse_blk_arg(arg: &str, objects: &HashMap<&str, &str>) -> BlkParam {
    if let Ok(param) = serde_aco::from_args(arg, objects) {
        param
    } else if let Ok(param) = serde_aco::from_args(arg, objects) {
        BlkParam::File(param)
    } else {
        eprintln!("Please update the cmd line to --blk file,path={arg}");
        BlkParam::File(BlkFileParam {
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
) -> Result<MemConfig, Error> {
    let config = if let Some(arg) = arg {
        serde_aco::from_args(&arg, objects).context(error::ParseArg { arg })?
    } else {
        #[cfg(target_os = "linux")]
        eprintln!("Please update the cmd line to --memory size={mem_size},backend=memfd");
        MemConfig {
            size: serde_aco::from_args(&mem_size, objects)
                .context(error::ParseArg { arg: mem_size })?,
            #[cfg(target_os = "linux")]
            backend: MemBackend::Memfd,
            #[cfg(not(target_os = "linux"))]
            backend: MemBackend::Anonymous,
            ..Default::default()
        }
    };
    Ok(config)
}

fn parse_cpu_arg(
    arg: Option<Box<str>>,
    num_cpu: u16,
    objects: &HashMap<&str, &str>,
) -> Result<CpuConfig, Error> {
    let config = if let Some(arg) = arg {
        serde_aco::from_args(&arg, objects).context(error::ParseArg { arg })?
    } else {
        eprintln!("Please update the cmd line to --cpu count={num_cpu}");
        CpuConfig {
            count: num_cpu,
            ..Default::default()
        }
    };
    Ok(config)
}

fn parse_payload_arg(args: &mut BootArgs) -> Payload {
    let mut payload = Payload {
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

fn parse_args(mut args: BootArgs, objects: HashMap<&str, &str>) -> Result<Config, Error> {
    let payload = parse_payload_arg(&mut args);

    let mut board_config = BoardConfig::default();
    if let Some(arg) = args.coco {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        board_config.coco = Some(param);
    };
    board_config.mem = parse_mem_arg(args.memory, args.mem_size, &objects)?;
    board_config.cpu = parse_cpu_arg(args.cpu, args.num_cpu, &objects)?;

    let mut config = Config {
        board: board_config,
        pvpanic: args.pvpanic,
        payload,
        ..Default::default()
    };

    #[cfg(target_arch = "x86_64")]
    for arg in args.fw_cfg {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.fw_cfg.push(param);
    }

    if args.entropy {
        config.entropy = Some(EntropyParam::default());
    }

    for arg in args.net {
        let param = parse_net_arg(&arg, &objects).context(error::ParseArg { arg })?;
        config.net.push(param);
    }

    for arg in args.blk {
        let param = parse_blk_arg(&arg, &objects);
        config.blk.push(param);
    }

    for arg in args.fs {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.fs.push(param);
    }

    if let Some(arg) = args.vsock {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.vsock = Some(param);
    }

    if let Some(arg) = args.balloon {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.balloon = Some(param);
    }

    #[cfg(target_os = "linux")]
    for arg in args.vfio_ioas {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.vfio_ioas.push(param);
    }
    #[cfg(target_os = "linux")]
    for arg in args.vfio_cdev {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.vfio_cdev.push(param);
    }
    #[cfg(target_os = "linux")]
    for arg in args.vfio_container {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.vfio_container.push(param);
    }
    #[cfg(target_os = "linux")]
    for arg in args.vfio_group {
        let param = serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?;
        config.vfio_group.push(param);
    }

    Ok(config)
}

fn create<H: Hypervisor>(hypervisor: &H, config: Config) -> Result<Machine<H>, alioth::vm::Error> {
    let vm = Machine::new(hypervisor, config.board)?;

    #[cfg(target_arch = "x86_64")]
    vm.add_com1()?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl011()?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl031();

    if config.pvpanic {
        vm.add_pvpanic()?;
    }

    #[cfg(target_arch = "x86_64")]
    if config.payload.firmware.is_some() || !config.fw_cfg.is_empty() {
        vm.add_fw_cfg(config.fw_cfg.into_iter())?;
    };

    if let Some(param) = config.entropy {
        vm.add_virtio_dev("virtio-entropy", param)?;
    }

    for (index, param) in config.net.into_iter().enumerate() {
        match param {
            #[cfg(target_os = "linux")]
            NetParam::Tap(tap_param) => vm.add_virtio_dev(format!("virtio-net-{index}"), tap_param),
            #[cfg(target_os = "linux")]
            NetParam::Vu(sock) => {
                let param = VuFrontendParam {
                    id: DeviceId::Net,
                    socket: sock.socket,
                };
                vm.add_virtio_dev(format!("vu-net-{index}"), param)
            }
            #[cfg(target_os = "macos")]
            NetParam::Vmnet(p) => vm.add_virtio_dev(format!("virtio-net-{index}"), p),
        }?;
    }

    for (index, param) in config.blk.into_iter().enumerate() {
        match param {
            BlkParam::File(p) => vm.add_virtio_dev(format!("virtio-blk-{index}"), p),
            #[cfg(target_os = "linux")]
            BlkParam::Vu(s) => {
                let p = VuFrontendParam {
                    id: DeviceId::Block,
                    socket: s.socket,
                };
                vm.add_virtio_dev(format!("vu-net-{index}"), p)
            }
        }?;
    }

    for (index, param) in config.fs.into_iter().enumerate() {
        match param {
            FsParam::Dir(p) => vm.add_virtio_dev(format!("virtio-fs-{index}"), p),
            #[cfg(target_os = "linux")]
            FsParam::Vu(p) => vm.add_virtio_dev(format!("vu-fs-{index}"), p),
        }?;
    }

    if let Some(param) = config.vsock {
        match param {
            #[cfg(target_os = "linux")]
            VsockParam::Vhost(p) => vm.add_virtio_dev("vhost-vsock", p),
            VsockParam::Uds(p) => vm.add_virtio_dev("uds-vsock", p),
            #[cfg(target_os = "linux")]
            VsockParam::Vu(s) => {
                let p = VuFrontendParam {
                    id: DeviceId::Socket,
                    socket: s.socket,
                };
                vm.add_virtio_dev("vu-vsock", p)
            }
        }?;
    }

    if let Some(param) = config.balloon {
        vm.add_virtio_dev("virtio-balloon", param)?;
    }

    #[cfg(target_os = "linux")]
    for param in config.vfio_ioas.into_iter() {
        vm.add_vfio_ioas(param)?;
    }
    #[cfg(target_os = "linux")]
    for (index, param) in config.vfio_cdev.into_iter().enumerate() {
        vm.add_vfio_cdev(format!("vfio-{index}").into(), param)?;
    }

    #[cfg(target_os = "linux")]
    for param in config.vfio_container.into_iter() {
        vm.add_vfio_container(param)?;
    }
    #[cfg(target_os = "linux")]
    for (index, param) in config.vfio_group.into_iter().enumerate() {
        vm.add_vfio_devs_in_group(&index.to_string(), param)?;
    }

    vm.add_payload(config.payload);

    Ok(vm)
}

pub fn boot(mut args: BootArgs) -> Result<(), Error> {
    let object_args = mem::take(&mut args.objects);
    let objects = parse_objects(&object_args)?;

    let hv_config = if let Some(arg) = args.hypervisor.take() {
        serde_aco::from_args(&arg, &objects).context(error::ParseArg { arg })?
    } else {
        HvConfig::default()
    };
    let hypervisor = match hv_config {
        #[cfg(target_os = "linux")]
        HvConfig::Kvm(kvm_config) => Kvm::new(kvm_config).context(error::Hypervisor)?,
        #[cfg(target_os = "macos")]
        HvConfig::Hvf => Hvf {},
    };

    let config = parse_args(args, objects)?;

    let vm = create(&hypervisor, config).context(error::CreateVm)?;

    vm.boot().context(error::BootVm)?;
    vm.wait().context(error::WaitVm)?;
    Ok(())
}

#[cfg(test)]
#[path = "boot_test.rs"]
mod tests;
