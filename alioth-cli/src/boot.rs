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

use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};

use alioth::board::{BoardConfig, CpuConfig};
#[cfg(target_arch = "x86_64")]
use alioth::device::fw_cfg::FwCfgItemParam;
use alioth::errors::{DebugTrace, trace_error};
#[cfg(target_os = "macos")]
use alioth::hv::Hvf;
use alioth::hv::{self, Coco};
#[cfg(target_os = "linux")]
use alioth::hv::{Kvm, KvmConfig};
use alioth::loader::{Executable, Payload};
use alioth::mem::{MemBackend, MemConfig};
#[cfg(target_os = "linux")]
use alioth::vfio::{CdevParam, ContainerParam, GroupParam, IoasParam};
#[cfg(target_os = "linux")]
use alioth::virtio::DeviceId;
use alioth::virtio::dev::balloon::BalloonParam;
use alioth::virtio::dev::blk::BlkFileParam;
use alioth::virtio::dev::entropy::EntropyParam;
use alioth::virtio::dev::fs::shared_dir::SharedDirParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::fs::vu::VuFsParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::net::tap::NetTapParam;
#[cfg(target_os = "macos")]
use alioth::virtio::dev::net::vmnet::NetVmnetParam;
use alioth::virtio::dev::vsock::UdsVsockParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::vsock::VhostVsockParam;
#[cfg(target_os = "linux")]
use alioth::virtio::vu::frontend::VuFrontendParam;
use alioth::virtio::worker::WorkerApi;
use alioth::vm::Machine;
use clap::Args;
use serde::Deserialize;
use serde_aco::{Help, help_text};
use snafu::{ResultExt, Snafu};

use crate::objects::{DOC_OBJECTS, parse_objects};

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
    #[snafu(display("Failed to create a device"))]
    CreateDevice { source: alioth::vm::Error },
    #[snafu(display("Failed to boot a VM"))]
    BootVm { source: alioth::vm::Error },
    #[snafu(display("VM did not shutdown peacefully"))]
    WaitVm { source: alioth::vm::Error },
}

#[derive(Debug, Deserialize, Clone, Help)]
#[cfg_attr(target_os = "macos", derive(Default))]
enum Hypervisor {
    /// KVM backed by the Linux kernel.
    #[cfg(target_os = "linux")]
    #[serde(alias = "kvm")]
    Kvm(KvmConfig),
    /// macOS Hypervisor Framework.
    #[cfg(target_os = "macos")]
    #[serde(alias = "hvf")]
    #[default]
    Hvf,
}

#[cfg(target_os = "linux")]
impl Default for Hypervisor {
    fn default() -> Self {
        Hypervisor::Kvm(KvmConfig::default())
    }
}

#[derive(Debug, Deserialize, Clone, Help)]
enum FsParam {
    /// VirtIO FS device backed by a shared directory.
    #[serde(alias = "dir")]
    Dir(SharedDirParam),
    #[cfg(target_os = "linux")]
    /// VirtIO FS device backed by a vhost-user process, e.g. virtiofsd.
    #[serde(alias = "vu")]
    Vu(VuFsParam),
}

#[derive(Debug, Deserialize, Clone, Help)]
enum VsockParam {
    #[cfg(target_os = "linux")]
    /// Vsock device backed by host kernel vhost-vsock module.
    #[serde(alias = "vhost")]
    Vhost(VhostVsockParam),
    /// Vsock device mapped to a Unix domain socket.
    #[serde(alias = "uds")]
    Uds(UdsVsockParam),
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Help)]
struct VuSocket {
    socket: Box<Path>,
}

#[derive(Deserialize, Help)]
enum NetParam {
    /// VirtIO net device backed by TUN/TAP, MacVTap, or IPVTap.
    #[cfg(target_os = "linux")]
    #[serde(alias = "tap")]
    Tap(NetTapParam),
    /// VirtIO net device backed by vmnet framework.
    #[cfg(target_os = "macos")]
    #[serde(alias = "vmnet")]
    Vmnet(NetVmnetParam),
    /// vhost-user net device over a Unix domain socket.
    #[cfg(target_os = "linux")]
    #[serde(alias = "vu")]
    Vu(VuSocket),
}

#[derive(Deserialize, Help)]
enum BlkParam {
    /// VirtIO block device backed a disk image file.
    #[serde(alias = "file")]
    File(BlkFileParam),
    #[cfg(target_os = "linux")]
    #[serde(alias = "vu")]
    /// vhost-user block device over a Unix domain socket.
    Vu(VuSocket),
}

#[derive(Args, Debug, Clone)]
#[command(arg_required_else_help = true, alias("run"))]
pub struct BootArgs {
    #[arg(long, help(
        help_text::<Hypervisor>("Specify the Hypervisor to run on.")
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
    #[arg(long = "fw-cfg", help(
        help_text::<FwCfgItemParam>("Add an extra item to the fw_cfg device.")
    ), value_name = "ITEM")]
    fw_cfgs: Vec<String>,

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

fn add_net<H>(
    vm: &Machine<H>,
    args: Vec<String>,
    objects: &HashMap<&str, &str>,
) -> Result<(), Error>
where
    H: hv::Hypervisor + 'static,
{
    for (index, arg) in args.into_iter().enumerate() {
        #[cfg(target_os = "linux")]
        let param: NetParam = match serde_aco::from_args(&arg, objects) {
            Ok(p) => p,
            Err(_) => {
                let tap_param = serde_aco::from_args::<NetTapParam>(&arg, objects)
                    .context(error::ParseArg { arg })?;
                NetParam::Tap(tap_param)
            }
        };
        #[cfg(target_os = "macos")]
        let param: NetParam =
            serde_aco::from_args(&arg, objects).context(error::ParseArg { arg })?;
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
        }
        .context(error::CreateDevice)?;
    }
    Ok(())
}

fn add_blk<H>(
    vm: &Machine<H>,
    args: Vec<String>,
    objects: &HashMap<&str, &str>,
) -> Result<(), Error>
where
    H: hv::Hypervisor + 'static,
{
    for (index, opt) in args.into_iter().enumerate() {
        let param: BlkParam = match serde_aco::from_args(&opt, objects) {
            Ok(param) => param,
            Err(_) => match serde_aco::from_args(&opt, objects) {
                Ok(param) => BlkParam::File(param),
                Err(_) => {
                    eprintln!("Please update the cmd line to --blk file,path={opt}");
                    BlkParam::File(BlkFileParam {
                        path: PathBuf::from(opt).into(),
                        readonly: false,
                        api: WorkerApi::Mio,
                    })
                }
            },
        };
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
        }
        .context(error::CreateDevice)?;
    }
    Ok(())
}

pub fn boot(args: BootArgs) -> Result<(), Error> {
    let objects = parse_objects(&args.objects)?;
    let hv_config = if let Some(hv_cfg_opt) = args.hypervisor {
        serde_aco::from_args(&hv_cfg_opt, &objects).context(error::ParseArg { arg: hv_cfg_opt })?
    } else {
        Hypervisor::default()
    };
    let hypervisor = match hv_config {
        #[cfg(target_os = "linux")]
        Hypervisor::Kvm(kvm_config) => Kvm::new(kvm_config).context(error::Hypervisor)?,
        #[cfg(target_os = "macos")]
        Hypervisor::Hvf => Hvf {},
    };
    let coco = match args.coco {
        None => None,
        Some(c) => Some(serde_aco::from_args(&c, &objects).context(error::ParseArg { arg: c })?),
    };
    let mem_config = if let Some(s) = args.memory {
        serde_aco::from_args(&s, &objects).context(error::ParseArg { arg: s })?
    } else {
        #[cfg(target_os = "linux")]
        eprintln!(
            "Please update the cmd line to --memory size={},backend=memfd",
            args.mem_size
        );
        let size = serde_aco::from_args(&args.mem_size, &objects)
            .context(error::ParseArg { arg: args.mem_size })?;
        MemConfig {
            size,
            #[cfg(target_os = "linux")]
            backend: MemBackend::Memfd,
            #[cfg(not(target_os = "linux"))]
            backend: MemBackend::Anonymous,
            ..Default::default()
        }
    };
    let cpu_config = if let Some(s) = args.cpu {
        serde_aco::from_args(&s, &objects).context(error::ParseArg { arg: s })?
    } else {
        eprintln!("Please update the cmd line to --cpu count={}", args.num_cpu);
        CpuConfig {
            count: args.num_cpu,
        }
    };
    let board_config = BoardConfig {
        mem: mem_config,
        cpu: cpu_config,
        coco,
    };
    let vm = Machine::new(hypervisor, board_config).context(error::CreateVm)?;
    #[cfg(target_arch = "x86_64")]
    vm.add_com1().context(error::CreateDevice)?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl011().context(error::CreateDevice)?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl031();

    if args.pvpanic {
        vm.add_pvpanic().context(error::CreateDevice)?;
    }

    #[cfg(target_arch = "x86_64")]
    if args.firmware.is_some() || !args.fw_cfgs.is_empty() {
        let params = args
            .fw_cfgs
            .into_iter()
            .map(|s| serde_aco::from_args(&s, &objects).context(error::ParseArg { arg: s }))
            .collect::<Result<Vec<_>, _>>()?;
        vm.add_fw_cfg(params.into_iter())
            .context(error::CreateDevice)?;
    };

    if args.entropy {
        vm.add_virtio_dev("virtio-entropy", EntropyParam::default())
            .context(error::CreateDevice)?;
    }
    add_net(&vm, args.net, &objects)?;
    add_blk(&vm, args.blk, &objects)?;
    for (index, fs) in args.fs.into_iter().enumerate() {
        let param: FsParam =
            serde_aco::from_args(&fs, &objects).context(error::ParseArg { arg: fs })?;
        match param {
            FsParam::Dir(p) => vm.add_virtio_dev(format!("virtio-fs-{index}"), p),
            #[cfg(target_os = "linux")]
            FsParam::Vu(p) => vm.add_virtio_dev(format!("vu-fs-{index}"), p),
        }
        .context(error::CreateDevice)?;
    }
    if let Some(vsock) = args.vsock {
        let param =
            serde_aco::from_args(&vsock, &objects).context(error::ParseArg { arg: vsock })?;
        match param {
            #[cfg(target_os = "linux")]
            VsockParam::Vhost(p) => vm
                .add_virtio_dev("vhost-vsock", p)
                .context(error::CreateDevice)?,
            VsockParam::Uds(p) => vm
                .add_virtio_dev("uds-vsock", p)
                .context(error::CreateDevice)?,
        };
    }
    if let Some(balloon) = args.balloon {
        let param: BalloonParam =
            serde_aco::from_args(&balloon, &objects).context(error::ParseArg { arg: balloon })?;
        vm.add_virtio_dev("virtio-balloon", param)
            .context(error::CreateDevice)?;
    }

    #[cfg(target_os = "linux")]
    for ioas in args.vfio_ioas.into_iter() {
        let param: IoasParam =
            serde_aco::from_args(&ioas, &objects).context(error::ParseArg { arg: ioas })?;
        vm.add_vfio_ioas(param).context(error::CreateDevice)?;
    }
    #[cfg(target_os = "linux")]
    for (index, vfio) in args.vfio_cdev.into_iter().enumerate() {
        let param: CdevParam =
            serde_aco::from_args(&vfio, &objects).context(error::ParseArg { arg: vfio })?;
        vm.add_vfio_cdev(format!("vfio-{index}").into(), param)
            .context(error::CreateDevice)?;
    }

    #[cfg(target_os = "linux")]
    for container in args.vfio_container.into_iter() {
        let param: ContainerParam = serde_aco::from_args(&container, &objects)
            .context(error::ParseArg { arg: container })?;
        vm.add_vfio_container(param).context(error::CreateDevice)?;
    }
    #[cfg(target_os = "linux")]
    for (index, group) in args.vfio_group.into_iter().enumerate() {
        let param: GroupParam =
            serde_aco::from_args(&group, &objects).context(error::ParseArg { arg: group })?;
        vm.add_vfio_devs_in_group(&index.to_string(), param)
            .context(error::CreateDevice)?;
    }

    let mut payload = Payload {
        firmware: args.firmware,
        initramfs: args.initramfs,
        cmdline: args.cmdline,
        ..Default::default()
    };
    payload.executable = args.kernel.map(Executable::Linux);
    #[cfg(target_arch = "x86_64")]
    if payload.executable.is_none() {
        payload.executable = args.pvh.map(Executable::Pvh);
    }
    vm.add_payload(payload);

    vm.boot().context(error::BootVm)?;
    vm.wait().context(error::WaitVm)?;
    Ok(())
}
