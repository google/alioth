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
#[cfg(target_arch = "x86_64")]
use std::ffi::CString;
#[cfg(target_arch = "x86_64")]
use std::fs::File;
use std::path::PathBuf;

use alioth::board::BoardConfig;
#[cfg(target_arch = "x86_64")]
use alioth::device::fw_cfg::FwCfgItemParam;
use alioth::errors::{trace_error, DebugTrace};
use alioth::hv::Coco;
#[cfg(target_os = "macos")]
use alioth::hv::Hvf;
#[cfg(target_os = "linux")]
use alioth::hv::{Kvm, KvmConfig};
use alioth::loader::{ExecType, Payload};
use alioth::mem::{MemBackend, MemConfig};
#[cfg(target_os = "linux")]
use alioth::vfio::{CdevParam, ContainerParam, GroupParam, IoasParam};
use alioth::virtio::dev::balloon::BalloonParam;
use alioth::virtio::dev::blk::BlockParam;
use alioth::virtio::dev::entropy::EntropyParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::fs::VuFsParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::net::NetParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::vsock::VhostVsockParam;
use alioth::vm::Machine;
use clap::{Args, Parser, Subcommand};
use flexi_logger::{FileSpec, Logger};
use serde::Deserialize;
use serde_aco::{help_text, Help};
use snafu::{ResultExt, Snafu};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[arg(short, long, value_name = "SPEC")]
    /// Loglevel specification, see
    /// https://docs.rs/flexi_logger/latest/flexi_logger/struct.LogSpecification.html.
    /// If not set, environment variable $RUST_LOG is used.
    pub log_spec: Option<String>,

    /// Log to file instead of STDERR.
    #[arg(long)]
    pub log_to_file: bool,

    /// Path to a directory where the log file is stored.
    #[arg(long, value_name = "PATH")]
    pub log_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create and boot a virtual machine.
    Run(RunArgs),
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

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Clone, Help)]
enum FsParam {
    #[serde(alias = "vu")]
    /// VirtIO device backed by a vhost-user process, e.g. virtiofsd.
    Vu(VuFsParam),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Clone, Help)]
enum VsockParam {
    /// Vsock device backed by host kernel vhost-vsock module.
    #[serde(alias = "vhost")]
    Vhost(VhostVsockParam),
}

const DOC_OBJECTS: &str = r#"Supply additional data to other command line flags.
* <id>,<value>

Any value that comes after an equal sign(=) and contains a comma(,)
or equal sign can be supplied using this flag. `<id>` must start
with `id_` and `<id>` cannot contain any comma or equal sign.

Example: assuming we are going a add a virtio-blk device backed by
`/path/to/disk,2024.img` and a virtio-fs device backed by a
vhost-user process listening on socket `/path/to/socket=1`, these
2 devices can be expressed in the command line as follows:
    --blk path=id_blk --fs vu,socket=id_fs,tag=shared-dir \
    -o id_blk,/path/to/disk,2024.img \
    -o id_fs,/path/to/socket=1"#;

#[derive(Args, Debug, Clone)]
#[command(arg_required_else_help = true)]
struct RunArgs {
    #[arg(long, help(
        help_text::<Hypervisor>("Specify the Hypervisor to run on.")
    ), value_name = "HV")]
    hypervisor: Option<String>,

    /// Path to a Linux kernel image.
    #[arg(short, long, value_name = "PATH")]
    kernel: Option<PathBuf>,

    /// Path to an ELF kernel with PVH note.
    #[cfg(target_arch = "x86_64")]
    #[arg(long, value_name = "PATH")]
    pvh: Option<PathBuf>,

    /// Path to a firmware image.
    #[arg(long, short, value_name = "PATH")]
    firmware: Option<PathBuf>,

    /// Command line to pass to the kernel, e.g. `console=ttyS0`.
    #[arg(short, long, value_name = "ARGS")]
    cmd_line: Option<String>,

    /// Path to an initramfs image.
    #[arg(short, long, value_name = "PATH")]
    initramfs: Option<PathBuf>,

    /// Number of VCPUs assigned to the guest.
    #[arg(long, default_value_t = 1)]
    num_cpu: u32,

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

    #[cfg(target_os = "linux")]
    #[arg(long, help(
        help_text::<NetParam>("Add a VirtIO net device backed by TUN/TAP, MacVTap, or IPVTap.")
    ))]
    net: Vec<String>,

    #[arg(long, help(
        help_text::<BlockParam>("Add a VirtIO block device.")
    ))]
    blk: Vec<String>,

    #[arg(long, help(
        help_text::<Coco>("Enable confidential compute supported by host platform.")
    ))]
    coco: Option<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, help(
        help_text::<FsParam>("Add a VirtIO filesystem device.")
    ))]
    fs: Vec<String>,

    #[cfg(target_os = "linux")]
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

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to parse {arg}"))]
    ParseArg {
        arg: String,
        error: serde_aco::Error,
    },
    #[snafu(display("Failed to access system hypervisor"))]
    Hypervisor { source: alioth::hv::Error },
    #[snafu(display("Failed to create a VM"))]
    CreateVm { source: alioth::vm::Error },
    #[snafu(display("Failed to create a device"))]
    CreateDevice { source: alioth::vm::Error },
    #[snafu(display("Failed to open {path:?}"))]
    OpenFile {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("Failed to configure the fw-cfg device"))]
    FwCfg { error: std::io::Error },
    #[snafu(display("{s} is not a valid CString"))]
    CreateCString { s: String },
    #[snafu(display("Failed to boot a VM"))]
    BootVm { source: alioth::vm::Error },
    #[snafu(display("VM did not shutdown peacefully"))]
    WaitVm { source: alioth::vm::Error },
    #[snafu(display("Invalid object key {key:?}, must start with `id_`"))]
    InvalidKey { key: String },
    #[snafu(display("Key {key:?} showed up more than once"))]
    DuplicateKey { key: String },
}

fn main_run(args: RunArgs) -> Result<(), Error> {
    let mut objects = HashMap::new();
    for obj_s in &args.objects {
        let (key, val) = obj_s.split_once(',').unwrap_or((obj_s, ""));
        if !key.starts_with("id_") {
            return error::InvalidKey {
                key: key.to_owned(),
            }
            .fail();
        }
        if objects.insert(key, val).is_some() {
            return error::DuplicateKey {
                key: key.to_owned(),
            }
            .fail();
        }
    }
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
    let board_config = BoardConfig {
        mem: mem_config,
        num_cpu: args.num_cpu,
        coco,
    };
    let vm = Machine::new(hypervisor, board_config).context(error::CreateVm)?;
    #[cfg(target_arch = "x86_64")]
    vm.add_com1().context(error::CreateDevice)?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl011().context(error::CreateDevice)?;

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
        let fw_cfg = vm
            .add_fw_cfg(params.into_iter())
            .context(error::CreateDevice)?;
        let mut dev = fw_cfg.lock();
        #[cfg(target_arch = "x86_64")]
        if let Some(kernel) = &args.kernel {
            dev.add_kernel_data(File::open(kernel).context(error::OpenFile { path: kernel })?)
                .context(error::FwCfg)?
        }
        if let Some(initramfs) = &args.initramfs {
            dev.add_initramfs_data(
                File::open(initramfs).context(error::OpenFile { path: initramfs })?,
            )
            .context(error::FwCfg)?;
        }
        if let Some(cmdline) = &args.cmd_line {
            let Ok(cmdline_c) = CString::new(cmdline.as_str()) else {
                return error::CreateCString {
                    s: cmdline.to_owned(),
                }
                .fail();
            };
            dev.add_kernel_cmdline(cmdline_c);
        }
    };

    if args.entropy {
        vm.add_virtio_dev("virtio-entropy", EntropyParam)
            .context(error::CreateDevice)?;
    }
    #[cfg(target_os = "linux")]
    for (index, net_opt) in args.net.into_iter().enumerate() {
        let net_param: NetParam =
            serde_aco::from_args(&net_opt, &objects).context(error::ParseArg { arg: net_opt })?;
        vm.add_virtio_dev(format!("virtio-net-{index}"), net_param)
            .context(error::CreateDevice)?;
    }
    for (index, blk) in args.blk.into_iter().enumerate() {
        let param = match serde_aco::from_args(&blk, &objects) {
            Ok(param) => param,
            Err(serde_aco::Error::ExpectedMapEq) => {
                eprintln!("Please update the cmd line to --blk path={blk}, see https://github.com/google/alioth/pull/72 for details");
                BlockParam {
                    path: blk.into(),
                    ..Default::default()
                }
            }
            Err(e) => return Err(e).context(error::ParseArg { arg: blk })?,
        };

        vm.add_virtio_dev(format!("virtio-blk-{index}"), param)
            .context(error::CreateDevice)?;
    }
    #[cfg(target_os = "linux")]
    for (index, fs) in args.fs.into_iter().enumerate() {
        let param: FsParam =
            serde_aco::from_args(&fs, &objects).context(error::ParseArg { arg: fs })?;
        match param {
            FsParam::Vu(p) => vm
                .add_virtio_dev(format!("vu-fs-{index}"), p)
                .context(error::CreateDevice)?,
        };
    }
    #[cfg(target_os = "linux")]
    if let Some(vsock) = args.vsock {
        let param =
            serde_aco::from_args(&vsock, &objects).context(error::ParseArg { arg: vsock })?;
        match param {
            VsockParam::Vhost(p) => vm
                .add_virtio_dev("vhost-vsock", p)
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

    let payload = if let Some(fw) = args.firmware {
        Some(Payload {
            executable: fw,
            exec_type: ExecType::Firmware,
            initramfs: None,
            cmd_line: None,
        })
    } else if let Some(kernel) = args.kernel {
        Some(Payload {
            exec_type: ExecType::Linux,
            executable: kernel,
            initramfs: args.initramfs,
            cmd_line: args.cmd_line,
        })
    } else {
        #[cfg(target_arch = "x86_64")]
        if let Some(pvh_kernel) = args.pvh {
            Some(Payload {
                executable: pvh_kernel,
                exec_type: ExecType::Pvh,
                initramfs: args.initramfs,
                cmd_line: args.cmd_line,
            })
        } else {
            None
        }
        #[cfg(not(target_arch = "x86_64"))]
        None
    };
    if let Some(payload) = payload {
        vm.add_payload(payload);
    }

    vm.boot().context(error::BootVm)?;
    for result in vm.wait() {
        result.context(error::WaitVm)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let logger = if let Some(ref spec) = cli.log_spec {
        Logger::try_with_str(spec)
    } else {
        Logger::try_with_env_or_str("warn")
    }?;
    let logger = if cli.log_to_file {
        logger.log_to_file(
            FileSpec::default()
                .suppress_timestamp()
                .o_directory(cli.log_dir),
        )
    } else {
        logger
    };
    let _handle = logger.start()?;
    log::debug!(
        "{} {} started...",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );

    match cli.cmd {
        Command::Run(args) => main_run(args)?,
    }
    Ok(())
}
