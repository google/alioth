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

use std::ffi::CString;
use std::fs::File;
use std::path::PathBuf;

use alioth::board::BoardConfig;
use alioth::errors::{trace_error, DebugTrace};
#[cfg(target_os = "macos")]
use alioth::hv::Hvf;
#[cfg(target_os = "linux")]
use alioth::hv::{Kvm, KvmConfig};
use alioth::loader::{ExecType, Payload};
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
use snafu::{ResultExt, Snafu};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[arg(short, long)]
    /// Loglevel specification, see
    /// https://docs.rs/flexi_logger/0.25.5/flexi_logger/struct.LogSpecification.html.
    /// If not set, environment variable $RUST_LOG is used.
    pub log_spec: Option<String>,

    #[arg(long)]
    pub log_to_file: bool,

    #[arg(long)]
    pub log_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run(RunArgs),
}

#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(target_os = "macos", derive(Default))]
enum Hypervisor {
    #[cfg(target_os = "linux")]
    #[serde(alias = "kvm")]
    Kvm(KvmConfig),
    #[cfg(target_os = "macos")]
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
#[derive(Debug, Deserialize, Clone)]
enum FsParam {
    #[serde(alias = "vu")]
    Vu(VuFsParam),
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Clone)]
enum VsockParam {
    #[serde(alias = "vhost")]
    Vhost(VhostVsockParam),
}

#[derive(Args, Debug, Clone)]
struct RunArgs {
    #[arg(long)]
    hypervisor: Option<String>,

    #[arg(short, long)]
    kernel: Option<PathBuf>,

    #[cfg(target_arch = "x86_64")]
    #[arg(long)]
    pvh: Option<PathBuf>,

    #[arg(long, short)]
    firmware: Option<PathBuf>,

    #[arg(short, long)]
    cmd_line: Option<String>,

    #[arg(short, long)]
    initramfs: Option<PathBuf>,

    #[arg(long, default_value_t = 1)]
    num_cpu: u32,

    #[arg(long, default_value = "1G")]
    mem_size: String,

    #[arg(long)]
    pvpanic: bool,

    #[arg(long = "fw-cfg")]
    fw_cfgs: Vec<String>,

    #[arg(long)]
    entropy: bool,

    #[arg(long)]
    net: Vec<String>,

    #[arg(long)]
    blk: Vec<String>,

    #[arg(long)]
    coco: Option<String>,

    #[arg(long)]
    fs: Vec<String>,

    #[arg(long)]
    vsock: Option<String>,
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
}

fn main_run(args: RunArgs) -> Result<(), Error> {
    let hv_config = if let Some(hv_cfg_opt) = args.hypervisor {
        serde_aco::from_arg(&hv_cfg_opt).context(error::ParseArg { arg: hv_cfg_opt })?
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
        Some(c) => Some(serde_aco::from_arg(&c).context(error::ParseArg { arg: c })?),
    };
    let board_config = BoardConfig {
        mem_size: serde_aco::from_arg(&args.mem_size)
            .context(error::ParseArg { arg: args.mem_size })?,
        num_cpu: args.num_cpu,
        coco,
    };
    let mut vm = Machine::new(hypervisor, board_config).context(error::CreateVm)?;
    #[cfg(target_arch = "x86_64")]
    vm.add_com1().context(error::CreateDevice)?;
    #[cfg(target_arch = "aarch64")]
    vm.add_pl011().context(error::CreateDevice)?;

    if args.pvpanic {
        vm.add_pvpanic().context(error::CreateDevice)?;
    }

    if args.firmware.is_some() || !args.fw_cfgs.is_empty() {
        let params = args
            .fw_cfgs
            .into_iter()
            .map(|s| serde_aco::from_arg(&s).context(error::ParseArg { arg: s }))
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
        vm.add_virtio_dev("virtio-entropy".to_owned(), EntropyParam)
            .context(error::CreateDevice)?;
    }
    #[cfg(target_os = "linux")]
    for (index, net_opt) in args.net.into_iter().enumerate() {
        let net_param: NetParam =
            serde_aco::from_arg(&net_opt).context(error::ParseArg { arg: net_opt })?;
        vm.add_virtio_dev(format!("virtio-net-{index}"), net_param)
            .context(error::CreateDevice)?;
    }
    for (index, blk) in args.blk.into_iter().enumerate() {
        let param = match serde_aco::from_arg(&blk) {
            Ok(param) => param,
            Err(serde_aco::Error::ExpectedMapEq) => {
                eprintln!("Please update the cmd line to --blk path={blk}, see https://github.com/google/alioth/pull/72 for details");
                BlockParam {
                    path: blk.into(),
                    readonly: false,
                }
            }
            Err(e) => return Err(e).context(error::ParseArg { arg: blk })?,
        };

        vm.add_virtio_dev(format!("virtio-blk-{index}"), param)
            .context(error::CreateDevice)?;
    }
    #[cfg(target_os = "linux")]
    for (index, fs) in args.fs.into_iter().enumerate() {
        let param: FsParam = serde_aco::from_arg(&fs).context(error::ParseArg { arg: fs })?;
        match param {
            FsParam::Vu(p) => vm
                .add_virtio_dev(format!("vu-fs-{index}"), p)
                .context(error::CreateDevice)?,
        };
    }
    #[cfg(target_os = "linux")]
    if let Some(vsock) = args.vsock {
        let param = serde_aco::from_arg(&vsock).context(error::ParseArg { arg: vsock })?;
        match param {
            VsockParam::Vhost(p) => vm
                .add_virtio_dev("vhost-vsock".to_owned(), p)
                .context(error::CreateDevice)?,
        };
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
    let Some(cmd) = cli.cmd else {
        return Ok(());
    };

    match cmd {
        Command::Run(args) => main_run(args)?,
    }
    Ok(())
}
