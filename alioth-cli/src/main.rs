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
use alioth::hv::{Kvm, KvmConfig};
use alioth::loader::{ExecType, Payload};
use alioth::virtio::dev::blk::BlockParam;
use alioth::virtio::dev::entropy::EntropyParam;
use alioth::virtio::dev::fs::VuFsParam;
use alioth::virtio::dev::net::NetParam;
use alioth::virtio::dev::vsock::VhostVsockParam;
use alioth::vm::Machine;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use flexi_logger::{FileSpec, Logger};
use serde::Deserialize;

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
enum Hypervisor {
    #[serde(alias = "kvm")]
    Kvm(KvmConfig),
}

impl Default for Hypervisor {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        Hypervisor::Kvm(KvmConfig::default())
    }
}

#[derive(Debug, Deserialize, Clone)]
enum FsParam {
    #[serde(alias = "vu")]
    Vu(VuFsParam),
}

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

fn main_run(args: RunArgs) -> Result<()> {
    let hv_config = if let Some(hv_cfg_opt) = args.hypervisor {
        serde_aco::from_arg(&hv_cfg_opt)?
    } else {
        Hypervisor::default()
    };
    let hypervisor = match hv_config {
        Hypervisor::Kvm(kvm_config) => Kvm::new(kvm_config),
    }?;
    let coco = match args.coco {
        None => None,
        Some(c) => Some(serde_aco::from_arg(&c)?),
    };
    let board_config = BoardConfig {
        mem_size: serde_aco::from_arg(&args.mem_size)?,
        num_cpu: args.num_cpu,
        coco,
    };
    let mut vm = Machine::new(hypervisor, board_config)?;
    #[cfg(target_arch = "x86_64")]
    vm.add_com1()?;

    if args.pvpanic {
        vm.add_pvpanic()?;
    }

    if args.firmware.is_some() || !args.fw_cfgs.is_empty() {
        let params = args
            .fw_cfgs
            .iter()
            .map(|s| serde_aco::from_arg(s))
            .collect::<Result<Vec<_>, _>>()?;
        let fw_cfg = vm.add_fw_cfg(params.into_iter())?;
        let mut dev = fw_cfg.lock();
        if let Some(kernel) = &args.kernel {
            dev.add_kernel_data(File::open(kernel)?)?
        }
        if let Some(initramfs) = &args.initramfs {
            dev.add_initramfs_data(File::open(initramfs)?)?;
        }
        if let Some(cmdline) = &args.cmd_line {
            let cmdline_c = CString::new(cmdline.as_str())?;
            dev.add_kernel_cmdline(cmdline_c);
        }
    };

    if args.entropy {
        vm.add_virtio_dev("virtio-entropy".to_owned(), EntropyParam)?;
    }
    for (index, net_opt) in args.net.into_iter().enumerate() {
        let net_param: NetParam = serde_aco::from_arg(&net_opt)?;
        vm.add_virtio_dev(format!("virtio-net-{index}"), net_param)?;
    }
    for (index, blk) in args.blk.into_iter().enumerate() {
        let param = BlockParam { path: blk.into() };
        vm.add_virtio_dev(format!("virtio-blk-{index}"), param)?;
    }
    for (index, fs) in args.fs.into_iter().enumerate() {
        let param: FsParam = serde_aco::from_arg(&fs)?;
        match param {
            FsParam::Vu(p) => vm.add_virtio_dev(format!("vu-fs-{index}"), p)?,
        };
    }
    if let Some(vsock) = args.vsock {
        let param = serde_aco::from_arg(&vsock)?;
        match param {
            VsockParam::Vhost(p) => vm.add_virtio_dev("vhost-vsock".to_owned(), p)?,
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
    } else if let Some(pvh_kernel) = args.pvh {
        Some(Payload {
            executable: pvh_kernel,
            exec_type: ExecType::Pvh,
            initramfs: args.initramfs,
            cmd_line: args.cmd_line,
        })
    } else {
        None
    };
    if let Some(payload) = payload {
        vm.add_payload(payload);
    }

    vm.boot()?;
    for result in vm.wait() {
        result?;
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
