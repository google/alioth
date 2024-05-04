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

use std::path::PathBuf;

use alioth::board::BoardConfig;
use alioth::hv::Kvm;
use alioth::loader::{ExecType, Payload};
use alioth::vm::Machine;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use flexi_logger::{FileSpec, Logger};

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

#[derive(Args, Debug, Clone)]
struct RunArgs {
    #[arg(short, long)]
    kernel: Option<PathBuf>,

    #[arg(long)]
    pvh: Option<PathBuf>,

    #[arg(short, long)]
    cmd_line: Option<String>,

    #[arg(short, long)]
    initramfs: Option<PathBuf>,

    #[arg(long, default_value_t = 1)]
    num_cpu: u32,

    #[arg(long, default_value = "1G")]
    mem_size: String,
}

fn parse_mem(s: &str) -> Result<usize> {
    if let Some((num, "")) = s.split_once(['g', 'G']) {
        let n = num.parse::<usize>()?;
        Ok(n << 30)
    } else if let Some((num, "")) = s.split_once(['m', 'M']) {
        let n = num.parse::<usize>()?;
        Ok(n << 20)
    } else if let Some((num, "")) = s.split_once(['k', 'K']) {
        let n = num.parse::<usize>()?;
        Ok(n << 10)
    } else {
        let n = s.parse::<usize>()?;
        Ok(n)
    }
}

fn main_run(args: RunArgs) -> Result<()> {
    let hypervisor = Kvm::new()?;
    let payload = if let Some(kernel) = args.kernel {
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
    let board_config = BoardConfig {
        mem_size: parse_mem(&args.mem_size)?,
        num_cpu: args.num_cpu,
    };
    let mut vm = Machine::new(hypervisor, board_config)?;
    #[cfg(target_arch = "x86_64")]
    vm.add_com1()?;
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
