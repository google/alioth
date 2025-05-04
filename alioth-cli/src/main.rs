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

mod boot;
mod objects;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use flexi_logger::{FileSpec, Logger};

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
    Boot(boot::BootArgs),
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
        Command::Boot(args) => boot::boot(args)?,
    }
    Ok(())
}
