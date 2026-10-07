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
#![allow(clippy::missing_safety_doc)]

use std::path::{Path, PathBuf};

pub mod ioctls;
#[path = "kvm/kvm.rs"]
pub mod kvm;
pub mod serial;
pub mod tap;
pub mod wasm_host;

#[cfg(feature = "compiler")]
const DEFAULT_COMPONENT_FILENAME: &str = "vmm-runner.wasm";
#[cfg(not(feature = "compiler"))]
const DEFAULT_COMPONENT_FILENAME: &str = "vmm-runner.cwasm";

fn print_usage_and_exit() -> ! {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string());
    eprintln!("Usage: `{prog} -c $CONFIG_FILENAME_TOML [-w $COMPONENT_PATH]`.");
    std::process::exit(1)
}

fn find_default_component() -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        for rel in [
            DEFAULT_COMPONENT_FILENAME.to_string(),
            format!("../wasm32-wasip2/release/{DEFAULT_COMPONENT_FILENAME}"),
            format!("../../wasm32-wasip2/release/{DEFAULT_COMPONENT_FILENAME}"),
        ] {
            let candidate = exe_dir.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let cwd_candidate = PathBuf::from(DEFAULT_COMPONENT_FILENAME);
    if cwd_candidate.is_file() {
        return Some(cwd_candidate);
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_filename: Option<String> = None;
    let mut wasm_path: Option<PathBuf> = std::env::var("VMM_RUNNER_WASM").ok().map(PathBuf::from);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                config_filename = Some(args[i].clone());
            }
            "-w" | "--wasm" | "--cwasm" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                wasm_path = Some(PathBuf::from(&args[i]));
            }
            _ => print_usage_and_exit(),
        }
        i += 1;
    }

    let Some(config_filename) = config_filename else {
        print_usage_and_exit();
    };

    let component_path = wasm_path.or_else(find_default_component).ok_or_else(|| {
        format!(
            "Could not find {DEFAULT_COMPONENT_FILENAME}; pass -w <path/to/{DEFAULT_COMPONENT_FILENAME}> or place it next to the host binary"
        )
    })?;

    wasm_host::run_wasm_vmm(Path::new(&component_path), &config_filename)
}
