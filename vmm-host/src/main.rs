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

pub mod ioctls;
#[path = "kvm/kvm.rs"]
pub mod kvm;
pub mod serial;
pub mod tap;
pub mod wasm_host;

static VMM_RUNNER_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vmm-runner.wasm"));

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: `{} -c $CONFIG_FILENAME_TOML [-w $WASM_COMPONENT_PATH]`.",
        env!("CARGO_PKG_NAME")
    );
    std::process::exit(1)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_filename: Option<String> = None;
    let mut wasm_path: Option<String> = std::env::var("VMM_RUNNER_WASM").ok();

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
            "-w" | "--wasm" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                wasm_path = Some(args[i].clone());
            }
            _ => print_usage_and_exit(),
        }
        i += 1;
    }

    let Some(config_filename) = config_filename else {
        print_usage_and_exit();
    };

    if wasm_path.is_none() {
        if let Ok(exe_path) = std::env::current_exe()
            && let Some(exe_dir) = exe_path.parent()
        {
            let candidate = exe_dir.join("vmm-runner.wasm");
            if candidate.is_file() {
                wasm_path = candidate.to_str().map(|s| s.to_owned());
            }
        }
        if wasm_path.is_none() && std::path::Path::new("vmm-runner.wasm").is_file() {
            wasm_path = Some("vmm-runner.wasm".to_owned());
        }
    }

    if let Some(wasm_path) = wasm_path {
        let wasm_bytes = std::fs::read(wasm_path)?;
        wasm_host::run_wasm_vmm(&wasm_bytes, &config_filename)
    } else {
        wasm_host::run_wasm_vmm(VMM_RUNNER_WASM, &config_filename)
    }
}
