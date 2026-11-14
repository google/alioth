// Copyright 2026 Google LLC
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
use std::sync::Arc;

pub mod motor_host;

#[path = "../../../vmm-io-host/src/verify_no_fp.rs"]
pub mod verify_no_fp;

#[path = "../../../vmm-io-host/src/wasm_host.rs"]
pub mod wasm_host;

#[cfg(target_os = "motor")]
#[path = "../../../../motor-dev/motor-os/external-sources/wasmtime/src/motor_memory.rs"]
mod motor_memory;

#[cfg(target_os = "motor")]
#[path = "../../../../motor-dev/motor-os/external-sources/wasmtime/src/motor_stack.rs"]
mod motor_stack;

#[cfg(target_os = "motor")]
thread_local! {
    static MOTOR_WASMTIME_TLS: [std::cell::Cell<*mut u8>; 2] = const {
        [
            std::cell::Cell::new(std::ptr::null_mut()),
            std::cell::Cell::new(std::ptr::null_mut()),
        ]
    };
}

#[cfg(target_os = "motor")]
#[unsafe(no_mangle)]
pub extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    MOTOR_WASMTIME_TLS.with(|slots| slots[slot].get())
}

#[cfg(target_os = "motor")]
#[unsafe(no_mangle)]
pub extern "C" fn wasmtime_tls_set(slot: usize, pointer: *mut u8) {
    MOTOR_WASMTIME_TLS.with(|slots| slots[slot].set(pointer));
}

#[cfg(feature = "compiler")]
const DEFAULT_IO_COMPONENT_FILENAME: &str = "vmm-io.wasm";
#[cfg(not(feature = "compiler"))]
const DEFAULT_IO_COMPONENT_FILENAME: &str = "vmm-io.cwasm";

const DEFAULT_CORE_COMPONENT_FILENAME: &str = "vmm-core.cwasm";

fn print_usage_and_exit() -> ! {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string());
    eprintln!(
        "Usage: `{prog} -c $CONFIG_FILENAME_TOML [-w $IO_COMPONENT_PATH] [--core-wasm $CORE_CWASM_PATH]`."
    );
    std::process::exit(1);
}

fn find_artifact(filename: &str, config_path: &Path) -> Option<PathBuf> {
    if let Some(cfg_dir) = config_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let candidate = cfg_dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        let candidate = exe_dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let cwd_candidate = PathBuf::from(filename);
    if cwd_candidate.is_file() {
        return Some(cwd_candidate);
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_filename: Option<String> = None;
    let mut io_wasm_path: Option<PathBuf> = std::env::var("VMM_IO_WASM").ok().map(PathBuf::from);
    let mut core_wasm_path: Option<PathBuf> =
        std::env::var("VMM_CORE_WASM").ok().map(PathBuf::from);

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
            "-w" | "--wasm" | "--cwasm" | "--io-wasm" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                io_wasm_path = Some(PathBuf::from(&args[i]));
            }
            "--core-wasm" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                core_wasm_path = Some(PathBuf::from(&args[i]));
            }
            _ if config_filename.is_none() && !args[i].starts_with('-') => {
                config_filename = Some(args[i].clone());
            }
            _ => print_usage_and_exit(),
        }
        i += 1;
    }

    let Some(config_filename) = config_filename else {
        print_usage_and_exit();
    };
    let config_path = Path::new(&config_filename);

    let io_component = io_wasm_path
        .or_else(|| find_artifact(DEFAULT_IO_COMPONENT_FILENAME, config_path))
        .ok_or_else(|| {
            format!(
                "Could not find {DEFAULT_IO_COMPONENT_FILENAME}; pass -w <path/to/{DEFAULT_IO_COMPONENT_FILENAME}>"
            )
        })?;

    let core_component = core_wasm_path
        .or_else(|| find_artifact(DEFAULT_CORE_COMPONENT_FILENAME, config_path))
        .or_else(|| find_artifact("vmm-core-motor.cwasm", config_path))
        .ok_or_else(|| {
            format!(
                "Could not find {DEFAULT_CORE_COMPONENT_FILENAME}; pass --core-wasm <path/to/{DEFAULT_CORE_COMPONENT_FILENAME}>"
            )
        })?;

    let host = motor_host::MotorIoHost::new(core_component)?;
    let run_res = wasm_host::run_wasm_io_with_config(
        &io_component,
        &config_filename,
        host.clone(),
        |config| {
            #[cfg(target_os = "motor")]
            {
                config.with_host_stack(Arc::new(motor_stack::StackPool::default()));
                config.with_host_memory(Arc::new(motor_memory::Reservations::default()));
            }
            Ok(())
        },
    );
    host.shutdown();
    run_res
}
