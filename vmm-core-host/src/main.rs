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

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod ioctls;
#[path = "kvm/kvm.rs"]
pub mod kvm;
pub mod linux_host;
pub mod verify_no_fp;
pub mod wasm_host;

#[cfg(feature = "compiler")]
const DEFAULT_COMPONENT_FILENAME: &str = "vmm-core.wasm";
#[cfg(not(feature = "compiler"))]
const DEFAULT_COMPONENT_FILENAME: &str = "vmm-core.cwasm";

fn print_usage_and_exit() -> ! {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string());
    eprintln!(
        "Usage: `{prog} --bridge-fd <fd> --ram-fd <fd> --payload-fd <fd> --c2i-fd <fd> --i2c-fd <fd> --cfg-fd <fd> [-w $COMPONENT_PATH]`."
    );
    std::process::exit(1)
}

fn find_default_component() -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        for rel in [
            DEFAULT_COMPONENT_FILENAME.to_string(),
            format!("../wasm32-wasip1-threads/release/{DEFAULT_COMPONENT_FILENAME}"),
            format!("../../wasm32-wasip1-threads/release/{DEFAULT_COMPONENT_FILENAME}"),
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
    let mut bridge_fd: Option<RawFd> = None;
    let mut ram_fd: Option<RawFd> = None;
    let mut payload_fd: Option<RawFd> = None;
    let mut c2i_fd: Option<RawFd> = None;
    let mut i2c_fd: Option<RawFd> = None;
    let mut cfg_fd: Option<RawFd> = None;
    let mut wasm_path: Option<PathBuf> = std::env::var("VMM_CORE_WASM").ok().map(PathBuf::from);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bridge-fd" => {
                i += 1;
                bridge_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--ram-fd" => {
                i += 1;
                ram_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--payload-fd" => {
                i += 1;
                payload_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--c2i-fd" => {
                i += 1;
                c2i_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--i2c-fd" => {
                i += 1;
                i2c_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--cfg-fd" => {
                i += 1;
                cfg_fd = args.get(i).and_then(|s| s.parse().ok());
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

    let (
        Some(bridge_fd),
        Some(ram_fd),
        Some(payload_fd),
        Some(c2i_fd),
        Some(i2c_fd),
        Some(cfg_fd),
    ) = (bridge_fd, ram_fd, payload_fd, c2i_fd, i2c_fd, cfg_fd)
    else {
        print_usage_and_exit();
    };

    let component_path = wasm_path.or_else(find_default_component).ok_or_else(|| {
        format!(
            "Could not find {DEFAULT_COMPONENT_FILENAME}; pass -w <path/to/{DEFAULT_COMPONENT_FILENAME}> or place it next to the host binary"
        )
    })?;

    let host = Arc::new(linux_host::KvmCoreHost::new(kvm::CoreBridgeFds {
        bridge_fd,
        ram_fd,
        payload_fd,
        c2i_fd,
        i2c_fd,
        cfg_fd,
    })?);

    wasm_host::run_wasm_core(Path::new(&component_path), host)
}
