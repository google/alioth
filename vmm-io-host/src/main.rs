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

use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use libc::{EFD_NONBLOCK, eventfd, ftruncate};
use vmm_core::host::abi::BridgeShm;

pub mod ioctls;
pub mod linux_host;
pub mod serial;
pub mod tap;
pub mod verify_no_fp;
pub mod wasm_host;

#[cfg(feature = "compiler")]
const DEFAULT_IO_COMPONENT_FILENAME: &str = "vmm-io.wasm";
#[cfg(not(feature = "compiler"))]
const DEFAULT_IO_COMPONENT_FILENAME: &str = "vmm-io.cwasm";

#[cfg(feature = "compiler")]
const DEFAULT_CORE_HOST_BIN: &str = "vmm-core-host-wasm";
#[cfg(not(feature = "compiler"))]
const DEFAULT_CORE_HOST_BIN: &str = "vmm-core-host-cwasm";

#[cfg(feature = "compiler")]
const DEFAULT_CORE_COMPONENT_FILENAME: &str = "vmm-core.wasm";
#[cfg(not(feature = "compiler"))]
const DEFAULT_CORE_COMPONENT_FILENAME: &str = "vmm-core.cwasm";

fn print_usage_and_exit() -> ! {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string());
    eprintln!(
        "Usage: `{prog} -c $CONFIG_FILENAME_TOML [-w $IO_COMPONENT_PATH] [--core-host $CORE_HOST_BIN] [--core-wasm $CORE_COMPONENT_PATH]`."
    );
    std::process::exit(1)
}

fn find_sibling_file(filename: &str) -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        for rel in [
            filename.to_string(),
            format!("../wasm32-wasip1-threads/release/{filename}"),
            format!("../../wasm32-wasip1-threads/release/{filename}"),
            format!("../wasm32-unknown-unknown/release/{filename}"),
            format!("../../wasm32-unknown-unknown/release/{filename}"),
        ] {
            let candidate = exe_dir.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let cwd_candidate = PathBuf::from(filename);
    if cwd_candidate.is_file() {
        return Some(cwd_candidate);
    }
    None
}

fn create_memfd(name: &str) -> std::io::Result<RawFd> {
    let cname = CString::new(name).unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, cname.as_ptr(), 0) as RawFd };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn create_eventfd(flags: libc::c_int) -> std::io::Result<RawFd> {
    let fd = unsafe { eventfd(0, flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_filename: Option<String> = None;
    let mut io_wasm_path: Option<PathBuf> = std::env::var("VMM_IO_WASM").ok().map(PathBuf::from);
    let mut core_host_path: Option<PathBuf> =
        std::env::var("VMM_CORE_HOST").ok().map(PathBuf::from);
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
            "--core-host" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                core_host_path = Some(PathBuf::from(&args[i]));
            }
            "--core-wasm" => {
                i += 1;
                if i >= args.len() {
                    print_usage_and_exit();
                }
                core_wasm_path = Some(PathBuf::from(&args[i]));
            }
            _ => print_usage_and_exit(),
        }
        i += 1;
    }

    let Some(config_filename) = config_filename else {
        print_usage_and_exit();
    };

    let io_component = io_wasm_path
        .or_else(|| find_sibling_file(DEFAULT_IO_COMPONENT_FILENAME))
        .ok_or_else(|| {
            format!(
                "Could not find {DEFAULT_IO_COMPONENT_FILENAME}; pass -w <path/to/{DEFAULT_IO_COMPONENT_FILENAME}>"
            )
        })?;

    let core_host = core_host_path
        .or_else(|| find_sibling_file(DEFAULT_CORE_HOST_BIN))
        .ok_or_else(|| {
            format!(
                "Could not find {DEFAULT_CORE_HOST_BIN}; pass --core-host <path/to/{DEFAULT_CORE_HOST_BIN}>"
            )
        })?;

    let core_component = core_wasm_path
        .or_else(|| find_sibling_file(DEFAULT_CORE_COMPONENT_FILENAME))
        .ok_or_else(|| {
            format!(
                "Could not find {DEFAULT_CORE_COMPONENT_FILENAME}; pass --core-wasm <path/to/{DEFAULT_CORE_COMPONENT_FILENAME}>"
            )
        })?;

    let bridge_fd = create_memfd("vmm_bridge_shm")?;
    let shm_size = std::mem::size_of::<BridgeShm>();
    if unsafe { ftruncate(bridge_fd, shm_size as libc::off_t) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let ram_fd = create_memfd("vmm_guest_ram")?;
    let payload_fd = create_memfd("vmm_payload")?;
    let c2i_fd = create_eventfd(EFD_NONBLOCK)?;
    let i2c_fd = create_eventfd(EFD_NONBLOCK)?;
    let cfg_fd = create_eventfd(0)?;

    let io_host = linux_host::LinuxIoHost::new(linux_host::IoBridgeFds {
        bridge_fd,
        ram_fd,
        payload_fd,
        c2i_fd,
        i2c_fd,
        cfg_fd,
    })?;

    let mut core_child = Command::new(&core_host)
        .arg("--bridge-fd")
        .arg(bridge_fd.to_string())
        .arg("--ram-fd")
        .arg(ram_fd.to_string())
        .arg("--payload-fd")
        .arg(payload_fd.to_string())
        .arg("--c2i-fd")
        .arg(c2i_fd.to_string())
        .arg("--i2c-fd")
        .arg(i2c_fd.to_string())
        .arg("--cfg-fd")
        .arg(cfg_fd.to_string())
        .arg("-w")
        .arg(&core_component)
        .spawn()
        .map_err(|e| format!("Failed to spawn {core_host:?}: {e}"))?;

    let io_res = wasm_host::run_wasm_io(Path::new(&io_component), &config_filename, io_host.clone());

    io_host.shutdown_bridge();

    let _ = core_child.wait();
    io_res
}
