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

use std::env;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use wasmtime::{Config, Engine};

#[path = "src/verify_no_fp.rs"]
mod verify_no_fp;

fn read_uleb(buf: &[u8], mut pos: usize) -> (u32, usize) {
    let mut res = 0u32;
    let mut shift = 0u32;
    loop {
        let b = buf[pos];
        pos += 1;
        res |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            return (res, pos);
        }
        shift += 7;
    }
}

fn rewrite_wasm_memory_copy(wasm_bytes: &mut [u8]) {
    let mut pos = 8;
    let mut memcpy_idx: Option<u32> = None;
    let mut code_range: Option<(usize, usize)> = None;

    while pos < wasm_bytes.len() {
        let sec_id = wasm_bytes[pos];
        pos += 1;
        let (sec_len, next_pos) = read_uleb(wasm_bytes, pos);
        pos = next_pos;
        let sec_end = pos + sec_len as usize;

        if sec_id == 7 {
            let (count, mut p) = read_uleb(wasm_bytes, pos);
            for _ in 0..count {
                let (name_len, next_p) = read_uleb(wasm_bytes, p);
                p = next_p;
                let name = std::str::from_utf8(&wasm_bytes[p..p + name_len as usize]).unwrap_or("");
                p += name_len as usize;
                let kind = wasm_bytes[p];
                p += 1;
                let (idx, next_p) = read_uleb(wasm_bytes, p);
                p = next_p;
                if name == "__vmm_memcpy" && kind == 0 {
                    memcpy_idx = Some(idx);
                }
            }
        } else if sec_id == 10 {
            code_range = Some((pos, sec_end));
        }

        pos = sec_end;
    }

    let idx = memcpy_idx.expect("__vmm_memcpy export not found in vmm-io.wasm");
    let (code_start, code_end) = code_range.expect("Code section not found in vmm-io.wasm");
    let call_bytes = [
        0x10u8,
        0x80 | ((idx & 0x7f) as u8),
        0x80 | (((idx >> 7) & 0x7f) as u8),
        ((idx >> 14) & 0x7f) as u8,
    ];

    let mut i = code_start;
    while i + 4 <= code_end {
        if wasm_bytes[i..i + 4] == [0xfc, 0x0a, 0x00, 0x00] {
            wasm_bytes[i..i + 4].copy_from_slice(&call_bytes);
            i += 4;
        } else {
            i += 1;
        }
    }
}

fn main() {
    let target = env::var("TARGET").unwrap();
    println!("cargo:rustc-env=VMM_HOST_TARGET={target}");
    if env::var_os("VMM_IO_HOST_INNER_BUILD").is_some() {
        return;
    }

    println!("cargo:rerun-if-changed=../vmm-io/src");
    println!("cargo:rerun-if-changed=../vmm-io/Cargo.toml");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap();
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("Failed to locate target profile directory from OUT_DIR")
        .to_path_buf();

    let wasm_target_dir = out_dir.join("wasm-target");
    let io_manifest = manifest_dir.join("../vmm-io/Cargo.toml");
    let host_manifest = manifest_dir.join("Cargo.toml");

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .arg("build")
        .arg("--manifest-path")
        .arg(&io_manifest)
        .arg("--bin")
        .arg("vmm-io")
        .arg("--target")
        .arg("wasm32-wasip1-threads")
        .arg("--target-dir")
        .arg(&wasm_target_dir)
        .arg("--release")
        .arg("--offline")
        .env("RUSTFLAGS", "-C target-feature=-bulk-memory,-simd128")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("Failed to invoke cargo to build vmm-io for wasm32-wasip1-threads");

    if !status.success() {
        panic!("Building vmm-io for wasm32-wasip1-threads failed");
    }

    let built_wasm = wasm_target_dir.join("wasm32-wasip1-threads/release/vmm-io.wasm");
    let mut wasm_bytes = fs::read(&built_wasm).expect("Failed to read built vmm-io.wasm");
    rewrite_wasm_memory_copy(&mut wasm_bytes);
    verify_no_fp::validate_wasm_no_fp(&wasm_bytes)
        .expect("vmm-io.wasm failed zero-FP/SIMD validation");

    let mut config = Config::new();
    config.wasm_threads(true);
    config.shared_memory(true);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    config
        .target(&target)
        .expect("Failed to configure Wasmtime target");
    let engine = Engine::new(&config).expect("Failed to create Wasmtime engine");
    let cwasm_bytes = engine
        .precompile_module(&wasm_bytes)
        .expect("Failed to precompile vmm-io.wasm to cwasm");
    verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes)
        .expect("vmm-io.cwasm failed zero-FP/SIMD machine-code validation");

    fs::write(out_dir.join("vmm-io.wasm"), &wasm_bytes)
        .expect("Failed to write vmm-io.wasm to OUT_DIR");
    fs::write(out_dir.join("vmm-io.cwasm"), &cwasm_bytes)
        .expect("Failed to write vmm-io.cwasm to OUT_DIR");

    let _ = fs::write(profile_dir.join("vmm-io.wasm"), &wasm_bytes);
    let _ = fs::write(profile_dir.join("vmm-io.cwasm"), &cwasm_bytes);

    let repo_wasm_release_dir = manifest_dir.join("../target/wasm32-wasip1-threads/release");
    let _ = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&repo_wasm_release_dir);
    let _ = fs::write(repo_wasm_release_dir.join("vmm-io.wasm"), &wasm_bytes);
    let _ = fs::write(repo_wasm_release_dir.join("vmm-io.cwasm"), &cwasm_bytes);

    if env::var_os("CARGO_FEATURE_COMPILER").is_none() {
        let compiler_target_dir = out_dir.join("compiler-host-target");
        let mut cmd = Command::new(&cargo);
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(&host_manifest)
            .arg("--bin")
            .arg("vmm-io-host-cwasm")
            .arg("--features")
            .arg("compiler")
            .arg("--target")
            .arg(&target)
            .arg("--target-dir")
            .arg(&compiler_target_dir)
            .arg("--offline")
            .env("VMM_IO_HOST_INNER_BUILD", "1");
        if profile == "release" {
            cmd.arg("--release");
        }
        let status = cmd
            .status()
            .expect("Failed to invoke cargo to build vmm-io-host-wasm");
        if !status.success() {
            panic!("Building vmm-io-host-wasm (with compiler feature) failed");
        }

        let built_host_wasm = compiler_target_dir
            .join(&target)
            .join(&profile)
            .join("vmm-io-host-cwasm");
        let dst_host_wasm = profile_dir.join("vmm-io-host-wasm");
        fs::copy(&built_host_wasm, &dst_host_wasm)
            .expect("Failed to copy built vmm-io-host-wasm to target profile directory");
        let _ = fs::set_permissions(&dst_host_wasm, fs::Permissions::from_mode(0o750));
    }
}
