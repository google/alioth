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

fn main() {
    let target = env::var("TARGET").unwrap();
    println!("cargo:rustc-env=VMM_HOST_TARGET={target}");
    if env::var_os("VMM_CORE_HOST_INNER_BUILD").is_some() {
        return;
    }

    println!("cargo:rerun-if-changed=../vmm-core/src");
    println!("cargo:rerun-if-changed=../vmm-core/Cargo.toml");
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
    let core_manifest = manifest_dir.join("../vmm-core/Cargo.toml");
    let host_manifest = manifest_dir.join("Cargo.toml");

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .arg("build")
        .arg("--manifest-path")
        .arg(&core_manifest)
        .arg("--bin")
        .arg("vmm-core")
        .arg("--target")
        .arg("wasm32-wasip1-threads")
        .arg("--target-dir")
        .arg(&wasm_target_dir)
        .arg("--release")
        .arg("--offline")
        .env(
            "RUSTFLAGS",
            "-C target-feature=-bulk-memory,-simd128 -C link-self-contained=no -C link-arg=--no-entry -C link-arg=--export=__stack_pointer",
        )
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("Failed to invoke cargo to build vmm-core for wasm32-wasip1-threads");

    if !status.success() {
        panic!("Building vmm-core for wasm32-wasip1-threads failed");
    }

    let built_wasm = wasm_target_dir.join("wasm32-wasip1-threads/release/vmm-core.wasm");
    let mut wasm_bytes = fs::read(&built_wasm).expect("Failed to read built vmm-core.wasm");
    verify_no_fp::rewrite_wasm_bulk_memory(&mut wasm_bytes)
        .expect("Failed to rewrite bulk-memory ops in vmm-core.wasm");
    verify_no_fp::validate_wasm_no_fp(&wasm_bytes)
        .expect("vmm-core.wasm failed zero-FP/SIMD/WASI validation");

    let mut config = Config::new();
    config.wasm_threads(true);
    config.shared_memory(true);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    config.signals_based_traps(false);
    config.memory_init_cow(false);
    config.memory_guard_size(0);
    config
        .target(&target)
        .expect("Failed to configure Wasmtime target");
    let engine = Engine::new(&config).expect("Failed to create Wasmtime engine");
    let cwasm_bytes = engine
        .precompile_module(&wasm_bytes)
        .expect("Failed to precompile vmm-core.wasm to cwasm");
    verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes)
        .expect("vmm-core.cwasm failed zero-FP/SIMD machine-code validation");

    fs::write(out_dir.join("vmm-core.wasm"), &wasm_bytes)
        .expect("Failed to write vmm-core.wasm to OUT_DIR");
    fs::write(out_dir.join("vmm-core.cwasm"), &cwasm_bytes)
        .expect("Failed to write vmm-core.cwasm to OUT_DIR");

    let _ = fs::write(profile_dir.join("vmm-core.wasm"), &wasm_bytes);
    let _ = fs::write(profile_dir.join("vmm-core.cwasm"), &cwasm_bytes);

    let repo_wasm_release_dir = manifest_dir.join("../target/wasm32-wasip1-threads/release");
    let _ = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&repo_wasm_release_dir);
    let _ = fs::write(repo_wasm_release_dir.join("vmm-core.wasm"), &wasm_bytes);
    let _ = fs::write(repo_wasm_release_dir.join("vmm-core.cwasm"), &cwasm_bytes);

    if env::var_os("CARGO_FEATURE_COMPILER").is_none() {
        let compiler_target_dir = out_dir.join("compiler-host-target");
        let mut cmd = Command::new(&cargo);
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(&host_manifest)
            .arg("--bin")
            .arg("vmm-core-host-cwasm")
            .arg("--features")
            .arg("compiler")
            .arg("--target")
            .arg(&target)
            .arg("--target-dir")
            .arg(&compiler_target_dir)
            .arg("--offline")
            .env("VMM_CORE_HOST_INNER_BUILD", "1");
        if profile == "release" {
            cmd.arg("--release");
        }
        let status = cmd
            .status()
            .expect("Failed to invoke cargo to build vmm-core-host-wasm");
        if !status.success() {
            panic!("Building vmm-core-host-wasm (with compiler feature) failed");
        }

        let built_host_wasm = compiler_target_dir
            .join(&target)
            .join(&profile)
            .join("vmm-core-host-cwasm");
        let dst_host_wasm = profile_dir.join("vmm-core-host-wasm");
        fs::copy(&built_host_wasm, &dst_host_wasm)
            .expect("Failed to copy built vmm-core-host-wasm to target profile directory");
        let _ = fs::set_permissions(&dst_host_wasm, fs::Permissions::from_mode(0o750));
    }
}
