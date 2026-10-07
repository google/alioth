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

fn main() {
    if env::var_os("VMM_HOST_INNER_BUILD").is_some() {
        return;
    }

    println!("cargo:rerun-if-changed=../vmm-runner/src");
    println!("cargo:rerun-if-changed=../vmm-runner/Cargo.toml");
    println!("cargo:rerun-if-changed=../wit/vmm.wit");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let profile = env::var("PROFILE").unwrap();
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("Failed to locate target profile directory from OUT_DIR")
        .to_path_buf();

    let wasm_target_dir = out_dir.join("wasm-target");
    let runner_manifest = manifest_dir.join("../vmm-runner/Cargo.toml");
    let host_manifest = manifest_dir.join("Cargo.toml");

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .arg("build")
        .arg("--manifest-path")
        .arg(&runner_manifest)
        .arg("--bin")
        .arg("vmm-runner")
        .arg("--target")
        .arg("wasm32-wasip2")
        .arg("--target-dir")
        .arg(&wasm_target_dir)
        .arg("--release")
        .arg("--offline")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("Failed to invoke cargo to build vmm-runner for wasm32-wasip2");

    if !status.success() {
        panic!("Building vmm-runner for wasm32-wasip2 failed");
    }

    let built_wasm = wasm_target_dir.join("wasm32-wasip2/release/vmm-runner.wasm");
    let wasm_bytes = fs::read(&built_wasm).expect("Failed to read built vmm-runner.wasm");

    let mut config = Config::new();
    config
        .target(&target)
        .expect("Failed to configure Wasmtime target");
    let engine = Engine::new(&config).expect("Failed to create Wasmtime engine");
    let cwasm_bytes = engine
        .precompile_component(&wasm_bytes)
        .expect("Failed to precompile vmm-runner.wasm to cwasm");

    fs::write(out_dir.join("vmm-runner.wasm"), &wasm_bytes)
        .expect("Failed to write vmm-runner.wasm to OUT_DIR");
    fs::write(out_dir.join("vmm-runner.cwasm"), &cwasm_bytes)
        .expect("Failed to write vmm-runner.cwasm to OUT_DIR");

    let _ = fs::write(profile_dir.join("vmm-runner.wasm"), &wasm_bytes);
    let _ = fs::write(profile_dir.join("vmm-runner.cwasm"), &cwasm_bytes);

    let repo_wasm_release_dir = manifest_dir.join("../target/wasm32-wasip2/release");
    let _ = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&repo_wasm_release_dir);
    let _ = fs::write(repo_wasm_release_dir.join("vmm-runner.wasm"), &wasm_bytes);
    let _ = fs::write(repo_wasm_release_dir.join("vmm-runner.cwasm"), &cwasm_bytes);

    if env::var_os("CARGO_FEATURE_COMPILER").is_none() {
        let compiler_target_dir = out_dir.join("compiler-host-target");
        let mut cmd = Command::new(&cargo);
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(&host_manifest)
            .arg("--bin")
            .arg("vmm-host-cwasm")
            .arg("--features")
            .arg("compiler")
            .arg("--target")
            .arg(&target)
            .arg("--target-dir")
            .arg(&compiler_target_dir)
            .arg("--offline")
            .env("VMM_HOST_INNER_BUILD", "1");
        if profile == "release" {
            cmd.arg("--release");
        }
        let status = cmd
            .status()
            .expect("Failed to invoke cargo to build vmm-host-wasm");
        if !status.success() {
            panic!("Building vmm-host-wasm (with compiler feature) failed");
        }

        let built_host_wasm = compiler_target_dir
            .join(&target)
            .join(&profile)
            .join("vmm-host-cwasm");
        let dst_host_wasm = profile_dir.join("vmm-host-wasm");
        fs::copy(&built_host_wasm, &dst_host_wasm)
            .expect("Failed to copy built vmm-host-wasm to target profile directory");
        let _ = fs::set_permissions(&dst_host_wasm, fs::Permissions::from_mode(0o750));
    }
}
