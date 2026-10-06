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
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../vmm-runner/src");
    println!("cargo:rerun-if-changed=../vmm-runner/Cargo.toml");
    println!("cargo:rerun-if-changed=../wit/vmm.wit");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let wasm_target_dir = out_dir.join("wasm-target");
    let runner_manifest = manifest_dir.join("../vmm-runner/Cargo.toml");

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
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
    let dst_wasm = out_dir.join("vmm-runner.wasm");
    std::fs::copy(&built_wasm, &dst_wasm).expect("Failed to copy vmm-runner.wasm to OUT_DIR");
}
