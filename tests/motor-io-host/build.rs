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

use std::env;
use std::fs;
use std::path::PathBuf;

use wasmtime::{Config, Engine};

#[path = "../../vmm-io-host/src/verify_no_fp.rs"]
mod verify_no_fp;

fn main() {
    let target = env::var("TARGET").unwrap();
    println!("cargo:rustc-env=VMM_HOST_TARGET={target}");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("tests/motor-io-host must live under <repo>/tests/");

    let wasm_path = repo_root.join("target/wasm32-wasip1/release/vmm-io.wasm");
    println!("cargo:rerun-if-changed={}", wasm_path.display());

    if wasm_path.is_file() {
        let wasm_bytes = fs::read(&wasm_path).expect("Failed to read vmm-io.wasm");
        verify_no_fp::validate_wasm_no_fp(&wasm_bytes)
            .expect("vmm-io.wasm failed zero-FP/SIMD validation");

        let mut config = Config::new();
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config
            .target("x86_64-unknown-motor")
            .expect("Failed to configure x86_64-unknown-motor Wasmtime target");
        let engine = Engine::new(&config).expect("Failed to create Wasmtime engine");
        let cwasm_bytes = engine
            .precompile_module(&wasm_bytes)
            .expect("Failed to precompile vmm-io.wasm for x86_64-unknown-motor");
        verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes)
            .expect("Motor OS vmm-io.cwasm failed zero-FP/SIMD machine-code validation");

        let motor_out = repo_root.join("target/motor");
        fs::create_dir_all(&motor_out).expect("Failed to create target/motor directory");
        fs::write(motor_out.join("vmm-io.cwasm"), &cwasm_bytes)
            .expect("Failed to write target/motor/vmm-io.cwasm");
    }
}
