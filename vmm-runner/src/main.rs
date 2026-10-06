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

#[cfg(target_os = "wasi")]
use vmm_runner::wasm::WasmGuest;

#[cfg(target_os = "wasi")]
vmm_runner::wasm::export!(WasmGuest with_types_in vmm_runner::wasm);

fn main() {
    #[cfg(target_os = "wasi")]
    {
        let args: Vec<String> = std::env::args().collect();
        let config_path = if args.len() >= 3 && args[1] == "-c" {
            args[2].clone()
        } else if args.len() >= 2 {
            args[1].clone()
        } else {
            panic!("Usage: vmm-runner -c <config_file>");
        };
        let hv = vmm_runner::wasm::WasmHypervisor::new().expect("Failed to get hypervisor");
        vmm_runner::run(&config_path, Box::new(hv)).expect("Failed to run VM");
    }
}
