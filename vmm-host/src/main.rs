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

use crate::kvm::Kvm;

pub mod ioctls;
#[path = "kvm/kvm.rs"]
pub mod kvm;
pub mod serial;
pub mod tap;

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: `{} -c $CONFIG_FILENAME_TOML`.",
        env!("CARGO_PKG_NAME")
    );
    std::process::exit(1)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1].as_str() != "-c" {
        print_usage_and_exit();
    }

    let kvm = Kvm::new()?;
    vmm_runner::run(args[2].as_str(), Box::new(kvm))
}
