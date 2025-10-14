// Copyright 2025 Google LLC
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

#[cfg(test)]
#[path = "notifier_test.rs"]
mod tests;

#[cfg(target_os = "linux")]
#[path = "notifier_linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "notifier_macos.rs"]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::Notifier;
#[cfg(target_os = "macos")]
pub use macos::Notifier;
