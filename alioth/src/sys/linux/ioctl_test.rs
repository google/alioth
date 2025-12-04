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

use super::{ioctl_io, ioctl_ior, ioctl_iow, ioctl_iowr};

#[test]
fn test_codes() {
    const KVMIO: u8 = 0xAE;
    assert_eq!(ioctl_io(KVMIO, 0x01), 0xae01);
    assert_eq!(ioctl_ior::<[u8; 320]>(KVMIO, 0xcc), 0x8140aecc);
    assert_eq!(ioctl_iow::<[u8; 320]>(KVMIO, 0xcd), 0x4140aecd);
    assert_eq!(ioctl_iowr::<[u8; 8]>(KVMIO, 0x05), 0xc008ae05);
}
