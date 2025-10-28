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

use assert_matches::assert_matches;

use crate::mem::emulated::Mmio;
use crate::pci::Pci;
use crate::pci::config::{CommonHeader, HeaderType};
use crate::pci::host_bridge::HostBridge;

#[test]
fn test_host_bridge() {
    let bridge = HostBridge::default();

    assert_matches!(bridge.name(), "host_bridge");

    let config = bridge.config();

    let header = config.get_header();

    assert_matches!(header.read(CommonHeader::OFFSET_CLASS as u64, 1), Ok(0x06));
    assert_matches!(
        header.read(CommonHeader::OFFSET_SUBCLASS as u64, 1),
        Ok(0x00)
    );
    assert_matches!(
        header.read(CommonHeader::OFFSET_HEADER_TYPE as u64, 1),
        Ok(t) if t as u8 == HeaderType::DEVICE.raw()
    );

    assert_matches!(bridge.reset(), Ok(()));
}
