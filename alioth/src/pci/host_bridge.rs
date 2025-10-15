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

use crate::pci;
use crate::pci::cap::PciCapList;
use crate::pci::config::{CommonHeader, DeviceHeader, EmulatedConfig, HeaderType, PciConfig};
use crate::pci::{Pci, PciBar};

#[derive(Debug)]
pub struct HostBridge {
    pub config: EmulatedConfig,
}

impl Default for HostBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl HostBridge {
    pub fn new() -> Self {
        let header = DeviceHeader {
            common: CommonHeader {
                vendor: 0x1022,
                device: 0x1480,
                class: 0x06,
                subclass: 0x00,
                header_type: HeaderType::DEVICE,
                ..Default::default()
            },
            ..Default::default()
        };
        let bars = [const { PciBar::Empty }; 6];
        let config = EmulatedConfig::new_device(header, [0; 6], bars, PciCapList::new());
        HostBridge { config }
    }
}

impl Pci for HostBridge {
    fn config(&self) -> &dyn PciConfig {
        &self.config
    }

    fn reset(&self) -> pci::Result<()> {
        Ok(())
    }
}
