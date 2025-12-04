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

use std::mem::size_of;

use super::{
    AcpiGenericAddress, AcpiMadtIoApic, AcpiMadtLocalX2apic, AcpiMcfgAllocation, AcpiTableFadt,
    AcpiTableHeader, AcpiTableMadt, AcpiTableMcfg1, AcpiTableRsdp, AcpiTableXsdt,
};

#[test]
fn test_size() {
    assert_eq!(size_of::<AcpiTableRsdp>(), 36);
    assert_eq!(size_of::<AcpiTableHeader>(), 36);
    assert_eq!(size_of::<AcpiGenericAddress>(), 12);
    assert_eq!(size_of::<AcpiTableFadt>(), 276);
    assert_eq!(size_of::<AcpiTableMadt>(), 44);
    assert_eq!(size_of::<AcpiMadtIoApic>(), 12);
    assert_eq!(size_of::<AcpiMadtLocalX2apic>(), 16);
    assert_eq!(size_of::<AcpiMcfgAllocation>(), 16);
    assert_eq!(size_of::<AcpiTableMcfg1>(), 60);
    assert_eq!(size_of::<AcpiTableXsdt<0>>(), 36);
    assert_eq!(size_of::<AcpiTableXsdt<4>>(), 36 + 4 * 8);
}
