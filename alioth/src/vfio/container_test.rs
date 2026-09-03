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

use assert_matches::assert_matches;

use crate::sys::vfio::VfioIommu;
use crate::vfio::Error;
use crate::vfio::container::Container;

#[test]
fn test_container_set_iommu_mismatch() {
    let tmp_file = tempfile::NamedTempFile::new().unwrap();
    let container = Container::new(tmp_file.path()).unwrap();
    // Simulate container already having TYPE1
    *container.iommu.lock() = Some(VfioIommu::TYPE1);

    // Setting same IOMMU returns Ok(())
    assert_matches!(container.set_iommu(VfioIommu::TYPE1), Ok(()));

    // Setting different IOMMU returns SetContainerIommu error
    assert_matches!(
        container.set_iommu(VfioIommu::TYPE1_V2),
        Err(Error::SetContainerIommu {
            current: VfioIommu::TYPE1,
            new: VfioIommu::TYPE1_V2,
            ..
        })
    );
}
