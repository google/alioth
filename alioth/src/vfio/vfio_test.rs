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

use crate::vfio::{VfioCdevSpec, VfioContainerSpec, VfioGroupSpec, VfioIoasSpec};

#[test]
fn test_vfio_specs_deserialization() {
    // VfioCdevSpec
    let cdev_aco = "path=/dev/vfio/devices/vfio0,ioas=my_ioas";
    let cdev_spec: VfioCdevSpec = serde_aco::from_arg(cdev_aco).unwrap();
    assert_eq!(cdev_spec.path.to_str().unwrap(), "/dev/vfio/devices/vfio0");
    assert_eq!(cdev_spec.ioas.as_deref(), Some("my_ioas"));

    // VfioIoasSpec
    let ioas_aco = "name=ioas0,dev_iommu=/dev/iommu";
    let ioas_spec: VfioIoasSpec = serde_aco::from_arg(ioas_aco).unwrap();
    assert_eq!(&*ioas_spec.name, "ioas0");
    assert_eq!(ioas_spec.dev_iommu.unwrap().to_str().unwrap(), "/dev/iommu");

    // VfioGroupSpec
    let group_aco = "path=/dev/vfio/12,devices=0000:06:0d.0,container=c0";
    let group_spec: VfioGroupSpec = serde_aco::from_arg(group_aco).unwrap();
    assert_eq!(group_spec.path.to_str().unwrap(), "/dev/vfio/12");
    assert_eq!(group_spec.devices.len(), 1);
    assert_eq!(&*group_spec.devices[0], "0000:06:0d.0");
    assert_eq!(group_spec.container.as_deref(), Some("c0"));

    // VfioContainerSpec
    let container_aco = "name=c0,dev_vfio=/dev/vfio/vfio";
    let container_spec: VfioContainerSpec = serde_aco::from_arg(container_aco).unwrap();
    assert_eq!(&*container_spec.name, "c0");
    assert_eq!(
        container_spec.dev_vfio.unwrap().to_str().unwrap(),
        "/dev/vfio/vfio"
    );
}
