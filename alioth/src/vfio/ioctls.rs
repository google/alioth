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

use crate::utils::ioctls::ioctl_io;
use crate::vfio::bindings::{
    IommuDestroy, IommuIoasAlloc, IommuIoasMap, IommuIoasUnmap, VfioDeviceAttachIommufdPt,
    VfioDeviceBindIommufd, VfioDeviceDetachIommufdPt, VfioDeviceInfo, VfioIrqInfo, VfioIrqSet,
    VfioRegionInfo, IOMMUFD_TYPE, VFIO_TYPE,
};
use crate::{ioctl_none, ioctl_write_buf, ioctl_write_ptr, ioctl_writeread};

ioctl_writeread!(
    vfio_device_get_info,
    ioctl_io(VFIO_TYPE, 107),
    VfioDeviceInfo
);
ioctl_writeread!(
    vfio_device_get_region_info,
    ioctl_io(VFIO_TYPE, 108),
    VfioRegionInfo
);
ioctl_writeread!(
    vfio_device_get_irq_info,
    ioctl_io(VFIO_TYPE, 109),
    VfioIrqInfo
);

ioctl_write_buf!(vfio_device_set_irqs, ioctl_io(VFIO_TYPE, 110), VfioIrqSet);

ioctl_none!(vfio_device_reset, VFIO_TYPE, 111, 0);

ioctl_write_ptr!(
    vfio_device_bind_iommufd,
    ioctl_io(VFIO_TYPE, 118),
    VfioDeviceBindIommufd
);

ioctl_write_ptr!(
    vfio_device_attach_iommufd_pt,
    ioctl_io(VFIO_TYPE, 119),
    VfioDeviceAttachIommufdPt
);

ioctl_write_ptr!(
    vfio_device_detach_iommufd_pt,
    ioctl_io(VFIO_TYPE, 120),
    VfioDeviceDetachIommufdPt
);

ioctl_write_ptr!(iommu_destroy, ioctl_io(IOMMUFD_TYPE, 0x80), IommuDestroy);

ioctl_writeread!(
    iommu_ioas_alloc,
    ioctl_io(IOMMUFD_TYPE, 0x81),
    IommuIoasAlloc
);

ioctl_write_ptr!(iommu_ioas_map, ioctl_io(IOMMUFD_TYPE, 0x85), IommuIoasMap);

ioctl_write_ptr!(
    iommu_ioas_unmap,
    ioctl_io(IOMMUFD_TYPE, 0x86),
    IommuIoasUnmap
);
