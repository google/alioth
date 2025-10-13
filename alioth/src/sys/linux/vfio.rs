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

use bitflags::bitflags;

use crate::c_enum;

pub const VFIO_TYPE: u8 = b';';
pub const IOMMUFD_TYPE: u8 = b';';

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioInfoCapHeader {
    pub id: u16,
    pub version: u16,
    pub next: u32,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct VfioDeviceInfoFlag: u32 {
        const RESET = 1 << 0;
        const PCI = 1 << 1;
        const PLATFORM = 1 << 2;
        const AMBA  = 1 << 3;
        const CCW = 1 << 4;
        const AP = 1 << 5;
        const FSL_MC = 1 << 6;
        const CAPS = 1 << 7;
        const CDX = 1 << 8;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioDeviceInfo {
    pub argsz: u32,
    pub flags: VfioDeviceInfoFlag,
    pub num_regions: u32,
    pub num_irqs: u32,
    pub cap_offset: u32,
    pub pad: u32,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct VfioRegionInfoFlag: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const MMAP = 1 << 2;
        const CAPS = 1 << 3;
    }
}

c_enum! {
    pub struct VfioPciRegion(u32);
    {
        BAR0 = 0;
        BAR1 = 1;
        BAR2 = 2;
        BAR3 = 3;
        BAR4 = 4;
        BAR5 = 5;
        ROM = 6;
        CONFIG = 7;
        VGA = 8;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioRegionInfo {
    pub argsz: u32,
    pub flags: VfioRegionInfoFlag,
    pub index: u32,
    pub cap_offset: u32,
    pub size: u64,
    pub offset: u64,
}

c_enum! {
    #[derive(Default)]
    pub struct VfioRegionInfoCap(u16);
    {
        MSIX_MAPPABLE = 3;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct VfioIrqInfoFlag: u32 {
        const EVENTFD = 1 << 0;
        const MASKABLE = 1 << 1;
        const AUTOMASKED = 1 << 2;
        const NORESIZE = 1 << 3;
    }
}

c_enum! {
    #[derive(Default)]
    pub struct VfioPciIrq(u32);
    {
        INTX = 0;
        MSI = 1;
        MSIX = 2;
        ERR = 3;
        REQ = 4;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioIrqInfo {
    pub argsz: u32,
    pub flags: VfioIrqInfoFlag,
    pub index: u32,
    pub count: u32,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct VfioIrqSetFlag: u32 {
        const DATA_NONE = 1 << 0;
        const DATA_BOOL = 1 << 1;
        const DATA_EVENTFD = 1 << 2;
        const ACTION_MASK = 1 << 3;
        const ACTION_UNMASK = 1 << 4;
        const ACTION_TRIGGER = 1 << 5;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union VfioIrqSetData<const N: usize> {
    pub eventfds: [i32; N],
    pub bools: [bool; N],
}

#[repr(C)]
#[derive(Clone)]
pub struct VfioIrqSet<const N: usize> {
    pub argsz: u32,
    pub flags: VfioIrqSetFlag,
    pub index: u32,
    pub start: u32,
    pub count: u32,
    pub data: VfioIrqSetData<N>,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioDeviceBindIommufd {
    pub argsz: u32,
    pub flags: u32,
    pub iommufd: i32,
    pub out_devid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioDeviceAttachIommufdPt {
    pub argsz: u32,
    pub flags: u32,
    pub pt_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioDeviceDetachIommufdPt {
    pub argsz: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IommuDestroy {
    pub size: u32,
    pub id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IommuIoasAlloc {
    pub size: u32,
    pub flags: u32,
    pub out_ioas_id: u32,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Default)]
    pub struct IommuIoasMapFlag: u32 {
        const FIXED_IOVA = 1 << 0;
        const WRITEABLE = 1 << 1;
        const READABLE = 1 << 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IommuIoasMap {
    pub size: u32,
    pub flags: IommuIoasMapFlag,
    pub ioas_id: u32,
    pub _reserved: u32,
    pub user_va: u64,
    pub length: u64,
    pub iova: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct IommuIoasUnmap {
    pub size: u32,
    pub ioas_id: u32,
    pub iova: u64,
    pub length: u64,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Default)]
    pub struct VfioDmaMapFlag: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const VADDR = 1 << 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioIommuType1DmaMap {
    pub argsz: u32,
    pub flags: VfioDmaMapFlag,
    pub vaddr: u64,
    pub iova: u64,
    pub size: u64,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Default)]
    pub struct VfioDmaUnmapFlag: u32 {
        const GET_DIRTY_BITMAP  = 1 << 0;
        const ALL = 1 << 1;
        const VADDR = 1 << 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VfioIommuType1DmaUnmap {
    pub argsz: u32,
    pub flags: VfioDmaUnmapFlag,
    pub iova: u64,
    pub size: u64,
}

c_enum! {
    pub struct VfioIommu(i32);
    {
        TYPE1 = 1;
        SPAR_TCE= 2;
        TYPE1_V2 = 3;
    }
}
