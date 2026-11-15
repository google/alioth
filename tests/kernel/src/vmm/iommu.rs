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

//! Internal Ring-0 IOMMU abstraction (`IommuProvider`) decoupling `MotorHvCore`
//! from the underlying IOMMU implementation (`VirtioIommuDriver` in nested VMs;
//! AMD-Vi / Intel VT-d on bare metal).

use core::sync::atomic::{AtomicPtr, Ordering};

use vmm_core::host::{HvResult, MemProt};

pub trait IommuProvider: Send + Sync + 'static {
    fn alloc_domain(&self) -> HvResult<u32>;
    fn free_domain(&self, domain: u32);
    fn attach_endpoint(&self, domain: u32, bdf: u16) -> HvResult<()>;
    fn detach_to_blocked(&self, bdf: u16) -> HvResult<()>;
    fn map_dma(
        &self,
        domain: u32,
        iova: u64,
        hpa: u64,
        size: u64,
        prot: MemProt,
    ) -> HvResult<()>;
    fn unmap_dma(&self, domain: u32, iova: u64, size: u64) -> HvResult<()>;
}

struct Holder {
    provider: &'static dyn IommuProvider,
}

static SYSTEM_IOMMU: AtomicPtr<Holder> = AtomicPtr::new(core::ptr::null_mut());

pub fn register_system_iommu(provider: &'static dyn IommuProvider) {
    let holder = alloc::boxed::Box::leak(alloc::boxed::Box::new(Holder { provider }));
    let prev = SYSTEM_IOMMU.swap(holder, Ordering::Release);
    assert!(prev.is_null(), "system IOMMU registered twice");
}

#[inline]
pub fn system_iommu() -> Option<&'static dyn IommuProvider> {
    let ptr = SYSTEM_IOMMU.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).provider })
    }
}
