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

//! OASIS VirtIO v1.2 §5.12 `virtio-iommu` device (`DeviceId::Iommu = 23`) and
//! per-PCI-endpoint DMA translation (`EndpointDmaView`).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::{self, ErrorKind};
use std::mem::size_of;
use std::sync::Arc;

use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::host::{GuestMemAccess, PollEvent, Token};
use crate::sync::RwLock;
use crate::virtio::dev::Virtio;
use crate::virtio::queue::Descriptor;
use crate::virtio::queue::handlers::handle_desc;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::{DeviceId, IrqSender, Result};

// Feature bits (VirtIO v1.2 §5.12.3)
pub const VIRTIO_IOMMU_F_INPUT_RANGE: u64 = 1 << 0;
pub const VIRTIO_IOMMU_F_DOMAIN_RANGE: u64 = 1 << 1;
pub const VIRTIO_IOMMU_F_MAP_UNMAP: u64 = 1 << 2;
pub const VIRTIO_IOMMU_F_BYPASS: u64 = 1 << 3;
pub const VIRTIO_IOMMU_F_PROBE: u64 = 1 << 4;
pub const VIRTIO_IOMMU_F_MMIO: u64 = 1 << 5;
pub const VIRTIO_IOMMU_F_BYPASS_CONFIG: u64 = 1 << 6;

// Request types (VirtIO v1.2 §5.12.6)
pub const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
pub const VIRTIO_IOMMU_T_DETACH: u8 = 2;
pub const VIRTIO_IOMMU_T_MAP: u8 = 3;
pub const VIRTIO_IOMMU_T_UNMAP: u8 = 4;

// Status codes (VirtIO v1.2 §5.12.6)
pub const VIRTIO_IOMMU_S_OK: u8 = 0;
pub const VIRTIO_IOMMU_S_IOERR: u8 = 1;
pub const VIRTIO_IOMMU_S_UNSUPP: u8 = 2;
pub const VIRTIO_IOMMU_S_DEVERR: u8 = 3;
pub const VIRTIO_IOMMU_S_INVAL: u8 = 4;
pub const VIRTIO_IOMMU_S_RANGE: u8 = 5;
pub const VIRTIO_IOMMU_S_NOENT: u8 = 6;
pub const VIRTIO_IOMMU_S_FAULT: u8 = 7;
pub const VIRTIO_IOMMU_S_NOMEM: u8 = 8;

// MAP permission flags (VirtIO v1.2 §5.12.6.3)
pub const VIRTIO_IOMMU_MAP_F_READ: u32 = 1 << 0;
pub const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 1 << 1;
pub const VIRTIO_IOMMU_MAP_F_MMIO: u32 = 1 << 2;
pub const VIRTIO_IOMMU_MAP_F_MASK: u32 =
    VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO;

const PAGE_MASK_4K: u64 = !0xfff;
const PAGE_OFFSET_MASK_4K: u64 = 0xfff;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub struct VirtioIommuConfig {
    pub page_size_mask: u64,
    pub input_range_start: u64,
    pub input_range_end: u64,
    pub domain_range_start: u32,
    pub domain_range_end: u32,
    pub probe_size: u32,
    pub bypass: u8,
    pub reserved: [u8; 3],
}

const _: () = assert!(size_of::<VirtioIommuConfig>() == 40);

impl Default for VirtioIommuConfig {
    fn default() -> Self {
        Self {
            page_size_mask: PAGE_MASK_4K,
            input_range_start: 0,
            input_range_end: u64::MAX,
            domain_range_start: 1,
            domain_range_end: u32::MAX,
            probe_size: 0,
            // Default-deny (`bypass = 0`) matching Cloud Hypervisor `--platform iommu_segments=0`.
            bypass: 0,
            reserved: [0; 3],
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub struct VirtioIommuReqAttach {
    pub type_: u8,
    pub reserved0: [u8; 3],
    pub domain: u32,
    pub endpoint: u32,
    pub reserved1: [u8; 8],
}

const _: () = assert!(size_of::<VirtioIommuReqAttach>() == 20);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub struct VirtioIommuReqDetach {
    pub type_: u8,
    pub reserved0: [u8; 3],
    pub domain: u32,
    pub endpoint: u32,
    pub reserved1: [u8; 8],
}

const _: () = assert!(size_of::<VirtioIommuReqDetach>() == 20);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub struct VirtioIommuReqMap {
    pub type_: u8,
    pub reserved0: [u8; 3],
    pub domain: u32,
    pub virt_start: u64,
    pub virt_end: u64,
    pub phys_start: u64,
    pub flags: u32,
}

const _: () = assert!(size_of::<VirtioIommuReqMap>() == 36);

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub struct VirtioIommuReqUnmap {
    pub type_: u8,
    pub reserved0: [u8; 3],
    pub domain: u32,
    pub virt_start: u64,
    pub virt_end: u64,
}

const _: () = assert!(size_of::<VirtioIommuReqUnmap>() == 24);

#[derive(Debug, Clone, Copy)]
struct IommuMapping {
    virt_start: u64,
    virt_end: u64,
    phys_start: u64,
    flags: u32,
}

#[derive(Debug, Default)]
struct IommuDomain {
    endpoints: BTreeSet<u32>,
    mappings: BTreeMap<u64, IommuMapping>,
}

#[derive(Debug)]
pub struct IommuState {
    bypass: bool,
    managed_endpoints: BTreeSet<u32>,
    endpoint_to_domain: BTreeMap<u32, u32>,
    domains: BTreeMap<u32, IommuDomain>,
}

impl Default for IommuState {
    fn default() -> Self {
        Self::new()
    }
}

impl IommuState {
    pub fn new() -> Self {
        Self {
            bypass: false,
            managed_endpoints: BTreeSet::new(),
            endpoint_to_domain: BTreeMap::new(),
            domains: BTreeMap::new(),
        }
    }

    pub fn register_endpoint(&mut self, bdf: u16) {
        self.managed_endpoints.insert(bdf as u32);
    }

    pub fn set_bypass(&mut self, bypass: bool) {
        self.bypass = bypass;
    }

    pub fn reset(&mut self) {
        self.bypass = false;
        self.endpoint_to_domain.clear();
        self.domains.clear();
    }

    fn detach_endpoint_inner(&mut self, domain_id: u32, endpoint: u32) -> u8 {
        let Some(&cur_dom) = self.endpoint_to_domain.get(&endpoint) else {
            return VIRTIO_IOMMU_S_NOENT;
        };
        if cur_dom != domain_id {
            return VIRTIO_IOMMU_S_INVAL;
        }
        self.endpoint_to_domain.remove(&endpoint);
        let remove_domain = if let Some(dom) = self.domains.get_mut(&domain_id) {
            dom.endpoints.remove(&endpoint);
            dom.endpoints.is_empty()
        } else {
            false
        };
        // VirtIO v1.2 §5.12.6.2: delete all mappings once the last endpoint detaches.
        if remove_domain {
            self.domains.remove(&domain_id);
        }
        VIRTIO_IOMMU_S_OK
    }

    pub fn attach(&mut self, domain_id: u32, endpoint: u32) -> u8 {
        if domain_id == 0 {
            return VIRTIO_IOMMU_S_RANGE;
        }
        if !self.managed_endpoints.contains(&endpoint) {
            return VIRTIO_IOMMU_S_NOENT;
        }
        if let Some(&prev_dom) = self.endpoint_to_domain.get(&endpoint) {
            if prev_dom == domain_id {
                return VIRTIO_IOMMU_S_OK;
            }
            let _ = self.detach_endpoint_inner(prev_dom, endpoint);
        }
        self.endpoint_to_domain.insert(endpoint, domain_id);
        self.domains
            .entry(domain_id)
            .or_default()
            .endpoints
            .insert(endpoint);
        VIRTIO_IOMMU_S_OK
    }

    pub fn detach(&mut self, domain_id: u32, endpoint: u32) -> u8 {
        if domain_id == 0 {
            return VIRTIO_IOMMU_S_RANGE;
        }
        if !self.managed_endpoints.contains(&endpoint) {
            return VIRTIO_IOMMU_S_NOENT;
        }
        self.detach_endpoint_inner(domain_id, endpoint)
    }

    pub fn map(
        &mut self,
        domain_id: u32,
        virt_start: u64,
        virt_end: u64,
        phys_start: u64,
        flags: u32,
    ) -> u8 {
        if (flags & !VIRTIO_IOMMU_MAP_F_MASK) != 0
            || (flags & (VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE)) == 0
        {
            return VIRTIO_IOMMU_S_INVAL;
        }
        if virt_start > virt_end {
            return VIRTIO_IOMMU_S_INVAL;
        }
        if (virt_start & PAGE_OFFSET_MASK_4K) != 0
            || (phys_start & PAGE_OFFSET_MASK_4K) != 0
            || (virt_end.wrapping_add(1) & PAGE_OFFSET_MASK_4K) != 0
        {
            return VIRTIO_IOMMU_S_RANGE;
        }
        let span_minus_one = virt_end - virt_start;
        if phys_start.checked_add(span_minus_one).is_none() {
            return VIRTIO_IOMMU_S_RANGE;
        }
        let Some(dom) = self.domains.get_mut(&domain_id) else {
            return VIRTIO_IOMMU_S_NOENT;
        };
        if let Some((_, prev)) = dom.mappings.range(..=virt_end).next_back()
            && prev.virt_end >= virt_start
        {
            return VIRTIO_IOMMU_S_INVAL;
        }
        dom.mappings.insert(
            virt_start,
            IommuMapping {
                virt_start,
                virt_end,
                phys_start,
                flags,
            },
        );
        VIRTIO_IOMMU_S_OK
    }

    pub fn unmap(&mut self, domain_id: u32, virt_start: u64, virt_end: u64) -> u8 {
        if virt_start > virt_end {
            return VIRTIO_IOMMU_S_INVAL;
        }
        if (virt_start & PAGE_OFFSET_MASK_4K) != 0
            || (virt_end.wrapping_add(1) & PAGE_OFFSET_MASK_4K) != 0
        {
            return VIRTIO_IOMMU_S_RANGE;
        }
        let Some(dom) = self.domains.get_mut(&domain_id) else {
            return VIRTIO_IOMMU_S_NOENT;
        };
        let mut to_remove = Vec::new();
        for (&k, m) in dom.mappings.range(..=virt_end).rev() {
            if m.virt_end < virt_start {
                break;
            }
            if m.virt_start < virt_start || m.virt_end > virt_end {
                return VIRTIO_IOMMU_S_RANGE;
            }
            to_remove.push(k);
        }
        for k in to_remove {
            dom.mappings.remove(&k);
        }
        VIRTIO_IOMMU_S_OK
    }

    fn translate_chunk(
        &self,
        endpoint: u32,
        iova: u64,
        rem_len: usize,
        req_perm: u32,
    ) -> io::Result<(u64, usize)> {
        debug_assert!(rem_len > 0);
        if let Some(&dom_id) = self.endpoint_to_domain.get(&endpoint) {
            let Some(dom) = self.domains.get(&dom_id) else {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("IOMMU endpoint {endpoint:#06x}: missing domain {dom_id}"),
                ));
            };
            let Some((_, m)) = dom.mappings.range(..=iova).next_back() else {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "IOMMU fault: endpoint {endpoint:#06x} domain {dom_id} unmapped IOVA {iova:#x}"
                    ),
                ));
            };
            if iova > m.virt_end {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "IOMMU fault: endpoint {endpoint:#06x} domain {dom_id} unmapped IOVA {iova:#x}"
                    ),
                ));
            }
            if (m.flags & req_perm) != req_perm {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "IOMMU permission fault: endpoint {endpoint:#06x} domain {dom_id} IOVA {iova:#x} flags={:#x} req={req_perm:#x}",
                        m.flags
                    ),
                ));
            }
            let off = iova - m.virt_start;
            let phys = m.phys_start + off;
            let max_minus_1 = m.virt_end - iova;
            let chunk = if max_minus_1 >= (rem_len - 1) as u64 {
                rem_len
            } else {
                (max_minus_1 + 1) as usize
            };
            Ok((phys, chunk))
        } else if self.bypass {
            Ok((iova, rem_len))
        } else {
            Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "IOMMU blocked unattached endpoint {endpoint:#06x} DMA at IOVA {iova:#x} (bypass=0)"
                ),
            ))
        }
    }
}

/// Per-endpoint `GuestMemAccess` wrapper enforcing `virtio-iommu` IOVA translation & permissions.
#[derive(Debug)]
pub struct EndpointDmaView {
    endpoint_bdf: u16,
    iommu: Arc<RwLock<IommuState>>,
    raw_mem: Arc<dyn GuestMemAccess>,
}

impl EndpointDmaView {
    pub fn new(
        endpoint_bdf: u16,
        iommu: Arc<RwLock<IommuState>>,
        raw_mem: Arc<dyn GuestMemAccess>,
    ) -> Self {
        iommu.write().register_endpoint(endpoint_bdf);
        Self {
            endpoint_bdf,
            iommu,
            raw_mem,
        }
    }
}

impl GuestMemAccess for EndpointDmaView {
    fn read_bytes(&self, mut iova: u64, mut dst: &mut [u8]) -> io::Result<()> {
        while !dst.is_empty() {
            let (phys_gpa, chunk) = {
                let state = self.iommu.read();
                state.translate_chunk(
                    self.endpoint_bdf as u32,
                    iova,
                    dst.len(),
                    VIRTIO_IOMMU_MAP_F_READ,
                )?
            };
            self.raw_mem.read_bytes(phys_gpa, &mut dst[..chunk])?;
            iova = iova.checked_add(chunk as u64).ok_or_else(|| {
                io::Error::new(ErrorKind::PermissionDenied, "IOMMU read IOVA overflow")
            })?;
            dst = &mut dst[chunk..];
        }
        Ok(())
    }

    fn write_bytes(&self, mut iova: u64, mut src: &[u8]) -> io::Result<()> {
        while !src.is_empty() {
            let (phys_gpa, chunk) = {
                let state = self.iommu.read();
                state.translate_chunk(
                    self.endpoint_bdf as u32,
                    iova,
                    src.len(),
                    VIRTIO_IOMMU_MAP_F_WRITE,
                )?
            };
            self.raw_mem.write_bytes(phys_gpa, &src[..chunk])?;
            iova = iova.checked_add(chunk as u64).ok_or_else(|| {
                io::Error::new(ErrorKind::PermissionDenied, "IOMMU write IOVA overflow")
            })?;
            src = &src[chunk..];
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VirtioIommu {
    name: Arc<String>,
    config: VirtioIommuConfig,
    state: Arc<RwLock<IommuState>>,
}

impl VirtioIommu {
    pub fn new(name: Arc<String>, state: Arc<RwLock<IommuState>>) -> Self {
        Self {
            name,
            config: VirtioIommuConfig::default(),
            state,
        }
    }

    fn dispatch_request(&self, req_bytes: &[u8]) -> u8 {
        let Some(&req_type) = req_bytes.first() else {
            return VIRTIO_IOMMU_S_INVAL;
        };
        match req_type {
            VIRTIO_IOMMU_T_ATTACH => {
                let Some(req) = VirtioIommuReqAttach::read_from_prefix(req_bytes) else {
                    return VIRTIO_IOMMU_S_INVAL;
                };
                if req.reserved0 != [0; 3] || req.reserved1 != [0; 8] {
                    return VIRTIO_IOMMU_S_INVAL;
                }
                self.state.write().attach(req.domain, req.endpoint)
            }
            VIRTIO_IOMMU_T_DETACH => {
                let Some(req) = VirtioIommuReqDetach::read_from_prefix(req_bytes) else {
                    return VIRTIO_IOMMU_S_INVAL;
                };
                if req.reserved0 != [0; 3] || req.reserved1 != [0; 8] {
                    return VIRTIO_IOMMU_S_INVAL;
                }
                self.state.write().detach(req.domain, req.endpoint)
            }
            VIRTIO_IOMMU_T_MAP => {
                let Some(req) = VirtioIommuReqMap::read_from_prefix(req_bytes) else {
                    return VIRTIO_IOMMU_S_INVAL;
                };
                if req.reserved0 != [0; 3] {
                    return VIRTIO_IOMMU_S_INVAL;
                }
                self.state.write().map(
                    req.domain,
                    req.virt_start,
                    req.virt_end,
                    req.phys_start,
                    req.flags,
                )
            }
            VIRTIO_IOMMU_T_UNMAP => {
                let Some(req) = VirtioIommuReqUnmap::read_from_prefix(req_bytes) else {
                    return VIRTIO_IOMMU_S_INVAL;
                };
                if req.reserved0 != [0; 3] {
                    return VIRTIO_IOMMU_S_INVAL;
                }
                self.state
                    .write()
                    .unmap(req.domain, req.virt_start, req.virt_end)
            }
            _ => VIRTIO_IOMMU_S_UNSUPP,
        }
    }

    fn process_desc(&self, desc: &mut Descriptor) -> io::Result<usize> {
        let req_bytes: Cow<'_, [u8]> = match desc.readable.as_slice() {
            [] => Cow::Borrowed(&[]),
            [single] => Cow::Borrowed(single.as_slice()),
            many => {
                let total: usize = many.iter().map(|b| b.len()).sum();
                let mut flat = Vec::with_capacity(total);
                for b in many {
                    flat.extend_from_slice(b);
                }
                Cow::Owned(flat)
            }
        };
        let status = self.dispatch_request(&req_bytes);
        let Some(tail_buf) = desc.writable.last_mut() else {
            return Err(ErrorKind::InvalidData.into());
        };
        if tail_buf.len() < 4 {
            return Err(ErrorKind::InvalidData.into());
        }
        tail_buf[0] = status;
        tail_buf[1] = 0;
        tail_buf[2] = 0;
        tail_buf[3] = 0;
        Ok(4)
    }
}

impl Virtio for VirtioIommu {
    fn num_queues(&self) -> u16 {
        // Queue 0: requestq, Queue 1: eventq.
        2
    }

    fn reset(&mut self) {
        self.config.bypass = 0;
        self.state.write().reset();
    }

    fn device_id(&self) -> DeviceId {
        DeviceId::Iommu
    }

    fn config_bytes(&self) -> Vec<u8> {
        self.config.as_bytes().to_vec()
    }

    fn feature(&self) -> u64 {
        VIRTIO_IOMMU_F_INPUT_RANGE
            | VIRTIO_IOMMU_F_DOMAIN_RANGE
            | VIRTIO_IOMMU_F_MAP_UNMAP
            | VIRTIO_IOMMU_F_BYPASS_CONFIG
    }

    fn activate(&mut self, _token: Token, _feature: u64) -> Result<()> {
        Ok(())
    }

    fn write_config(&mut self, offset: u16, data: &[u8]) {
        if offset == 36
            && let Some(&b) = data.first()
        {
            let bypass = (b & 1) != 0;
            self.config.bypass = u8::from(bypass);
            self.state.write().set_bypass(bypass);
            log::info!("{}: updated bypass mode to {}", self.name, bypass);
        }
    }

    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[SplitQueue],
        irq_sender: &impl IrqSender,
    ) -> Result<()> {
        if index == 1 {
            // eventq buffer replenishment requires no immediate action.
            return Ok(());
        }
        let Some(queue) = queues.get(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        handle_desc(&self.name, index, queue, irq_sender, |desc| {
            self.process_desc(desc)
        })
    }

    fn handle_event(
        &mut self,
        _event: &PollEvent,
        _queues: &[SplitQueue],
        _irq_sender: &impl IrqSender,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use super::*;
    use crate::sync::Mutex;

    #[derive(Debug)]
    struct TestRam(Mutex<Vec<u8>>);

    impl GuestMemAccess for TestRam {
        fn read_bytes(&self, gpa: u64, dst: &mut [u8]) -> io::Result<()> {
            let ram = self.0.lock();
            let s = gpa as usize;
            dst.copy_from_slice(&ram[s..s + dst.len()]);
            Ok(())
        }
        fn write_bytes(&self, gpa: u64, src: &[u8]) -> io::Result<()> {
            let mut ram = self.0.lock();
            let s = gpa as usize;
            ram[s..s + src.len()].copy_from_slice(src);
            Ok(())
        }
    }

    #[test]
    fn test_iommu_isolation_and_translation() {
        let raw_ram: Arc<dyn GuestMemAccess> = Arc::new(TestRam(Mutex::new(vec![0u8; 0x20000])));
        raw_ram.write_bytes(0x9000, b"KERNEL_SECRET!!!").unwrap();

        let state = Arc::new(RwLock::new(IommuState::new()));
        let net_dma = EndpointDmaView::new(0x0018, state.clone(), raw_ram.clone());

        // 1. Default-deny (`bypass = 0`): unattached endpoint DMA must be blocked!
        let mut leak = [0u8; 16];
        assert!(net_dma.read_bytes(0x9000, &mut leak).is_err());

        // 2. Attach `00:03.0` (`0x0018`) to domain 7 (`0` mappings) -> still blocked!
        assert_eq!(state.write().attach(7, 0x0018), VIRTIO_IOMMU_S_OK);
        assert!(net_dma.read_bytes(0x9000, &mut leak).is_err());

        // 3. Map L2 GPA `[0x1000..=0x2fff]` -> L1 PA `0x10000` (RW) and `[0x3000..=0x3fff]` -> `0x14000` (RO).
        assert_eq!(
            state.write().map(
                7,
                0x1000,
                0x2fff,
                0x10000,
                VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE
            ),
            VIRTIO_IOMMU_S_OK
        );
        assert_eq!(
            state
                .write()
                .map(7, 0x3000, 0x3fff, 0x14000, VIRTIO_IOMMU_MAP_F_READ),
            VIRTIO_IOMMU_S_OK
        );

        // Overlapping MAP must fail with `S_INVAL`.
        assert_eq!(
            state
                .write()
                .map(7, 0x2000, 0x3fff, 0x18000, VIRTIO_IOMMU_MAP_F_READ),
            VIRTIO_IOMMU_S_INVAL
        );

        // 4. Valid L2 DMA at `0x1ff8` spanning into `0x2008` translates to `0x10ff8..0x11008`.
        net_dma.write_bytes(0x1ff8, &[0x5au8; 16]).unwrap();
        let mut check = [0u8; 16];
        raw_ram.read_bytes(0x10ff8, &mut check).unwrap();
        assert_eq!(check, [0x5au8; 16]);

        // 5. DMA spanning two adjacent mappings (`0x2ff8..0x3008`) works for reads,
        //    but fails for writes because `[0x3000..=0x3fff]` is read-only!
        net_dma.write_bytes(0x2ff8, &[0x5au8; 8]).unwrap();
        raw_ram.write_bytes(0x14000, &[0xa5u8; 8]).unwrap();
        net_dma.read_bytes(0x2ff8, &mut check).unwrap();
        assert_eq!(&check[..8], &[0x5au8; 8]);
        assert_eq!(&check[8..], &[0xa5u8; 8]);
        assert!(net_dma.write_bytes(0x3000, &[0xffu8; 4]).is_err());

        // 6. Malicious L2 attempting to read L1 kernel secret at `0x9000` is blocked!
        assert!(net_dma.read_bytes(0x9000, &mut leak).is_err());
        assert_eq!(leak, [0u8; 16]);

        // 7. Partial UNMAP rejected (`S_RANGE`); full UNMAP succeeds (`S_OK`) and revokes access.
        assert_eq!(state.write().unmap(7, 0x1000, 0x1fff), VIRTIO_IOMMU_S_RANGE);
        assert_eq!(state.write().unmap(7, 0x1000, 0x2fff), VIRTIO_IOMMU_S_OK);
        assert!(net_dma.read_bytes(0x1000, &mut leak).is_err());

        // 8. Detaching the last endpoint from domain 7 deletes domain 7's remaining mappings.
        assert_eq!(state.write().detach(7, 0x0018), VIRTIO_IOMMU_S_OK);
        assert_eq!(
            state
                .write()
                .map(7, 0x1000, 0x1fff, 0x10000, VIRTIO_IOMMU_MAP_F_READ),
            VIRTIO_IOMMU_S_NOENT
        );
    }
}
