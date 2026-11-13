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

use std::io::ErrorKind;
use std::slice;
use std::sync::Arc;

use assert_matches::assert_matches;
use flume::Receiver;
use rstest::rstest;
use zerocopy::{FromBytes, IntoBytes};

use crate::mem::mapped::Ram;
use crate::sys::vmnet::{VmPktDesc, VmnetReturn};
use crate::virtio::Error;
use crate::virtio::dev::net::VirtioNetHdr;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::{GuestQueue, UsedDesc};
use crate::virtio::queue::{Queue, QueueReg};
use crate::virtio::tests::{self as virtio_tests, DATA_ADDR, FakeIrqSender};

const HDR_LEN: usize = size_of::<VirtioNetHdr>();
const DESC_STRIDE: u64 = 0x1000;

struct QueueHarness {
    ram: Arc<Ram>,
    host_q: Queue<SplitQueue>,
    guest_q: GuestQueue<SplitQueue>,
    irq_sender: FakeIrqSender,
    _irq_rx: Receiver<u16>,
}

impl QueueHarness {
    fn new() -> Self {
        let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
        let regs: Box<[QueueReg]> = virtio_tests::fixture_queues(1);
        let ram = ram_bus.load();
        let host_q = Queue::<SplitQueue>::new(&regs[0], ram_bus, false)
            .unwrap()
            .unwrap();
        let guest_q = GuestQueue::new(
            SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
            &regs[0],
        );
        let (irq_tx, irq_rx) = flume::unbounded();
        let irq_sender = FakeIrqSender { q_tx: irq_tx };
        Self {
            ram,
            host_q,
            guest_q,
            irq_sender,
            _irq_rx: irq_rx,
        }
    }

    fn add_rx_chain(&mut self, lens: &[u32], fill: u8) -> (u16, Vec<(u64, u32)>) {
        let writable: Vec<(u64, u32)> = lens
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                let gpa = DATA_ADDR + i as u64 * DESC_STRIDE;
                if len > 0 {
                    self.ram.write(gpa, &vec![fill; len as usize]).unwrap();
                }
                (gpa, len)
            })
            .collect();
        let id = self.guest_q.add_desc(&[], &writable);
        (id, writable)
    }

    fn read_chain(&self, descs: &[(u64, u32)], total_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(total_len);
        let mut rem = total_len;
        for &(gpa, len) in descs {
            let take = rem.min(len as usize);
            if take > 0 {
                let mut tmp = vec![0u8; take];
                self.ram.read(gpa, &mut tmp).unwrap();
                out.extend_from_slice(&tmp);
                rem -= take;
            }
            if rem == 0 {
                break;
            }
        }
        assert_eq!(rem, 0);
        out
    }

    fn add_tx_chain(&mut self, lens: &[u32], data: &[u8]) -> u16 {
        let total: usize = lens.iter().map(|&l| l as usize).sum();
        assert_eq!(total, data.len());
        let mut offset = 0;
        let readable: Vec<(u64, u32)> = lens
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                let gpa = DATA_ADDR + i as u64 * DESC_STRIDE;
                let len_usize = len as usize;
                if len_usize > 0 {
                    self.ram
                        .write(gpa, &data[offset..offset + len_usize])
                        .unwrap();
                    offset += len_usize;
                }
                (gpa, len)
            })
            .collect();
        self.guest_q.add_desc(&readable, &[])
    }
}

fn mock_eth_frame(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7) ^ 0x3c).collect()
}

fn write_mock_pkt(packets: &mut VmPktDesc, frame: &[u8]) {
    let iov =
        unsafe { slice::from_raw_parts_mut(packets.vm_pkt_iov, packets.vm_pkt_iovcnt as usize) };
    let cap: usize = iov.iter().map(|s| s.iov_len).sum();
    assert_eq!(packets.vm_pkt_size, cap);
    assert!(frame.len() <= cap);

    let mut rem = frame;
    for seg in iov {
        assert!(seg.iov_len > 0);
        if rem.is_empty() {
            break;
        }
        let dst = unsafe { slice::from_raw_parts_mut(seg.iov_base as *mut u8, seg.iov_len) };
        let len = rem.len().min(dst.len());
        dst[..len].copy_from_slice(&rem[..len]);
        rem = &rem[len..];
    }
    assert!(rem.is_empty());
    packets.vm_pkt_size = frame.len();
}

fn read_mock_pkt(packets: &VmPktDesc) -> Vec<u8> {
    let iov = unsafe { slice::from_raw_parts(packets.vm_pkt_iov, packets.vm_pkt_iovcnt as usize) };
    let total: usize = iov.iter().map(|s| s.iov_len).sum();
    assert_eq!(packets.vm_pkt_size, total);
    let mut out = Vec::with_capacity(total);
    for seg in iov {
        assert!(seg.iov_len > 0);
        let src = unsafe { slice::from_raw_parts(seg.iov_base as *const u8, seg.iov_len) };
        out.extend_from_slice(src);
    }
    out
}

#[test]
fn test_trim_desc_chain_single_slice() {
    let mut buf: Vec<u8> = (0..1526).map(|i| (i & 0xff) as u8).collect();
    let expected_ptr = unsafe { buf.as_ptr().add(HDR_LEN) };

    let iov = super::trim_desc_chain([buf.as_slice()]);
    assert_eq!(iov.len(), 1);
    assert_eq!(iov[0].iov_base as *const u8, expected_ptr);
    assert_eq!(iov[0].iov_len, 1514);

    let iov_mut = super::trim_desc_chain([buf.as_mut_slice()]);
    assert_eq!(iov_mut.len(), 1);
    assert_eq!(iov_mut[0].iov_base as *const u8, expected_ptr);
    assert_eq!(iov_mut[0].iov_len, 1514);
}

#[rstest]
#[case(&[12, 60], &[(1, 0, 60)])]
#[case(&[12, 30, 40], &[(1, 0, 30), (2, 0, 40)])]
#[case(&[4, 4, 4, 60], &[(3, 0, 60)])]
#[case(&[8, 20], &[(1, 4, 16)])]
#[case(&[0, 12, 60], &[(2, 0, 60)])]
#[case(&[0, 4, 0, 8, 0, 60, 0], &[(5, 0, 60)])]
#[case(&[], &[])]
#[case(&[0], &[])]
#[case(&[8], &[])]
#[case(&[4, 4], &[])]
#[case(&[12], &[])]
#[case(&[6, 6], &[])]
#[case(&[12, 0], &[])]
fn test_trim_desc_chain_layouts(
    #[case] slice_lens: &[usize],
    #[case] expected: &[(usize, usize, usize)],
) {
    let mut backing: Vec<Vec<u8>> = slice_lens.iter().map(|&n| vec![0x5au8; n]).collect();
    let ptrs: Vec<*const u8> = backing.iter().map(|v| v.as_ptr()).collect();

    let iov = super::trim_desc_chain(backing.iter().map(Vec::as_slice));
    assert_eq!(iov.len(), expected.len());
    for (seg, &(idx, off, len)) in iov.iter().zip(expected.iter()) {
        assert_eq!(seg.iov_base as *const u8, unsafe { ptrs[idx].add(off) });
        assert_eq!(seg.iov_len, len);
    }

    let iov_mut = super::trim_desc_chain(backing.iter_mut().map(Vec::as_mut_slice));
    assert_eq!(iov_mut.len(), expected.len());
    for (seg, &(idx, off, len)) in iov_mut.iter().zip(expected.iter()) {
        assert_eq!(seg.iov_base as *const u8, unsafe { ptrs[idx].add(off) });
        assert_eq!(seg.iov_len, len);
    }
}

#[rstest]
#[case(&[0])]
#[case(&[8])]
#[case(&[4, 4])]
#[case(&[12])]
#[case(&[6, 6])]
#[case(&[12, 0])]
fn test_rx_rejects_undersized_writable_chains(#[case] lens: &[u32]) {
    let mut h = QueueHarness::new();
    h.add_rx_chain(lens, 0xff);

    let mut invoked = false;
    let res = h.host_q.handle_desc(
        0,
        &h.irq_sender,
        super::read_from_vmnet_with(|_, _| {
            invoked = true;
            VmnetReturn::SUCCESS
        }),
    );
    assert_matches!(res, Err(Error::InvalidBuffer { .. }));
    assert!(!invoked);
    assert!(h.guest_q.get_used().is_none());
}

#[test]
fn test_rx_rejects_chain_with_no_writable_descriptors() {
    let mut h = QueueHarness::new();
    h.guest_q.add_desc(&[(DATA_ADDR, 64)], &[]);

    let mut invoked = false;
    let res = h.host_q.handle_desc(
        0,
        &h.irq_sender,
        super::read_from_vmnet_with(|_, _| {
            invoked = true;
            VmnetReturn::SUCCESS
        }),
    );
    assert_matches!(res, Err(Error::InvalidBuffer { .. }));
    assert!(!invoked);
    assert!(h.guest_q.get_used().is_none());
}

#[test]
fn test_rx_contiguous_buffer() {
    let mut h = QueueHarness::new();
    let (id, descs) = h.add_rx_chain(&[1526], 0xff);
    let frame = mock_eth_frame(60);

    h.host_q
        .handle_desc(
            0,
            &h.irq_sender,
            super::read_from_vmnet_with(|packets, pktcnt| {
                assert_eq!(packets.vm_pkt_iovcnt, 1);
                assert_eq!(packets.vm_pkt_size, 1514);
                write_mock_pkt(packets, &frame);
                *pktcnt = 1;
                VmnetReturn::SUCCESS
            }),
        )
        .unwrap();

    let expected_len = (HDR_LEN + frame.len()) as u32;
    assert_matches!(
        h.guest_q.get_used(),
        Some(UsedDesc { id: used_id, len, .. }) if used_id == id && len == expected_len
    );

    let written = h.read_chain(&descs, expected_len as usize);
    let hdr = VirtioNetHdr::read_from_bytes(&written[..HDR_LEN]).unwrap();
    assert_eq!(hdr.flags, 0);
    assert_eq!(hdr.gso_type, 0);
    assert_eq!(hdr.hdr_len, 0);
    assert_eq!(hdr.gso_size, 0);
    assert_eq!(hdr.csum_start, 0);
    assert_eq!(hdr.csum_offset, 0);
    assert_eq!(hdr.num_buffers, 1);
    assert_eq!(&written[HDR_LEN..], frame.as_slice());
}

#[rstest]
#[case(&[6, 6, 64], 60)]
#[case(&[10, 64], 60)]
#[case(&[0, 8, 68], 60)]
#[case(&[5, 5, 5, 25, 36], 60)]
fn test_rx_scatter_gather_split_header_and_payload(#[case] lens: &[u32], #[case] pkt_len: usize) {
    let mut h = QueueHarness::new();
    let (id, descs) = h.add_rx_chain(lens, 0xa5);
    let frame = mock_eth_frame(pkt_len);

    h.host_q
        .handle_desc(
            0,
            &h.irq_sender,
            super::read_from_vmnet_with(|packets, pktcnt| {
                write_mock_pkt(packets, &frame);
                *pktcnt = 1;
                VmnetReturn::SUCCESS
            }),
        )
        .unwrap();

    let expected_len = (HDR_LEN + frame.len()) as u32;
    assert_matches!(
        h.guest_q.get_used(),
        Some(UsedDesc { id: used_id, len, .. }) if used_id == id && len == expected_len
    );

    let written = h.read_chain(&descs, expected_len as usize);
    let expected_hdr = VirtioNetHdr {
        num_buffers: 1,
        ..Default::default()
    };
    assert_eq!(&written[..HDR_LEN], expected_hdr.as_bytes());
    let hdr = VirtioNetHdr::read_from_bytes(&written[..HDR_LEN]).unwrap();
    assert_eq!(hdr.num_buffers, 1);
    assert_eq!(&written[HDR_LEN..], frame.as_slice());
}

#[test]
fn test_rx_break_when_pktcnt_zero() {
    let mut h = QueueHarness::new();
    h.add_rx_chain(&[1526], 0);

    h.host_q
        .handle_desc(
            0,
            &h.irq_sender,
            super::read_from_vmnet_with(|_, pktcnt| {
                *pktcnt = 0;
                VmnetReturn::SUCCESS
            }),
        )
        .unwrap();

    assert!(h.guest_q.get_used().is_none());
}

#[test]
fn test_rx_rejects_oversized_vm_pkt_size() {
    let mut h = QueueHarness::new();
    h.add_rx_chain(&[12, 64], 0);

    let res = h.host_q.handle_desc(
        0,
        &h.irq_sender,
        super::read_from_vmnet_with(|packets, pktcnt| {
            packets.vm_pkt_size += 1;
            *pktcnt = 1;
            VmnetReturn::SUCCESS
        }),
    );
    assert_matches!(res, Err(Error::InvalidBuffer { .. }));
    assert!(h.guest_q.get_used().is_none());
}

#[rstest]
#[case(VmnetReturn::MEM_FAILURE, ErrorKind::OutOfMemory)]
#[case(VmnetReturn::INVALID_ARGUMENT, ErrorKind::InvalidInput)]
#[case(VmnetReturn::INVALID_ACCESS, ErrorKind::PermissionDenied)]
#[case(VmnetReturn::FAILURE, ErrorKind::Other)]
fn test_rx_vmnet_error_mapping(#[case] ret: VmnetReturn, #[case] expected_kind: ErrorKind) {
    let mut h = QueueHarness::new();
    h.add_rx_chain(&[1526], 0);

    let res = h
        .host_q
        .handle_desc(0, &h.irq_sender, super::read_from_vmnet_with(|_, _| ret));
    assert_matches!(
        res,
        Err(Error::System { error, .. }) if error.kind() == expected_kind
    );
    assert!(h.guest_q.get_used().is_none());
}

#[rstest]
#[case(&[0])]
#[case(&[8])]
#[case(&[4, 4])]
#[case(&[12])]
#[case(&[5, 7])]
#[case(&[12, 0])]
fn test_tx_rejects_undersized_readable_chains(#[case] lens: &[u32]) {
    let mut h = QueueHarness::new();
    let total: usize = lens.iter().map(|&l| l as usize).sum();
    h.add_tx_chain(lens, &vec![0x11u8; total]);

    let mut invoked = false;
    let res = h.host_q.handle_desc(
        1,
        &h.irq_sender,
        super::write_to_vmnet_with(|_, _| {
            invoked = true;
            VmnetReturn::SUCCESS
        }),
    );
    assert_matches!(res, Err(Error::InvalidBuffer { .. }));
    assert!(!invoked);
    assert!(h.guest_q.get_used().is_none());
}

#[test]
fn test_tx_rejects_chain_with_no_readable_descriptors() {
    let mut h = QueueHarness::new();
    h.guest_q.add_desc(&[], &[(DATA_ADDR, 64)]);

    let mut invoked = false;
    let res = h.host_q.handle_desc(
        1,
        &h.irq_sender,
        super::write_to_vmnet_with(|_, _| {
            invoked = true;
            VmnetReturn::SUCCESS
        }),
    );
    assert_matches!(res, Err(Error::InvalidBuffer { .. }));
    assert!(!invoked);
    assert!(h.guest_q.get_used().is_none());
}

#[rstest]
#[case(&[5, 7, 30, 30], 60)]
#[case(&[8, 24, 40], 60)]
#[case(&[0, 12, 60], 60)]
#[case(&[72], 60)]
fn test_tx_strips_header_across_split_descriptors(#[case] lens: &[u32], #[case] pkt_len: usize) {
    let mut h = QueueHarness::new();
    let hdr = VirtioNetHdr {
        flags: 1,
        gso_type: 2,
        hdr_len: 14,
        gso_size: 1460,
        csum_start: 14,
        csum_offset: 16,
        num_buffers: 0,
    };
    let frame = mock_eth_frame(pkt_len);
    let mut full_buf = Vec::with_capacity(HDR_LEN + pkt_len);
    full_buf.extend_from_slice(hdr.as_bytes());
    full_buf.extend_from_slice(&frame);

    let id = h.add_tx_chain(lens, &full_buf);

    let mut transmitted = None;
    h.host_q
        .handle_desc(
            1,
            &h.irq_sender,
            super::write_to_vmnet_with(|packets, pktcnt| {
                transmitted = Some(read_mock_pkt(packets));
                *pktcnt = 1;
                VmnetReturn::SUCCESS
            }),
        )
        .unwrap();

    assert_eq!(transmitted.as_deref(), Some(frame.as_slice()));
    assert_matches!(
        h.guest_q.get_used(),
        Some(UsedDesc { id: used_id, len: 0, .. }) if used_id == id
    );
}

#[test]
fn test_tx_break_when_pktcnt_zero_and_error_mapping() {
    let mut h = QueueHarness::new();
    let mut full_buf = vec![0u8; HDR_LEN];
    full_buf.extend_from_slice(&mock_eth_frame(60));
    let id = h.add_tx_chain(&[5, 7, 30, 30], &full_buf);

    h.host_q
        .handle_desc(
            1,
            &h.irq_sender,
            super::write_to_vmnet_with(|_, pktcnt| {
                *pktcnt = 0;
                VmnetReturn::SUCCESS
            }),
        )
        .unwrap();
    assert!(h.guest_q.get_used().is_none());

    let res = h.host_q.handle_desc(
        1,
        &h.irq_sender,
        super::write_to_vmnet_with(|_, _| VmnetReturn::INVALID_ARGUMENT),
    );
    assert_matches!(
        res,
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::InvalidInput
    );
    assert!(h.guest_q.get_used().is_none());

    h.host_q
        .handle_desc(
            1,
            &h.irq_sender,
            super::write_to_vmnet_with(|_, pktcnt| {
                *pktcnt = 1;
                VmnetReturn::SUCCESS
            }),
        )
        .unwrap();
    assert_matches!(
        h.guest_q.get_used(),
        Some(UsedDesc { id: used_id, len: 0, .. }) if used_id == id
    );
}
