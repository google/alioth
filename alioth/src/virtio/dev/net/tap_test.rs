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

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::Arc;

use assert_matches::assert_matches;
use mio::unix::SourceFd;
use mio::{Interest, Poll, Token};
use rstest::rstest;

use crate::device::net::MacAddr;
use crate::mem::mapped::Ram;
use crate::virtio::Error;
use crate::virtio::dev::DevSpec;
use crate::virtio::dev::net::tap::{MIN_MTU, Net, TapNetSpec};
use crate::virtio::dev::net::{NetConfig, NetFeature};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::GuestQueue;
use crate::virtio::queue::{DescChain, QueueReg, VirtQueue};
use crate::virtio::tests::{self, DATA_ADDR};
use crate::virtio::worker::WorkerApi;
use crate::virtio::worker::io_uring::{BufferAction, VirtioIoUring};
use crate::virtio::worker::mio::VirtioMio;

const WRITABLE_ADDR: u64 = DATA_ADDR + 4096;

fn fixture_net(max_queue_pairs: u16, num_sockets: usize, api: WorkerApi) -> Net {
    let tap_sockets = (0..num_sockets)
        .map(|_| {
            let (sock, _peer) = UnixDatagram::pair().unwrap();
            File::from(OwnedFd::from(sock))
        })
        .collect();
    let mut feature = NetFeature::MAC | NetFeature::MTU | NetFeature::CTRL_VQ;
    if max_queue_pairs > 1 {
        feature |= NetFeature::MQ;
    }
    Net {
        name: "test-net".into(),
        config: Arc::new(NetConfig {
            max_queue_pairs,
            mtu: 1500,
            ..Default::default()
        }),
        tap_sockets,
        feature,
        driver_feature: NetFeature::empty(),
        dev_tap: None,
        if_name: None,
        api,
    }
}

struct ChainBuilder {
    ram: Arc<Ram>,
    _regs: Box<[QueueReg]>,
    guest_q: GuestQueue<SplitQueue>,
    dev_q: SplitQueue,
    avail_idx: u16,
}

impl ChainBuilder {
    fn new() -> Self {
        let ram_bus = tests::fixture_ram_bus();
        let regs = tests::fixture_queues(1);
        let ram = ram_bus.load();
        let guest_q = GuestQueue::new(
            SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
            &regs[0],
        );
        let dev_q = SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap();
        Self {
            ram,
            _regs: regs,
            guest_q,
            dev_q,
            avail_idx: 0,
        }
    }

    fn build<'m>(
        &'m mut self,
        readable_chunks: &[&[u8]],
        writable_lens: &[u32],
    ) -> (DescChain<'m>, Vec<(u64, u32)>) {
        let mut r_addr = DATA_ADDR;
        let mut r_descs = Vec::with_capacity(readable_chunks.len());
        for chunk in readable_chunks {
            if !chunk.is_empty() {
                self.ram.write(r_addr, chunk).unwrap();
            }
            let len = chunk.len() as u32;
            r_descs.push((r_addr, len));
            r_addr += u64::from(len.max(1));
        }

        let mut w_addr = WRITABLE_ADDR;
        let mut w_descs = Vec::with_capacity(writable_lens.len());
        for &len in writable_lens {
            if len > 0 {
                let fill = vec![0xffu8; len as usize];
                self.ram.write(w_addr, &fill).unwrap();
            }
            w_descs.push((w_addr, len));
            w_addr += u64::from(len.max(1));
        }

        self.guest_q.add_desc(&r_descs, &w_descs);
        let chain = self
            .dev_q
            .get_avail(self.avail_idx, &self.ram)
            .unwrap()
            .unwrap();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        (chain, w_descs)
    }
}

#[test]
fn test_io_uring_reset() {
    let mut net = fixture_net(4, 3, WorkerApi::IoUring);
    net.driver_feature = NetFeature::CSUM | NetFeature::MQ | NetFeature::CTRL_VQ;

    let mut builder = ChainBuilder::new();
    {
        let (mut rx2_chain, _) = builder.build(&[], &[64]);
        assert_matches!(
            VirtioIoUring::handle_desc(&mut net, 2, &mut rx2_chain),
            Ok(BufferAction::Sqe(_))
        );
    }

    VirtioIoUring::reset(&mut net);
    assert_eq!(net.tap_sockets.len(), 1);
    assert!(net.driver_feature.is_empty());

    // After reset, only queue pair 0 (rxq1/txq1) remains active.
    {
        let (mut rx2_chain, _) = builder.build(&[], &[64]);
        assert_matches!(
            VirtioIoUring::handle_desc(&mut net, 2, &mut rx2_chain),
            Ok(BufferAction::Written(0))
        );
    }
    {
        let (mut rx1_chain, _) = builder.build(&[], &[64]);
        assert_matches!(
            VirtioIoUring::handle_desc(&mut net, 0, &mut rx1_chain),
            Ok(BufferAction::Sqe(_))
        );
    }
}

#[test]
fn test_mio_reset() {
    let mut net = fixture_net(4, 3, WorkerApi::Mio);
    net.driver_feature = NetFeature::CSUM | NetFeature::MQ | NetFeature::CTRL_VQ;

    let poll = Poll::new().unwrap();
    poll.registry()
        .register(
            &mut SourceFd(&net.tap_sockets[0].as_raw_fd()),
            Token(0),
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();

    VirtioMio::reset(&mut net, poll.registry());
    assert_eq!(net.tap_sockets.len(), 1);
    assert!(net.driver_feature.is_empty());
}

#[test]
fn test_tap_net_spec_default() {
    let spec = TapNetSpec::default();
    assert_eq!(spec.mtu, 0);
    let (config, feat) = spec.build_config().unwrap();
    assert_eq!(config.mtu, 0);
    assert_eq!(config.max_queue_pairs, 1);
    assert!(!feat.contains(NetFeature::MTU));
    assert!(!feat.contains(NetFeature::MQ));
    assert!(feat.contains(NetFeature::MAC));
}

#[rstest]
#[case(0, 0, false, 1, false)]
#[case(MIN_MTU, 1, true, 1, false)]
#[case(1280, 1, true, 1, false)]
#[case(1500, 2, true, 2, true)]
#[case(65535, 4, true, 4, true)]
fn test_build_config(
    #[case] mtu: u16,
    #[case] queue_pairs: u16,
    #[case] want_mtu_feat: bool,
    #[case] want_max_qp: u16,
    #[case] want_mq_feat: bool,
) {
    let mac = MacAddr([0x02, 0x32, 0x10, 0xd0, 0x00, 0x01]);
    let spec = TapNetSpec {
        mac: mac.clone(),
        mtu,
        queue_pairs,
        ..Default::default()
    };
    let (config, feat) = spec.build_config().unwrap();
    assert_eq!(config.mac, mac);
    assert_eq!(config.mtu, mtu);
    assert_eq!(feat.contains(NetFeature::MTU), want_mtu_feat);
    assert_eq!(config.max_queue_pairs, want_max_qp);
    assert_eq!(feat.contains(NetFeature::MQ), want_mq_feat);
}

#[rstest]
#[case(1)]
#[case(67)]
fn test_invalid_mtu(#[case] mtu: u16) {
    let spec = TapNetSpec {
        mtu,
        tap: Some(Path::new("/nonexistent/tap").into()),
        ..Default::default()
    };
    assert_matches!(
        spec.build_config(),
        Err(Error::InvalidMtu { mtu: actual, .. }) if actual == mtu
    );
    assert_matches!(
        Net::new(spec.clone(), "tap-net"),
        Err(Error::InvalidMtu { mtu: actual, .. }) if actual == mtu
    );
    assert_matches!(
        spec.build("tap-net"),
        Err(Error::InvalidMtu { mtu: actual, .. }) if actual == mtu
    );
}
