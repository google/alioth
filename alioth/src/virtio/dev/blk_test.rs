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
use std::os::fd::BorrowedFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use assert_matches::assert_matches;
use flume::Sender;
use mio::Poll;
use rstest::rstest;
use tempfile::NamedTempFile;
use zerocopy::IntoBytes;

use crate::mem::mapped::Ram;
use crate::virtio::dev::blk::{
    BlkFileSpec, BlkRequest, Block, BlockFeature, Request, RequestType, SECTOR_SIZE, Status,
    VIRTIO_BLK_ID_SIZE,
};
use crate::virtio::dev::{DevSpec, StartParam, Virtio, VirtioDevice, WakeEvent};
use crate::virtio::queue::packed::PackedQueue;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::{GuestQueue, VirtQueueGuest};
use crate::virtio::queue::{Queue, Status as QStatus};
use crate::virtio::tests::{DATA_ADDR, FakeIrqSender};
use crate::virtio::worker::WorkerApi;
use crate::virtio::worker::mio::{ActiveMio, VirtioMio};
use crate::virtio::{
    DeviceId, Error, FEATURE_BUILT_IN, IrqSender, Result, VirtioFeature, tests as virtio_tests,
};

fn create_disk_file(sectors: u64) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    file.as_file()
        .set_len(sectors * SECTOR_SIZE as u64)
        .unwrap();
    file
}

fn build_block(path: &Path, readonly: bool, name: &str) -> Block {
    BlkFileSpec {
        path: path.into(),
        readonly,
        api: WorkerApi::Mio,
    }
    .build(name)
    .unwrap()
}

fn write_req(ram: &Ram, gpa: u64, type_: RequestType, sector: u64) {
    let req = Request {
        type_,
        reserved: 0,
        sector,
    };
    ram.write(gpa, req.as_bytes()).unwrap();
}

fn run_mio_queue<Q>(dev: &mut Block, host_q: Queue<Q>) -> (Result<()>, Queue<Q>)
where
    Q: VirtQueueGuest,
{
    let (irq_tx, _irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();
    let mut queues = [Some(host_q)];
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &[],
        poll: &mut poll,
    };
    let ret = VirtioMio::handle_queue(dev, 0, &mut active_mio);
    (ret, queues[0].take().unwrap())
}

#[derive(Debug)]
struct TestIrqSender {
    q_tx: Sender<u16>,
    config_tx: Sender<()>,
}

impl IrqSender for TestIrqSender {
    fn queue_irq(&self, idx: u16) {
        let _ = self.q_tx.send(idx);
    }

    fn config_irq(&self) {
        let _ = self.config_tx.send(());
    }

    fn queue_irqfd<F, T>(&self, _idx: u16, _f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        unimplemented!()
    }

    fn config_irqfd<F, T>(&self, _f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        unimplemented!()
    }
}

#[test]
fn block_new_and_lock_test() {
    let disk_file = create_disk_file(8);
    let dev = build_block(disk_file.path(), false, "blk0");
    assert_eq!(dev.id(), DeviceId::BLOCK);
    assert_eq!(dev.name(), "blk0");
    assert_eq!(dev.num_queues(), 1);
    assert_eq!(dev.config().capacity, 8);
    assert_eq!(dev.feature(), BlockFeature::FLUSH.bits() | FEATURE_BUILT_IN);

    let dup = BlkFileSpec {
        path: disk_file.path().into(),
        readonly: false,
        api: WorkerApi::Mio,
    }
    .build("blk-dup");
    assert_matches!(dup, Err(Error::LockFile { .. }));
    drop(dev);

    let ro1 = build_block(disk_file.path(), true, "blk-ro1");
    let ro2 = build_block(disk_file.path(), true, "blk-ro2");
    assert_eq!(
        ro1.feature(),
        (BlockFeature::FLUSH | BlockFeature::RO).bits() | FEATURE_BUILT_IN
    );
    assert_eq!(ro2.config().capacity, 8);
}

fn check_scatter_gather_in_out<Q>(mut host_q: Queue<Q>, mut guest_q: GuestQueue<Q>, ram: &Ram)
where
    Q: VirtQueueGuest,
{
    let disk_file = create_disk_file(16);
    let mut dev = build_block(disk_file.path(), false, "blk-sg");

    let hdr_gpa = DATA_ADDR;
    let status_gpa = DATA_ADDR + 0x100;
    let out0_gpa = DATA_ADDR + 0x1000;
    let out1_gpa = DATA_ADDR + 0x3000;
    let out2_gpa = DATA_ADDR + 0x6000;

    let seg0: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
    let seg1: Vec<u8> = (0..1024).map(|i| ((i * 7 + 3) % 253) as u8).collect();
    let seg2: Vec<u8> = (0..512).map(|i| ((i * 13 + 11) % 241) as u8).collect();
    ram.write(out0_gpa, &seg0).unwrap();
    ram.write(out1_gpa, &seg1).unwrap();
    ram.write(out2_gpa, &seg2).unwrap();
    ram.write_t(status_gpa, &0xffu8).unwrap();
    write_req(ram, hdr_gpa, RequestType::OUT, 2);

    let out_id = guest_q.add_desc(
        &[
            (hdr_gpa, size_of::<Request>() as u32),
            (out0_gpa, seg0.len() as u32),
            (out1_gpa, seg1.len() as u32),
            (out2_gpa, seg2.len() as u32),
        ],
        &[(status_gpa, 1)],
    );
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;

    let used = guest_q.get_used().unwrap();
    assert_eq!((used.id, used.len), (out_id, 1));
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    let mut expected = Vec::new();
    expected.extend_from_slice(&seg0);
    expected.extend_from_slice(&seg1);
    expected.extend_from_slice(&seg2);

    let observer = File::open(disk_file.path()).unwrap();
    let mut on_disk = vec![0u8; expected.len()];
    observer
        .read_exact_at(&mut on_disk, 2 * SECTOR_SIZE as u64)
        .unwrap();
    assert_eq!(on_disk, expected);

    // Read the 2048 bytes back into 3 differently sized guest segments.
    let in0_gpa = DATA_ADDR + 0x10000;
    let in1_gpa = DATA_ADDR + 0x14000;
    let in2_gpa = DATA_ADDR + 0x18000;
    ram.write_t(status_gpa, &0xffu8).unwrap();
    write_req(ram, hdr_gpa, RequestType::IN, 2);

    let in_id = guest_q.add_desc(
        &[(hdr_gpa, size_of::<Request>() as u32)],
        &[
            (in0_gpa, 256),
            (in1_gpa, 1280),
            (in2_gpa, 512),
            (status_gpa, 1),
        ],
    );
    let (ret, _host_q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();

    let used = guest_q.get_used().unwrap();
    assert_eq!((used.id, used.len), (in_id, 2048 + 1));
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    let mut actual = vec![0u8; 2048];
    ram.read(in0_gpa, &mut actual[..256]).unwrap();
    ram.read(in1_gpa, &mut actual[256..1536]).unwrap();
    ram.read(in2_gpa, &mut actual[1536..2048]).unwrap();
    assert_eq!(actual, expected);
}

#[rstest]
#[case::split(false)]
#[case::packed(true)]
fn scatter_gather_in_out_test(#[case] packed: bool) {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let regs = virtio_tests::fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &regs[0];
    if packed {
        let host_q = Queue::<PackedQueue>::new(reg, ram_bus.clone(), false)
            .unwrap()
            .unwrap();
        let guest_q = GuestQueue::new(PackedQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
        check_scatter_gather_in_out(host_q, guest_q, &ram);
    } else {
        let host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
            .unwrap()
            .unwrap();
        let guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
        check_scatter_gather_in_out(host_q, guest_q, &ram);
    }
}

#[test]
fn coalesced_and_split_framing_test() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let regs = virtio_tests::fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &regs[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);

    let disk_file = create_disk_file(8);
    let mut dev = build_block(disk_file.path(), false, "blk-frame");

    // 1. Coalesced single readable descriptor: [16B hdr | 512B data_out].
    let coalesced_out_gpa = DATA_ADDR;
    let status_gpa = DATA_ADDR + 0x1000;
    let pattern_a: Vec<u8> = (0..512).map(|i| (i ^ 0x5a) as u8).collect();
    write_req(&ram, coalesced_out_gpa, RequestType::OUT, 1);
    ram.write(coalesced_out_gpa + size_of::<Request>() as u64, &pattern_a)
        .unwrap();
    ram.write_t(status_gpa, &0xffu8).unwrap();

    guest_q.add_desc(
        &[(coalesced_out_gpa, (size_of::<Request>() + 512) as u32)],
        &[(status_gpa, 1)],
    );
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    // 2. Coalesced single writable descriptor: [512B data_in | 1B status].
    let hdr_gpa = DATA_ADDR + 0x2000;
    let coalesced_in_gpa = DATA_ADDR + 0x3000;
    write_req(&ram, hdr_gpa, RequestType::IN, 1);
    ram.write(coalesced_in_gpa, &[0xffu8; 513]).unwrap();

    guest_q.add_desc(
        &[(hdr_gpa, size_of::<Request>() as u32)],
        &[(coalesced_in_gpa, 513)],
    );
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.len, 513);
    let mut read_back = vec![0u8; 513];
    ram.read(coalesced_in_gpa, &mut read_back).unwrap();
    assert_eq!(&read_back[..512], &pattern_a[..]);
    assert_eq!(read_back[512], Status::OK.raw());

    // 3. Split 16-byte header across 3 descriptors, with the 3rd also carrying
    // 200 bytes of OUT data, followed by 312 bytes in a 4th descriptor.
    let req_bytes = Request {
        type_: RequestType::OUT,
        reserved: 0,
        sector: 3,
    };
    let raw_hdr = req_bytes.as_bytes();
    let pattern_b: Vec<u8> = (0..512).map(|i| ((i * 3) ^ 0xa5) as u8).collect();
    let r0_gpa = DATA_ADDR + 0x4000;
    let r1_gpa = DATA_ADDR + 0x4100;
    let r2_gpa = DATA_ADDR + 0x4200;
    let r3_gpa = DATA_ADDR + 0x4400;
    ram.write(r0_gpa, &raw_hdr[..5]).unwrap();
    ram.write(r1_gpa, &raw_hdr[5..12]).unwrap();
    ram.write(r2_gpa, &raw_hdr[12..16]).unwrap();
    ram.write(r2_gpa + 4, &pattern_b[..200]).unwrap();
    ram.write(r3_gpa, &pattern_b[200..]).unwrap();
    ram.write_t(status_gpa, &0xffu8).unwrap();

    guest_q.add_desc(
        &[(r0_gpa, 5), (r1_gpa, 7), (r2_gpa, 204), (r3_gpa, 312)],
        &[(status_gpa, 1)],
    );
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    // 4. Split 16-byte header (6B + 10B) + multi-segment IN with coalesced tail [256B, 257B].
    let in_hdr = Request {
        type_: RequestType::IN,
        reserved: 0,
        sector: 3,
    };
    let in_hdr_bytes = in_hdr.as_bytes();
    let ih0_gpa = DATA_ADDR + 0x5000;
    let ih1_gpa = DATA_ADDR + 0x5100;
    let iw0_gpa = DATA_ADDR + 0x5200;
    let iw1_gpa = DATA_ADDR + 0x5400;
    ram.write(ih0_gpa, &in_hdr_bytes[..6]).unwrap();
    ram.write(ih1_gpa, &in_hdr_bytes[6..16]).unwrap();
    ram.write(iw1_gpa, &[0xffu8; 257]).unwrap();

    guest_q.add_desc(
        &[(ih0_gpa, 6), (ih1_gpa, 10)],
        &[(iw0_gpa, 256), (iw1_gpa, 257)],
    );
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    assert_eq!(guest_q.get_used().unwrap().len, 513);
    let mut got = vec![0u8; 512];
    ram.read(iw0_gpa, &mut got[..256]).unwrap();
    ram.read(iw1_gpa, &mut got[256..512]).unwrap();
    assert_eq!(got, pattern_b);
    assert_eq!(ram.read_t::<u8>(iw1_gpa + 256).unwrap(), Status::OK.raw());

    // 5. Zero-byte OUT and zero-byte IN complete cleanly with written == 1.
    for op in [RequestType::OUT, RequestType::IN] {
        write_req(&ram, hdr_gpa, op, 0);
        ram.write_t(status_gpa, &0xffu8).unwrap();
        guest_q.add_desc(&[(hdr_gpa, 16)], &[(status_gpa, 1)]);
        let (ret, q) = run_mio_queue(&mut dev, host_q);
        ret.unwrap();
        host_q = q;
        assert_eq!(guest_q.get_used().unwrap().len, 1);
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());
    }
}

#[test]
fn flush_get_id_ro_and_errors_test() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let regs = virtio_tests::fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &regs[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);

    let disk_file = create_disk_file(2);
    let mut dev = build_block(disk_file.path(), false, "blk-id");

    let hdr_gpa = DATA_ADDR;
    let status_gpa = DATA_ADDR + 0x100;
    let data_gpa = DATA_ADDR + 0x1000;

    // FLUSH succeeds.
    write_req(&ram, hdr_gpa, RequestType::FLUSH, 0);
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16)], &[(status_gpa, 1)]);
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    // FLUSH ignores data, which a driver SHOULD NOT include but may.
    for (readable, writable) in [
        (
            &[(hdr_gpa, 16), (data_gpa, 512)][..],
            &[(status_gpa, 1)][..],
        ),
        (
            &[(hdr_gpa, 16)][..],
            &[(data_gpa, 512), (status_gpa, 1)][..],
        ),
    ] {
        write_req(&ram, hdr_gpa, RequestType::FLUSH, 0);
        ram.write(data_gpa, &[0xcd; 512]).unwrap();
        ram.write_t(status_gpa, &0xffu8).unwrap();
        guest_q.add_desc(readable, writable);
        let (ret, q) = run_mio_queue(&mut dev, host_q);
        ret.unwrap();
        host_q = q;
        assert_eq!(guest_q.get_used().unwrap().len, 1);
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());
        let mut data = [0u8; 512];
        ram.read(data_gpa, &mut data).unwrap();
        assert_eq!(data, [0xcd; 512]);
    }

    // GET_ID across 3 writable slices [6, 6, 8], NUL-padded to 20 bytes.
    let id0_gpa = DATA_ADDR + 0x200;
    let id1_gpa = DATA_ADDR + 0x220;
    let id2_gpa = DATA_ADDR + 0x240;
    ram.write(id0_gpa, &[0xffu8; 6]).unwrap();
    ram.write(id1_gpa, &[0xffu8; 6]).unwrap();
    ram.write(id2_gpa, &[0xffu8; 8]).unwrap();
    ram.write_t(status_gpa, &0xffu8).unwrap();
    write_req(&ram, hdr_gpa, RequestType::GET_ID, 0);
    guest_q.add_desc(
        &[(hdr_gpa, 16)],
        &[(id0_gpa, 6), (id1_gpa, 6), (id2_gpa, 8), (status_gpa, 1)],
    );
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    assert_eq!(
        guest_q.get_used().unwrap().len,
        VIRTIO_BLK_ID_SIZE as u32 + 1
    );
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());
    let mut id_bytes = [0u8; VIRTIO_BLK_ID_SIZE];
    ram.read(id0_gpa, &mut id_bytes[..6]).unwrap();
    ram.read(id1_gpa, &mut id_bytes[6..12]).unwrap();
    ram.read(id2_gpa, &mut id_bytes[12..20]).unwrap();
    let mut expected_id = [0u8; VIRTIO_BLK_ID_SIZE];
    expected_id[..6].copy_from_slice(b"blk-id");
    assert_eq!(id_bytes, expected_id);

    // Unknown op (including DISCARD with data_out) returns Status::UNSUPP.
    for (op, extra_out) in [(RequestType::DISCARD, 16u32), (RequestType(0xff), 0u32)] {
        write_req(&ram, hdr_gpa, op, 0);
        ram.write_t(status_gpa, &0xffu8).unwrap();
        if extra_out > 0 {
            guest_q.add_desc(&[(hdr_gpa, 16), (data_gpa, extra_out)], &[(status_gpa, 1)]);
        } else {
            guest_q.add_desc(&[(hdr_gpa, 16)], &[(status_gpa, 1)]);
        }
        let (ret, q) = run_mio_queue(&mut dev, host_q);
        ret.unwrap();
        host_q = q;
        assert_eq!(guest_q.get_used().unwrap().len, 1);
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::UNSUPP.raw());
    }

    // Read beyond the capacity returns Status::IOERR with written == 1.
    write_req(&ram, hdr_gpa, RequestType::IN, 10);
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16)], &[(data_gpa, 512), (status_gpa, 1)]);
    let (ret, q) = run_mio_queue(&mut dev, host_q);
    ret.unwrap();
    host_q = q;
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::IOERR.raw());

    // Sector multiplication overflow and off_t overflow return Status::IOERR without panicking.
    for (op, bad_sector) in [
        (RequestType::IN, u64::MAX),
        (RequestType::OUT, u64::MAX),
        (RequestType::IN, 1u64 << 55),
        (RequestType::OUT, 1u64 << 55),
    ] {
        write_req(&ram, hdr_gpa, op, bad_sector);
        ram.write_t(status_gpa, &0xffu8).unwrap();
        if op == RequestType::IN {
            guest_q.add_desc(&[(hdr_gpa, 16)], &[(data_gpa, 512), (status_gpa, 1)]);
        } else {
            guest_q.add_desc(&[(hdr_gpa, 16), (data_gpa, 512)], &[(status_gpa, 1)]);
        }
        let (ret, q) = run_mio_queue(&mut dev, host_q);
        ret.unwrap();
        host_q = q;
        assert_eq!(guest_q.get_used().unwrap().len, 1);
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::IOERR.raw());
    }

    // Writes beyond the capacity return Status::IOERR and do not extend the
    // disk image file.
    for (sector, len) in [(2, 512), (1, 1024)] {
        write_req(&ram, hdr_gpa, RequestType::OUT, sector);
        ram.write_t(status_gpa, &0xffu8).unwrap();
        guest_q.add_desc(&[(hdr_gpa, 16), (data_gpa, len)], &[(status_gpa, 1)]);
        let (ret, q) = run_mio_queue(&mut dev, host_q);
        ret.unwrap();
        host_q = q;
        assert_eq!(guest_q.get_used().unwrap().len, 1);
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::IOERR.raw());
    }
    let disk_len = disk_file.as_file().metadata().unwrap().len();
    assert_eq!(disk_len, 2 * SECTOR_SIZE as u64);

    // Long device name (> 20 bytes) is truncated to VIRTIO_BLK_ID_SIZE without NUL terminator.
    drop(dev);
    let mut long_dev = build_block(disk_file.path(), true, "0123456789abcdefghijklmnop");
    write_req(&ram, hdr_gpa, RequestType::GET_ID, 0);
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16)], &[(data_gpa, 20), (status_gpa, 1)]);
    let (ret, q) = run_mio_queue(&mut long_dev, host_q);
    ret.unwrap();
    host_q = q;
    assert_eq!(guest_q.get_used().unwrap().len, 21);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());
    let mut got_long_id = [0u8; 20];
    ram.read(data_gpa, &mut got_long_id).unwrap();
    assert_eq!(&got_long_id, b"0123456789abcdefghij");

    // Read-only device rejects OUT with Status::IOERR and does not modify disk.
    ram.write(data_gpa, &[0xcd; 512]).unwrap();
    write_req(&ram, hdr_gpa, RequestType::OUT, 0);
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16), (data_gpa, 512)], &[(status_gpa, 1)]);
    let (ret, _host_q) = run_mio_queue(&mut long_dev, host_q);
    ret.unwrap();
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::IOERR.raw());
    let mut sector0 = [0xffu8; 512];
    disk_file.as_file().read_exact_at(&mut sector0, 0).unwrap();
    assert_eq!(sector0, [0u8; 512]);
}

#[derive(Debug, Clone, Copy)]
enum MalformedCase {
    EmptyReadable,
    ShortSplitHeader,
    EmptyWritable,
    InWithSeparateDataOut,
    InWithCoalescedDataOut,
    OutWithSeparateDataIn,
    OutWithCoalescedDataIn,
    GetIdWithDataOut,
}

#[rstest]
#[case::empty_readable(MalformedCase::EmptyReadable)]
#[case::short_split_header(MalformedCase::ShortSplitHeader)]
#[case::empty_writable(MalformedCase::EmptyWritable)]
#[case::in_separate_data_out(MalformedCase::InWithSeparateDataOut)]
#[case::in_coalesced_data_out(MalformedCase::InWithCoalescedDataOut)]
#[case::out_separate_data_in(MalformedCase::OutWithSeparateDataIn)]
#[case::out_coalesced_data_in(MalformedCase::OutWithCoalescedDataIn)]
#[case::get_id_data_out(MalformedCase::GetIdWithDataOut)]
fn malformed_desc_propagates_error_test(#[case] kind: MalformedCase) {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let regs = virtio_tests::fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &regs[0];
    let host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);

    let disk_file = create_disk_file(4);
    let mut dev = build_block(disk_file.path(), false, "blk-bad");

    let hdr_gpa = DATA_ADDR;
    let extra_gpa = DATA_ADDR + 0x1000;
    let status_gpa = DATA_ADDR + 0x2000;
    // Pre-zero status in guest RAM: a malformed chain must NOT be completed
    // with len == 0 leaving status == Status::OK (0).
    ram.write_t(status_gpa, &Status::OK.raw()).unwrap();

    match kind {
        MalformedCase::EmptyReadable => {
            guest_q.add_desc(&[], &[(status_gpa, 1)]);
        }
        MalformedCase::ShortSplitHeader => {
            guest_q.add_desc(&[(hdr_gpa, 8), (hdr_gpa + 8, 7)], &[(status_gpa, 1)]);
        }
        MalformedCase::EmptyWritable => {
            write_req(&ram, hdr_gpa, RequestType::FLUSH, 0);
            guest_q.add_desc(&[(hdr_gpa, 16)], &[]);
        }
        MalformedCase::InWithSeparateDataOut => {
            write_req(&ram, hdr_gpa, RequestType::IN, 0);
            guest_q.add_desc(
                &[(hdr_gpa, 16), (extra_gpa, 512)],
                &[(extra_gpa + 512, 512), (status_gpa, 1)],
            );
        }
        MalformedCase::InWithCoalescedDataOut => {
            write_req(&ram, hdr_gpa, RequestType::IN, 0);
            guest_q.add_desc(&[(hdr_gpa, 17)], &[(extra_gpa, 512), (status_gpa, 1)]);
        }
        MalformedCase::OutWithSeparateDataIn => {
            write_req(&ram, hdr_gpa, RequestType::OUT, 0);
            guest_q.add_desc(
                &[(hdr_gpa, 16), (extra_gpa, 512)],
                &[(extra_gpa + 512, 512), (status_gpa, 1)],
            );
        }
        MalformedCase::OutWithCoalescedDataIn => {
            write_req(&ram, hdr_gpa, RequestType::OUT, 0);
            guest_q.add_desc(&[(hdr_gpa, 16), (extra_gpa, 512)], &[(status_gpa, 2)]);
        }
        MalformedCase::GetIdWithDataOut => {
            write_req(&ram, hdr_gpa, RequestType::GET_ID, 0);
            guest_q.add_desc(
                &[(hdr_gpa, 16), (extra_gpa, 4)],
                &[(extra_gpa + 512, 20), (status_gpa, 1)],
            );
        }
    }

    let (ret, _host_q) = run_mio_queue(&mut dev, host_q);
    assert_matches!(ret, Err(Error::InvalidBuffer { .. }));
    assert!(guest_q.get_used().is_none());
}

fn setup_worker_queue(
    virtio_dev: &VirtioDevice<TestIrqSender>,
    ram: &Arc<Ram>,
) -> GuestQueue<SplitQueue> {
    let regs = virtio_tests::fixture_queues(1);
    virtio_dev.queue_regs[0]
        .size
        .store(regs[0].size.load(Ordering::Acquire), Ordering::Release);
    virtio_dev.queue_regs[0]
        .desc
        .store(regs[0].desc.load(Ordering::Acquire), Ordering::Release);
    virtio_dev.queue_regs[0]
        .driver
        .store(regs[0].driver.load(Ordering::Acquire), Ordering::Release);
    virtio_dev.queue_regs[0]
        .device
        .store(regs[0].device.load(Ordering::Acquire), Ordering::Release);
    virtio_dev.queue_regs[0]
        .enabled
        .store(true, Ordering::Release);
    GuestQueue::new(
        SplitQueue::new(&virtio_dev.queue_regs[0], ram, false)
            .unwrap()
            .unwrap(),
        &virtio_dev.queue_regs[0],
    )
}

#[test]
fn mio_worker_fails_on_invalid_buffer_test() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let disk_file = create_disk_file(4);
    let block = build_block(disk_file.path(), false, "blk-worker");

    let virtio_dev =
        VirtioDevice::<TestIrqSender>::new("blk-worker", block, ram_bus.clone(), false).unwrap();
    let mut guest_q = setup_worker_queue(&virtio_dev, &ram);

    let (q_tx, _q_rx) = flume::unbounded();
    let (config_tx, config_rx) = flume::unbounded();
    let irq_sender = Arc::new(TestIrqSender { q_tx, config_tx });
    virtio_dev.ctl.wake(WakeEvent::Start {
        param: StartParam {
            feature: VirtioFeature::VERSION_1.bits(),
            irq_sender,
            notifiers: None,
        },
    });

    // Submit a chain with only 8 readable bytes (< 16-byte Request header).
    guest_q.add_desc(&[(DATA_ADDR, 8)], &[(DATA_ADDR + 0x100, 1)]);
    virtio_dev.ctl.wake(WakeEvent::Notify { q_index: 0 });

    assert_eq!(config_rx.recv_timeout(Duration::from_secs(2)), Ok(()));
    assert!(virtio_dev.ctl.failed());
    assert!(guest_q.get_used().is_none());
}

#[test]
fn deferred_complete_io_and_toctou_test() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let regs = virtio_tests::fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &regs[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, _irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let disk_file = create_disk_file(8);
    let dev = build_block(disk_file.path(), false, "blk-deferred");

    let hdr_gpa = DATA_ADDR;
    let buf0_gpa = DATA_ADDR + 0x1000;
    let buf1_gpa = DATA_ADDR + 0x2000;
    let status_gpa = DATA_ADDR + 0x3000;

    // 1. Multi-segment + coalesced IN: verify iovec pointer stability across deferral
    // AND immunity to guest TOCTOU overwriting the Request header in RAM!
    write_req(&ram, hdr_gpa, RequestType::IN, 2);
    ram.write(buf1_gpa, &[0xffu8; 513]).unwrap();
    let in_id = guest_q.add_desc(&[(hdr_gpa, 16)], &[(buf0_gpa, 512), (buf1_gpa, 513)]);

    let mut saved_iov_addr = 0usize;
    let mut saved_iov_len = 0usize;
    host_q
        .handle_desc(0, &irq_sender, |chain| {
            match dev.handle_desc(chain)? {
                BlkRequest::In { data, offset, .. } => {
                    assert_eq!(offset, 2 * SECTOR_SIZE as u64);
                    assert_eq!(data.len(), 2);
                    assert_eq!(data[0].len(), 512);
                    assert_eq!(data[1].len(), 512);
                    saved_iov_addr = data.as_ptr() as usize;
                    saved_iov_len = data.len();
                }
                _ => panic!("expected BlkRequest::In"),
            }
            Ok(QStatus::Deferred)
        })
        .unwrap();

    // Malicious guest overwrites the Request header in RAM while I/O is in flight!
    write_req(&ram, hdr_gpa, RequestType::GET_ID, 0);

    host_q
        .handle_deferred(in_id, 0, &irq_sender, |chain| {
            assert_eq!(chain.writable.as_ptr() as usize, saved_iov_addr);
            assert_eq!(chain.writable.len(), saved_iov_len + 1);
            dev.complete_io(0, chain, 1024)
        })
        .unwrap();
    let used = guest_q.get_used().unwrap();
    assert_eq!((used.id, used.len), (in_id, 1025));
    assert_eq!(ram.read_t::<u8>(buf1_gpa + 512).unwrap(), Status::OK.raw());

    // 2. Short read / EOF (result < expected) returns Status::IOERR and written == 1.
    for short_res in [0, 512, -libc::EIO] {
        write_req(&ram, hdr_gpa, RequestType::IN, 0);
        ram.write_t(status_gpa, &0xffu8).unwrap();
        let id = guest_q.add_desc(
            &[(hdr_gpa, 16)],
            &[(buf0_gpa, 512), (buf1_gpa, 512), (status_gpa, 1)],
        );
        host_q
            .handle_desc(0, &irq_sender, |chain| {
                assert_matches!(dev.handle_desc(chain)?, BlkRequest::In { .. });
                Ok(QStatus::Deferred)
            })
            .unwrap();
        host_q
            .handle_deferred(id, 0, &irq_sender, |chain| {
                dev.complete_io(0, chain, short_res)
            })
            .unwrap();
        let used = guest_q.get_used().unwrap();
        assert_eq!((used.id, used.len), (id, 1));
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::IOERR.raw());
    }

    // 3. Multi-segment OUT: exact write vs short write vs negative errno + TOCTOU.
    for (res, expected_status) in [
        (1024, Status::OK),
        (512, Status::IOERR),
        (-libc::ENOSPC, Status::IOERR),
    ] {
        write_req(&ram, hdr_gpa, RequestType::OUT, 1);
        ram.write_t(status_gpa, &0xffu8).unwrap();
        let id = guest_q.add_desc(
            &[(hdr_gpa, 16), (buf0_gpa, 512), (buf1_gpa, 512)],
            &[(status_gpa, 1)],
        );
        let mut out_addr = 0usize;
        host_q
            .handle_desc(0, &irq_sender, |chain| {
                match dev.handle_desc(chain)? {
                    BlkRequest::Out { data, offset, .. } => {
                        assert_eq!(offset, SECTOR_SIZE as u64);
                        assert_eq!(data.len(), 2);
                        out_addr = data.as_ptr() as usize;
                    }
                    _ => panic!("expected BlkRequest::Out"),
                }
                Ok(QStatus::Deferred)
            })
            .unwrap();
        // Mutate guest header to an unknown opcode while deferred.
        write_req(&ram, hdr_gpa, RequestType(0xdead), 99);
        host_q
            .handle_deferred(id, 0, &irq_sender, |chain| {
                assert_eq!(chain.readable.as_ptr() as usize, out_addr);
                dev.complete_io(0, chain, res)
            })
            .unwrap();
        let used = guest_q.get_used().unwrap();
        assert_eq!((used.id, used.len), (id, 1));
        assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), expected_status.raw());
    }

    // 4. FLUSH completion: success and error, ignoring any data in the request.
    for (res, expected_status) in [(0, Status::OK), (-libc::EIO, Status::IOERR)] {
        for (readable, writable) in [
            (&[(hdr_gpa, 16)][..], &[(status_gpa, 1)][..]),
            (
                &[(hdr_gpa, 16), (buf0_gpa, 512)][..],
                &[(status_gpa, 1)][..],
            ),
            (
                &[(hdr_gpa, 16)][..],
                &[(buf0_gpa, 512), (status_gpa, 1)][..],
            ),
        ] {
            write_req(&ram, hdr_gpa, RequestType::FLUSH, 0);
            ram.write_t(status_gpa, &0xffu8).unwrap();
            let id = guest_q.add_desc(readable, writable);
            host_q
                .handle_desc(0, &irq_sender, |chain| {
                    assert_matches!(dev.handle_desc(chain)?, BlkRequest::Flush { .. });
                    Ok(QStatus::Deferred)
                })
                .unwrap();
            host_q
                .handle_deferred(id, 0, &irq_sender, |chain| dev.complete_io(0, chain, res))
                .unwrap();
            let used = guest_q.get_used().unwrap();
            assert_eq!((used.id, used.len), (id, 1));
            assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), expected_status.raw());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn io_uring_scatter_gather_worker_test() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let disk_file = create_disk_file(8);
    let block = BlkFileSpec {
        path: disk_file.path().into(),
        readonly: false,
        api: WorkerApi::IoUring,
    }
    .build("blk-uring")
    .unwrap();

    let virtio_dev =
        VirtioDevice::<TestIrqSender>::new("blk-uring", block, ram_bus.clone(), false).unwrap();
    let mut guest_q = setup_worker_queue(&virtio_dev, &ram);

    let (q_tx, q_rx) = flume::unbounded();
    let (config_tx, _config_rx) = flume::unbounded();
    let irq_sender = Arc::new(TestIrqSender { q_tx, config_tx });
    virtio_dev.ctl.wake(WakeEvent::Start {
        param: StartParam {
            feature: VirtioFeature::VERSION_1.bits(),
            irq_sender,
            notifiers: None,
        },
    });

    let hdr_gpa = DATA_ADDR;
    let seg0_gpa = DATA_ADDR + 0x1000;
    let seg1_gpa = DATA_ADDR + 0x2000;
    let status_gpa = DATA_ADDR + 0x3000;

    // Multi-segment OUT (coalesced hdr + seg0, plus seg1).
    let data: Vec<u8> = (0..1024).map(|i| (i * 5 + 1) as u8).collect();
    write_req(&ram, hdr_gpa, RequestType::OUT, 1);
    ram.write(hdr_gpa + 16, &data[..512]).unwrap();
    ram.write(seg1_gpa, &data[512..]).unwrap();
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16 + 512), (seg1_gpa, 512)], &[(status_gpa, 1)]);
    virtio_dev.ctl.wake(WakeEvent::Notify { q_index: 0 });
    assert_eq!(q_rx.recv_timeout(Duration::from_secs(2)), Ok(0));
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    // FLUSH.
    write_req(&ram, hdr_gpa, RequestType::FLUSH, 0);
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16)], &[(status_gpa, 1)]);
    virtio_dev.ctl.wake(WakeEvent::Notify { q_index: 0 });
    assert_eq!(q_rx.recv_timeout(Duration::from_secs(2)), Ok(0));
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::OK.raw());

    // Multi-segment + coalesced IN: [512B, 513B (512B + 1B status)].
    let in0_gpa = DATA_ADDR + 0x4000;
    let in1_gpa = DATA_ADDR + 0x5000;
    write_req(&ram, hdr_gpa, RequestType::IN, 1);
    ram.write(in1_gpa, &[0xffu8; 513]).unwrap();
    guest_q.add_desc(&[(hdr_gpa, 16)], &[(in0_gpa, 512), (in1_gpa, 513)]);
    virtio_dev.ctl.wake(WakeEvent::Notify { q_index: 0 });
    assert_eq!(q_rx.recv_timeout(Duration::from_secs(2)), Ok(0));
    assert_eq!(guest_q.get_used().unwrap().len, 1025);
    let mut got = vec![0u8; 1024];
    ram.read(in0_gpa, &mut got[..512]).unwrap();
    ram.read(in1_gpa, &mut got[512..]).unwrap();
    assert_eq!(got, data);
    assert_eq!(ram.read_t::<u8>(in1_gpa + 512).unwrap(), Status::OK.raw());

    // A read beyond the capacity returns Status::IOERR and len == 1.
    write_req(&ram, seg0_gpa, RequestType::IN, 7);
    ram.write_t(status_gpa, &0xffu8).unwrap();
    guest_q.add_desc(
        &[(seg0_gpa, 16)],
        &[(in0_gpa, 512), (in1_gpa, 512), (status_gpa, 1)],
    );
    virtio_dev.ctl.wake(WakeEvent::Notify { q_index: 0 });
    assert_eq!(q_rx.recv_timeout(Duration::from_secs(2)), Ok(0));
    assert_eq!(guest_q.get_used().unwrap().len, 1);
    assert_eq!(ram.read_t::<u8>(status_gpa).unwrap(), Status::IOERR.raw());
}
