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

use std::io::{IoSlice, IoSliceMut, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use assert_matches::assert_matches;
use zerocopy::{FromBytes, IntoBytes};

use crate::mem::LayoutChanged;
use crate::mem::mapped::ArcMemPages;
use crate::sys::vfio::{
    VfioDeviceInfoFlag, VfioIrqInfo, VfioIrqInfoFlag, VfioRegionInfo, VfioRegionInfoFlag,
};
use crate::utils::uds::{recv_msg_with_fds, send_msg_with_fds};
use crate::vfio::Error;
use crate::vfio::device::Device;
use crate::vfio::user::bindings::{
    VfioUserCmd, VfioUserDeviceInfo, VfioUserDmaUnmap, VfioUserHeader, VfioUserHeaderFlag,
    VfioUserMessageType, VfioUserRegionAccess, VfioUserVersion,
};
use crate::vfio::user::conn::VfioUserSession;
use crate::vfio::user::device::{UpdateVfioUserMapping, VfioUserDevice};

fn handle_vfio_user_server(stream: &UnixStream) {
    let dummy_file = tempfile::tempfile().unwrap();
    dummy_file.set_len(0x1000).unwrap();
    let mmap_fd: OwnedFd = dummy_file.into();

    let mut header_buf = [0u8; size_of::<VfioUserHeader>()];
    let mut payload_buf = [0u8; 4096];
    let mut recv_fds = [const { None }; 32];

    loop {
        for fd in &mut recv_fds {
            *fd = None;
        }
        let mut header_slice = [IoSliceMut::new(&mut header_buf)];
        let bytes = match recv_msg_with_fds(stream, &mut header_slice, &mut recv_fds) {
            Ok(0) => break, // EOF
            Ok(b) => b,
            Err(e) => {
                eprintln!("server recv_msg error: {e:?}");
                break;
            }
        };
        if bytes < size_of::<VfioUserHeader>() {
            let mut s = stream;
            if let Err(e) = s.read_exact(&mut header_buf[bytes..]) {
                eprintln!("server read_exact header error: {e:?}");
                break;
            }
        }
        let (req_header, _) = VfioUserHeader::read_from_prefix(&header_buf).unwrap();
        let payload_size = req_header.msg_size as usize - size_of::<VfioUserHeader>();
        if payload_size > 0 {
            let mut s = stream;
            if let Err(e) = s.read_exact(&mut payload_buf[..payload_size]) {
                eprintln!("server read_exact payload error: {e:?}");
                break;
            }
        }

        match req_header.cmd {
            VfioUserCmd::VERSION => {
                let reply_version = VfioUserVersion { major: 0, minor: 2 };
                let cap_str = b"{\"capabilities\":{\"max_msg_fds\":32}}\0";
                let reply_size =
                    size_of::<VfioUserHeader>() + size_of::<VfioUserVersion>() + cap_str.len();
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::VERSION,
                    msg_size: reply_size as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(reply_version.as_bytes()),
                    IoSlice::new(cap_str),
                ];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::DEVICE_GET_INFO => {
                let dev_info = VfioUserDeviceInfo {
                    argsz: size_of::<VfioUserDeviceInfo>() as u32,
                    flags: VfioDeviceInfoFlag::PCI | VfioDeviceInfoFlag::RESET,
                    num_regions: 2,
                    num_irqs: 2,
                };
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DEVICE_GET_INFO,
                    msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserDeviceInfo>())
                        as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(dev_info.as_bytes()),
                ];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::DEVICE_GET_REGION_INFO => {
                let (reg_req, _) = VfioRegionInfo::read_from_prefix(&payload_buf).unwrap();
                let (reg_info, fd_to_send) = if reg_req.index == 0 {
                    (
                        VfioRegionInfo {
                            argsz: size_of::<VfioRegionInfo>() as u32,
                            flags: VfioRegionInfoFlag::READ
                                | VfioRegionInfoFlag::WRITE
                                | VfioRegionInfoFlag::MMAP,
                            index: 0,
                            cap_offset: 0,
                            size: 0x1000,
                            offset: 0,
                        },
                        Some(mmap_fd.as_fd()),
                    )
                } else {
                    (
                        VfioRegionInfo {
                            argsz: size_of::<VfioRegionInfo>() as u32,
                            flags: VfioRegionInfoFlag::READ | VfioRegionInfoFlag::WRITE,
                            index: 1,
                            cap_offset: 0,
                            size: 0x1000,
                            offset: 0,
                        },
                        None,
                    )
                };
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DEVICE_GET_REGION_INFO,
                    msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioRegionInfo>()) as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(reg_info.as_bytes()),
                ];
                if let Some(fd) = fd_to_send {
                    send_msg_with_fds(stream, &slices, &[fd]).unwrap();
                } else {
                    send_msg_with_fds(stream, &slices, &[]).unwrap();
                }
            }
            VfioUserCmd::DEVICE_GET_IRQ_INFO => {
                let (irq_req, _) = VfioIrqInfo::read_from_prefix(&payload_buf).unwrap();
                let irq_info = VfioIrqInfo {
                    argsz: size_of::<VfioIrqInfo>() as u32,
                    flags: VfioIrqInfoFlag::EVENTFD,
                    index: irq_req.index,
                    count: 4,
                };
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DEVICE_GET_IRQ_INFO,
                    msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioIrqInfo>()) as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(irq_info.as_bytes()),
                ];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::DEVICE_RESET => {
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DEVICE_RESET,
                    msg_size: size_of::<VfioUserHeader>() as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [IoSlice::new(reply_hdr.as_bytes())];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::DEVICE_SET_IRQS => {
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DEVICE_SET_IRQS,
                    msg_size: size_of::<VfioUserHeader>() as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [IoSlice::new(reply_hdr.as_bytes())];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::REGION_READ => {
                let (access_req, _) = VfioUserRegionAccess::read_from_prefix(&payload_buf).unwrap();
                let access_resp = VfioUserRegionAccess {
                    offset: access_req.offset,
                    region: access_req.region,
                    count: access_req.count,
                };
                let data = vec![0xaa; access_req.count as usize];
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::REGION_READ,
                    msg_size: (size_of::<VfioUserHeader>()
                        + size_of::<VfioUserRegionAccess>()
                        + data.len()) as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(access_resp.as_bytes()),
                    IoSlice::new(&data),
                ];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::REGION_WRITE => {
                let (access_req, _) = VfioUserRegionAccess::read_from_prefix(&payload_buf).unwrap();
                let access_resp = VfioUserRegionAccess {
                    offset: access_req.offset,
                    region: access_req.region,
                    count: access_req.count,
                };
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::REGION_WRITE,
                    msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserRegionAccess>())
                        as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(access_resp.as_bytes()),
                ];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::DMA_MAP => {
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DMA_MAP,
                    msg_size: size_of::<VfioUserHeader>() as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [IoSlice::new(reply_hdr.as_bytes())];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            VfioUserCmd::DMA_UNMAP => {
                let (unmap_req, _) = VfioUserDmaUnmap::read_from_prefix(&payload_buf).unwrap();
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: VfioUserCmd::DMA_UNMAP,
                    msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserDmaUnmap>()) as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
                    error_no: 0,
                };
                let slices = [
                    IoSlice::new(reply_hdr.as_bytes()),
                    IoSlice::new(unmap_req.as_bytes()),
                ];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
            _ => {
                let reply_hdr = VfioUserHeader {
                    msg_id: req_header.msg_id,
                    cmd: req_header.cmd,
                    msg_size: size_of::<VfioUserHeader>() as u32,
                    flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, true),
                    error_no: libc::ENOSYS as u32,
                };
                let slices = [IoSlice::new(reply_hdr.as_bytes())];
                send_msg_with_fds(stream, &slices, &[]).unwrap();
            }
        }
    }
}

#[test]
fn test_vfio_user_device_full_lifecycle() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        handle_vfio_user_server(&server);
    });

    let session = Arc::new(VfioUserSession::new(client));
    let dev = VfioUserDevice::new(session.clone()).unwrap();

    // 1. Test get_info
    let info = dev.get_info().unwrap();
    assert_eq!(info.num_regions, 2);
    assert_eq!(info.num_irqs, 2);

    // 2. Test get_region_info
    let reg0 = dev.get_region_info(0).unwrap();
    assert_eq!(reg0.size, 0x1000);
    assert!(reg0.flags.contains(VfioRegionInfoFlag::MMAP));

    let reg1 = dev.get_region_info(1).unwrap();
    assert_eq!(reg1.size, 0x1000);
    assert!(!reg1.flags.contains(VfioRegionInfoFlag::MMAP));

    // 3. Test get_region_mmap
    let mmap0 = dev.get_region_mmap_fd(0).unwrap();
    assert!(mmap0.is_some());
    let mmap1 = dev.get_region_mmap_fd(1).unwrap();
    assert!(mmap1.is_none());

    // 4. Test get_irq_info
    let irq_info = dev.get_irq_info(0).unwrap();
    assert_eq!(irq_info.count, 4);

    // 5. Test read_region and write_region
    let mut read_buf = [0u8; 16];
    dev.read_region(&reg0, 0, &mut read_buf).unwrap();
    assert_eq!(read_buf, [0xaa; 16]);

    let write_buf = [0x55; 16];
    dev.write_region(&reg0, 0, &write_buf).unwrap();

    // 6. Test set_irq_eventfd and disable_irq
    let eventfd_file = tempfile::tempfile().unwrap();
    let eventfd_borrowed = eventfd_file.as_fd();
    dev.set_irq_eventfd(0, 0, &[Some(eventfd_borrowed)])
        .unwrap();
    dev.disable_irq(0).unwrap();

    // 7. Test reset
    dev.reset().unwrap();

    // 8. Test get_dma_buf_fd (unsupported)
    assert_matches!(dev.get_dma_buf_fd(0, 0, 0x1000), Err(_));

    // 9. Test DMA mapping and UpdateVfioUserMapping
    let arc_anon = ArcMemPages::from_memfd(c"test_mem", 0x2000, None).unwrap();

    let updater = UpdateVfioUserMapping::new(session.clone());
    // RAM add / remove
    assert_matches!(updater.ram_added(0x1000_0000, &arc_anon), Ok(()));
    assert_matches!(updater.ram_removed(0x1000_0000, &arc_anon), Ok(()));

    // Dev mem add / remove
    assert_matches!(updater.dev_mem_added(0x2000_0000, &arc_anon, None), Ok(()));
    assert_matches!(
        updater.dev_mem_removed(0x2000_0000, &arc_anon, None),
        Ok(())
    );

    drop(updater);
    drop(dev);
    drop(session);
    server_handle.join().unwrap();
}

#[test]
fn test_vfio_user_version_server_mismatch() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        let mut header_buf = [0u8; size_of::<VfioUserHeader>()];
        let mut recv_fds = [const { None }; 32];
        let mut header_slice = [IoSliceMut::new(&mut header_buf)];
        recv_msg_with_fds(&server, &mut header_slice, &mut recv_fds).unwrap();
        let (req_header, _) = VfioUserHeader::read_from_prefix(&header_buf).unwrap();

        // Server sends major version 1 (mismatch)
        let reply_version = VfioUserVersion { major: 1, minor: 0 };
        let reply_hdr = VfioUserHeader {
            msg_id: req_header.msg_id,
            cmd: VfioUserCmd::VERSION,
            msg_size: (size_of::<VfioUserHeader>() + size_of::<VfioUserVersion>()) as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, false),
            error_no: 0,
        };
        let slices = [
            IoSlice::new(reply_hdr.as_bytes()),
            IoSlice::new(reply_version.as_bytes()),
        ];
        send_msg_with_fds(&server, &slices, &[]).unwrap();
    });

    let session = VfioUserSession::new(client);
    let res = session.negotiate_version();
    assert_matches!(res, Err(Error::VfioUser { .. }));

    server_handle.join().unwrap();
}

#[test]
fn test_vfio_user_server_error_response() {
    let (client, server) = UnixStream::pair().unwrap();
    let server_handle = thread::spawn(move || {
        let mut header_buf = [0u8; size_of::<VfioUserHeader>()];
        let mut recv_fds = [const { None }; 32];
        let mut header_slice = [IoSliceMut::new(&mut header_buf)];
        recv_msg_with_fds(&server, &mut header_slice, &mut recv_fds).unwrap();
        let (req_header, _) = VfioUserHeader::read_from_prefix(&header_buf).unwrap();

        // Server replies with ERROR flag and EINVAL
        let reply_hdr = VfioUserHeader {
            msg_id: req_header.msg_id,
            cmd: req_header.cmd,
            msg_size: size_of::<VfioUserHeader>() as u32,
            flags: VfioUserHeaderFlag::new(VfioUserMessageType::REPLY, false, true),
            error_no: libc::EINVAL as u32,
        };
        let slices = [IoSlice::new(reply_hdr.as_bytes())];
        send_msg_with_fds(&server, &slices, &[]).unwrap();
    });

    let session = VfioUserSession::new(client);
    let mut resp_buf = [0u8; 64];
    let mut resp_fds = [const { None }; 32];
    let res = session.transact(VfioUserCmd::VERSION, &[], &[], &mut resp_buf, &mut resp_fds);
    assert_matches!(res, Err(Error::System { .. }));

    server_handle.join().unwrap();
}
