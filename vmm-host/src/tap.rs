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

use std::fs::{self, File};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::iter::zip;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::prelude::OpenOptionsExt;

use bitflags::bitflags;
use libc::{IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, O_NONBLOCK, c_int, c_uint, c_ulong, ifreq};
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use vmm_runner::host::Tap;
use vmm_runner::virtio::dev::net::NetFeature;

use crate::ioctls::{ioctl_ior, ioctl_iow};
use crate::{ioctl_read, ioctl_write_ptr, ioctl_write_val};

ioctl_write_ptr!(tun_set_iff, ioctl_iow::<c_int>(b'T', 202), ifreq);

ioctl_write_val!(tun_set_offload, ioctl_iow::<c_uint>(b'T', 208));

ioctl_read!(tun_get_iff, ioctl_ior::<c_uint>(b'T', 210), ifreq);

ioctl_read!(tun_get_vnet_hdr_sz, b'T', 215, c_int);

ioctl_write_ptr!(tun_set_vnet_hdr_sz, b'T', 216, c_int);

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TunFeature: c_ulong {
        const CSUM = 0x01;
        const TSO4 = 0x02;
        const TSO6 = 0x04;
        const TSO_ECN = 0x08;
        const UFO = 0x10;
        const USO4 = 0x20;
        const USO6 = 0x40;
    }
}

const VNET_HEADER_SIZE: i32 = 12;

#[derive(Debug)]
pub struct HostTap {
    file: File,
    detected_offload: NetFeature,
}

impl HostTap {
    pub fn new(if_name: Option<&str>) -> io::Result<Self> {
        let mut file = fs::OpenOptions::new()
            .custom_flags(O_NONBLOCK)
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let detected_offload = detect_tap_offload(&file);
        setup_tap(&mut file, if_name)?;

        Ok(HostTap {
            file,
            detected_offload,
        })
    }
}

impl Tap for HostTap {
    fn detected_offload(&self) -> NetFeature {
        self.detected_offload
    }

    fn enable_offload(&mut self, feature: NetFeature) -> io::Result<()> {
        enable_tap_offload(&mut self.file, feature)?;
        Ok(())
    }

    fn register(&self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        registry.register(&mut SourceFd(&self.file.as_raw_fd()), token, interests)
    }

    fn deregister(&self, registry: &Registry) {
        let _ = registry.deregister(&mut SourceFd(&self.file.as_raw_fd()));
    }

    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&self.file).read_vectored(bufs)
    }

    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&self.file).write_vectored(bufs)
    }
}

fn setup_tap(file: &mut File, if_name: Option<&str>) -> io::Result<()> {
    let mut tap_ifconfig = match if_name {
        None => unsafe { tun_get_iff(file) }?,
        Some(name) => {
            let mut tap_ifconfig = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };
            for (s, d) in zip(name.as_bytes(), tap_ifconfig.ifr_name.as_mut()) {
                *d = *s as i8;
            }
            tap_ifconfig
        }
    };

    tap_ifconfig.ifr_ifru.ifru_flags = (IFF_TAP | IFF_NO_PI | IFF_VNET_HDR) as i16;
    unsafe { tun_set_iff(file, &tap_ifconfig) }?;
    unsafe { tun_set_vnet_hdr_sz(file, &VNET_HEADER_SIZE) }?;
    Ok(())
}

fn detect_tap_offload(tap: &impl AsRawFd) -> NetFeature {
    let mut tap_feature = TunFeature::all();
    let mut dev_feat = NetFeature::GUEST_CSUM
        | NetFeature::GUEST_TSO4
        | NetFeature::GUEST_TSO6
        | NetFeature::GUEST_ECN
        | NetFeature::GUEST_UFO
        | NetFeature::GUEST_USO4
        | NetFeature::GUEST_USO6;
    if unsafe { tun_set_offload(tap, tap_feature.bits()) }.is_ok() {
        return dev_feat;
    }
    tap_feature &= !(TunFeature::USO4 | TunFeature::USO6);
    dev_feat &= !(NetFeature::GUEST_USO4 | NetFeature::GUEST_USO6);
    if unsafe { tun_set_offload(tap, tap_feature.bits()) }.is_ok() {
        return dev_feat;
    }
    tap_feature &= !(TunFeature::UFO);
    dev_feat &= !NetFeature::GUEST_UFO;
    if unsafe { tun_set_offload(tap, tap_feature.bits()) }.is_ok() {
        return dev_feat;
    }
    NetFeature::empty()
}

fn enable_tap_offload(tap: &mut File, feature: NetFeature) -> io::Result<i32> {
    let mut tap_feature = TunFeature::empty();
    if feature.contains(NetFeature::GUEST_CSUM) {
        tap_feature |= TunFeature::CSUM;
    }
    if feature.contains(NetFeature::GUEST_TSO4) {
        tap_feature |= TunFeature::TSO4;
    }
    if feature.contains(NetFeature::GUEST_TSO6) {
        tap_feature |= TunFeature::TSO6;
    }
    if feature.contains(NetFeature::GUEST_ECN) {
        tap_feature |= TunFeature::TSO_ECN;
    }
    if feature.contains(NetFeature::GUEST_UFO) {
        tap_feature |= TunFeature::UFO;
    }
    if feature.contains(NetFeature::GUEST_USO4) {
        tap_feature |= TunFeature::USO4;
    }
    if feature.contains(NetFeature::GUEST_USO6) {
        tap_feature |= TunFeature::USO6;
    }
    unsafe { tun_set_offload(tap, tap_feature.bits()) }
}
