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
use mio::Registry;
use mio::unix::SourceFd;
use vmm_io::host::{Interest, Tap, Token};
use vmm_io::virtio::dev::net::NetFeature;

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
    registry: Registry,
}

impl HostTap {
    pub fn new(if_name: Option<&str>, registry: Registry) -> io::Result<Self> {
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
            registry,
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

    fn register(&self, token: Token, interests: Interest) -> io::Result<()> {
        let mut mio_interest = None;
        if interests.contains(Interest::READABLE) {
            mio_interest = Some(mio::Interest::READABLE);
        }
        if interests.contains(Interest::WRITABLE) {
            mio_interest = Some(match mio_interest {
                Some(i) => i | mio::Interest::WRITABLE,
                None => mio::Interest::WRITABLE,
            });
        }
        let Some(mio_interest) = mio_interest else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty Interest"));
        };
        self.registry.register(
            &mut SourceFd(&self.file.as_raw_fd()),
            mio::Token(token.0 as usize),
            mio_interest,
        )
    }

    fn deregister(&self) {
        let _ = self
            .registry
            .deregister(&mut SourceFd(&self.file.as_raw_fd()));
    }

    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&self.file).read_vectored(bufs)
    }

    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&self.file).write_vectored(bufs)
    }
}

fn parse_if_name_and_cidr(spec: &str) -> io::Result<(&str, Option<(std::net::Ipv4Addr, u8)>)> {
    let Some((name, cidr)) = spec.split_once(':') else {
        return Ok((spec, None));
    };
    let (ip_str, prefix_str) = cidr.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TAP CIDR '{cidr}' in '{spec}' (expected <ifname>:<ipv4>/<prefix>)"),
        )
    })?;
    let ip: std::net::Ipv4Addr = ip_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TAP IPv4 '{ip_str}': {e}"),
        )
    })?;
    let prefix: u8 = prefix_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TAP prefix '{prefix_str}': {e}"),
        )
    })?;
    if prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TAP prefix {prefix} > 32"),
        ));
    }
    Ok((name, Some((ip, prefix))))
}

fn make_sockaddr_in(ip: u32) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: ip.to_be() },
        sin_zero: [0; 8],
    };
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
}

fn configure_tap_ipv4(dev_name: &str, ip: std::net::Ipv4Addr, prefix: u8) -> io::Result<()> {
    const SIOCGIFFLAGS: libc::Ioctl = 0x8913;
    const SIOCSIFFLAGS: libc::Ioctl = 0x8914;
    const SIOCSIFADDR: libc::Ioctl = 0x8916;
    const SIOCSIFNETMASK: libc::Ioctl = 0x891c;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    struct SockGuard(c_int);
    impl Drop for SockGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::close(self.0);
            }
        }
    }
    let _guard = SockGuard(sock);

    let make_req = || {
        let mut req = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };
        for (s, d) in zip(dev_name.as_bytes(), req.ifr_name.as_mut()) {
            *d = *s as _;
        }
        req
    };

    let mut addr_req = make_req();
    addr_req.ifr_ifru.ifru_addr = make_sockaddr_in(u32::from(ip));
    if unsafe { libc::ioctl(sock, SIOCSIFADDR, &addr_req) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let mut mask_req = make_req();
    mask_req.ifr_ifru.ifru_addr = make_sockaddr_in(mask);
    if unsafe { libc::ioctl(sock, SIOCSIFNETMASK, &mask_req) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut flags_req = make_req();
    if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &flags_req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        flags_req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
    }
    if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &flags_req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn setup_tap(file: &mut File, if_name: Option<&str>) -> io::Result<()> {
    let parsed = match if_name {
        Some(spec) => Some(parse_if_name_and_cidr(spec)?),
        None => None,
    };
    let mut tap_ifconfig = match parsed {
        None => unsafe { tun_get_iff(file) }?,
        Some((name, _)) => {
            let mut tap_ifconfig = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };
            for (s, d) in zip(name.as_bytes(), tap_ifconfig.ifr_name.as_mut()) {
                *d = *s as _;
            }
            tap_ifconfig
        }
    };

    tap_ifconfig.ifr_ifru.ifru_flags = (IFF_TAP | IFF_NO_PI | IFF_VNET_HDR) as i16;
    unsafe { tun_set_iff(file, &tap_ifconfig) }?;
    unsafe { tun_set_vnet_hdr_sz(file, &VNET_HEADER_SIZE) }?;

    if let Some((name, Some((ip, prefix)))) = parsed {
        configure_tap_ipv4(name, ip, prefix)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_if_name_and_cidr() {
        let (name, cidr) = parse_if_name_and_cidr("puff-tap").unwrap();
        assert_eq!(name, "puff-tap");
        assert!(cidr.is_none());

        let (name, cidr) = parse_if_name_and_cidr("tap0:192.168.5.1/24").unwrap();
        assert_eq!(name, "tap0");
        assert_eq!(
            cidr,
            Some((std::net::Ipv4Addr::new(192, 168, 5, 1), 24))
        );

        assert!(parse_if_name_and_cidr("tap0:192.168.5.1").is_err());
        assert!(parse_if_name_and_cidr("tap0:192.168.5.1/33").is_err());
    }
}
