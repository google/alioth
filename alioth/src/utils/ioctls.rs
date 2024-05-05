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

use std::mem::size_of;

use libc::c_ulong;

const IOC_NONN: c_ulong = 0;
const IOC_WRITE: c_ulong = 1;
const IOC_READ: c_ulong = 2;

const IOC_NRSHIFT: usize = 0;
const IOC_TYPESHIFT: usize = 8;
const IOC_SIZESHIFT: usize = 16;
const IOC_DIRSHIFT: usize = 30;

const fn ioctl_ioc(dir: c_ulong, type_: u8, nr: u8, size: c_ulong) -> c_ulong {
    (dir << IOC_DIRSHIFT)
        | (size << IOC_SIZESHIFT)
        | ((type_ as c_ulong) << IOC_TYPESHIFT)
        | ((nr as c_ulong) << IOC_NRSHIFT)
}

pub const fn ioctl_io(type_: u8, nr: u8) -> c_ulong {
    ioctl_ioc(IOC_NONN, type_, nr, 0)
}

pub const fn ioctl_ior<T>(type_: u8, nr: u8) -> c_ulong {
    ioctl_ioc(IOC_READ, type_, nr, size_of::<T>() as c_ulong)
}

pub const fn ioctl_iow<T>(type_: u8, nr: u8) -> c_ulong {
    ioctl_ioc(IOC_WRITE, type_, nr, size_of::<T>() as c_ulong)
}

pub const fn ioctl_iowr<T>(type_: u8, nr: u8) -> c_ulong {
    ioctl_ioc(IOC_WRITE | IOC_READ, type_, nr, size_of::<T>() as c_ulong)
}

#[macro_export]
macro_rules! ioctl_none {
    ($name:ident, $type_:expr, $nr:expr, $val:expr) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(fd: &F) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_io($type_, $nr),
                $val as ::libc::c_ulong,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_write_val {
    ($name:ident, $code:expr) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: ::libc::c_ulong,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code, val))
        }
    };
    ($name:ident, $code:expr, $ty:ty) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: $ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code, val))
        }
    };
}

#[macro_export]
macro_rules! ioctl_write_ptr {
    ($name:ident, $code:expr, $ty:ty) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: &$ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code, val as *const $ty))
        }
    };

    ($name:ident, $type_:expr, $nr:expr, $ty:ty) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: &$ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iow::<$ty>($type_, $nr),
                val as *const $ty,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_write_buf {
    ($name:ident, $type_:expr, $nr:expr, $ty:ident) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd, const N: usize>(
            fd: &F,
            val: &$ty<N>,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iow::<$ty<0>>($type_, $nr),
                val as *const $ty<N>,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_writeread {
    ($name:ident, $type_:expr, $nr:expr, $ty:ty) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: &mut $ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iowr::<$ty>($type_, $nr),
                val as *mut $ty,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_writeread_buf {
    ($name:ident, $type_:expr, $nr:expr, $ty:ident) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd, const N: usize>(
            fd: &F,
            val: &mut $ty<N>,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iowr::<$ty<0>>($type_, $nr),
                val as *mut $ty<N>,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_read {
    ($name:ident, $code:expr, $ty:ty) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(fd: &F) -> ::std::io::Result<$ty> {
            let mut val = ::core::mem::MaybeUninit::<$ty>::uninit();
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code, val.as_mut_ptr()))?;
            ::std::io::Result::Ok(val.assume_init())
        }
    };
    ($name:ident, $type_:expr, $nr:expr, $ty:ty) => {
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(fd: &F) -> ::std::io::Result<$ty> {
            let mut val = ::core::mem::MaybeUninit::<$ty>::uninit();
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_ior::<$ty>($type_, $nr),
                val.as_mut_ptr()
            ))?;
            ::std::io::Result::Ok(val.assume_init())
        }
    };
}

#[cfg(test)]
mod test {
    use crate::utils::ioctls::{ioctl_io, ioctl_ior, ioctl_iow, ioctl_iowr};

    #[test]
    fn test_codes() {
        const KVMIO: u8 = 0xAE;
        assert_eq!(ioctl_io(KVMIO, 0x01), 0xae01);
        assert_eq!(ioctl_ior::<[u8; 320]>(KVMIO, 0xcc), 0x8140aecc);
        assert_eq!(ioctl_iow::<[u8; 320]>(KVMIO, 0xcd), 0x4140aecd);
        assert_eq!(ioctl_iowr::<[u8; 8]>(KVMIO, 0x05), 0xc008ae05);
    }
}
