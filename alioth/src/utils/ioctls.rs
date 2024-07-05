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

const IOC_NONN: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const IOC_NRSHIFT: usize = 0;
const IOC_TYPESHIFT: usize = 8;
const IOC_SIZESHIFT: usize = 16;
const IOC_DIRSHIFT: usize = 30;

const fn ioctl_ioc(dir: u32, type_: u8, nr: u8, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT)
        | (size << IOC_SIZESHIFT)
        | ((type_ as u32) << IOC_TYPESHIFT)
        | ((nr as u32) << IOC_NRSHIFT)
}

pub const fn ioctl_io(type_: u8, nr: u8) -> u32 {
    ioctl_ioc(IOC_NONN, type_, nr, 0)
}

pub const fn ioctl_ior<T>(type_: u8, nr: u8) -> u32 {
    ioctl_ioc(IOC_READ, type_, nr, size_of::<T>() as u32)
}

pub const fn ioctl_iow<T>(type_: u8, nr: u8) -> u32 {
    ioctl_ioc(IOC_WRITE, type_, nr, size_of::<T>() as u32)
}

pub const fn ioctl_iowr<T>(type_: u8, nr: u8) -> u32 {
    ioctl_ioc(IOC_WRITE | IOC_READ, type_, nr, size_of::<T>() as u32)
}

#[macro_export]
macro_rules! ioctl_none {
    ($name:ident, $type_:expr, $nr:expr, $val:expr) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(fd: &F) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_io($type_, $nr) as _,
                $val as ::libc::c_ulong,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_write_val {
    ($name:ident, $code:expr) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: ::libc::c_ulong,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code as _, val))
        }
    };
    ($name:ident, $code:expr, $ty:ty) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: $ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code as _, val))
        }
    };
}

#[macro_export]
macro_rules! ioctl_write_ptr {
    ($name:ident, $code:expr, $ty:ty) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: &$ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code as _, val as *const $ty))
        }
    };

    ($name:ident, $type_:expr, $nr:expr, $ty:ty) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: &$ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iow::<$ty>($type_, $nr) as _,
                val as *const $ty,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_write_buf {
    ($name:ident, $type_:expr, $nr:expr, $ty:ident) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd, const N: usize>(
            fd: &F,
            val: &$ty<N>,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iow::<$ty<0>>($type_, $nr) as _,
                val as *const $ty<N>,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_writeread {
    ($name:ident, $type_:expr, $nr:expr, $ty:ty) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(
            fd: &F,
            val: &mut $ty,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iowr::<$ty>($type_, $nr) as _,
                val as *mut $ty,
            ))
        }
    };
    ($name:ident, $code:expr) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd, T>(
            fd: &F,
            val: &mut T,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code as _, val as *mut T))
        }
    };
}

#[macro_export]
macro_rules! ioctl_writeread_buf {
    ($name:ident, $type_:expr, $nr:expr, $ty:ident) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd, const N: usize>(
            fd: &F,
            val: &mut $ty<N>,
        ) -> ::std::io::Result<libc::c_int> {
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_iowr::<$ty<0>>($type_, $nr) as _,
                val as *mut $ty<N>,
            ))
        }
    };
}

#[macro_export]
macro_rules! ioctl_read {
    ($name:ident, $code:expr, $ty:ty) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(fd: &F) -> ::std::io::Result<$ty> {
            let mut val = ::core::mem::MaybeUninit::<$ty>::uninit();
            $crate::ffi!(::libc::ioctl(fd.as_raw_fd(), $code as _, val.as_mut_ptr()))?;
            ::std::io::Result::Ok(val.assume_init())
        }
    };
    ($name:ident, $type_:expr, $nr:expr, $ty:ty) => {
        #[allow(clippy::missing_safety_doc)]
        pub unsafe fn $name<F: ::std::os::fd::AsRawFd>(fd: &F) -> ::std::io::Result<$ty> {
            let mut val = ::core::mem::MaybeUninit::<$ty>::uninit();
            $crate::ffi!(::libc::ioctl(
                fd.as_raw_fd(),
                $crate::utils::ioctls::ioctl_ior::<$ty>($type_, $nr) as _,
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
