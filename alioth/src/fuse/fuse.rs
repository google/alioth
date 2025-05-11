// Copyright 2025 Google LLC
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

pub mod bindings;
pub mod passthrough;

use std::ffi::FromBytesUntilNulError;
use std::io::{Error as IoError, IoSliceMut};

use macros::trace_error;
use snafu::Snafu;

use crate::errors::DebugTrace;

use self::bindings::{
    FuseAttrOut, FuseEntryOut, FuseFlushIn, FuseForgetIn, FuseGetattrIn, FuseInHeader, FuseInitIn,
    FuseInitOut, FuseIoctlIn, FuseIoctlOut, FuseOpcode, FuseOpenIn, FuseOpenOut, FusePollIn,
    FusePollOut, FuseReadIn, FuseReleaseIn, FuseSyncfsIn,
};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Node id {id:#x} does not exist"))]
    NodeId { id: u64 },
    #[snafu(display("Invalid C String "), context(false))]
    InvalidCString { error: FromBytesUntilNulError },
    #[snafu(display("Unsupported flag {flag:#x} of {op:?}"))]
    Unsupported { op: FuseOpcode, flag: u32 },
    #[snafu(display("Directory was not opened"))]
    DirNotOpened,
    #[snafu(display("Invalid access mode {mode:#x}"))]
    InvalidAccMode { mode: i32 },
    #[snafu(display("File was not opened"))]
    FileNotOpened,
}

impl From<&IoError> for Error {
    fn from(e: &IoError) -> Self {
        let code = e.raw_os_error().unwrap_or(libc::EINVAL);
        IoError::from_raw_os_error(code).into()
    }
}

impl Error {
    pub fn error_code(&self) -> i32 {
        match self {
            Error::System { error, .. } => error.raw_os_error().unwrap_or(libc::EINVAL),
            Error::NodeId { .. } => libc::ENOENT,
            Error::InvalidCString { .. } => libc::EINVAL,
            Error::Unsupported { .. } => libc::EOPNOTSUPP,
            Error::DirNotOpened { .. } => libc::EBADF,
            Error::InvalidAccMode { .. } => libc::EINVAL,
            Error::FileNotOpened { .. } => libc::EBADF,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

macro_rules! fuse_no_impl {
    ($hdr:expr, $in_:expr) => {{
        log::debug!("unimplemented: hdr: {:?}, in: {:?}", $hdr, $in_);
        let err: IoError = IoError::from_raw_os_error(libc::ENOSYS);
        Err(Error::from(err))
    }};
}

macro_rules! fuse_method {
    ($name:ident, $in_ty:ty,[]) => {
        fn $name(&mut self, hdr: &FuseInHeader, in_: &$in_ty, _buf: &mut [u8]) -> Result<usize> {
            fuse_no_impl!(hdr, in_)
        }
    };
    ($name:ident, $in_ty:ty,[[]]) => {
        fn $name(
            &mut self,
            hdr: &FuseInHeader,
            in_: &$in_ty,
            _iov: &mut [IoSliceMut],
        ) -> Result<usize> {
            fuse_no_impl!(hdr, in_)
        }
    };
    ($name:ident, $in_ty:ty, $out_ty:ty) => {
        fn $name(&mut self, hdr: &FuseInHeader, in_: &$in_ty) -> Result<$out_ty> {
            fuse_no_impl!(hdr, in_)
        }
    };
}

pub trait Fuse {
    fuse_method!(init, FuseInitIn, FuseInitOut);
    fuse_method!(get_attr, FuseGetattrIn, FuseAttrOut);
    fuse_method!(open, FuseOpenIn, FuseOpenOut);
    fuse_method!(open_dir, FuseOpenIn, FuseOpenOut);
    fuse_method!(read_dir, FuseReadIn, []);
    fuse_method!(release_dir, FuseReleaseIn, ());
    fuse_method!(lookup, [u8], FuseEntryOut);
    fuse_method!(forget, FuseForgetIn, ());
    fuse_method!(read, FuseReadIn, [[]]);
    fuse_method!(poll, FusePollIn, FusePollOut);
    fuse_method!(flush, FuseFlushIn, ());
    fuse_method!(release, FuseReleaseIn, ());
    fuse_method!(syncfs, FuseSyncfsIn, ());
    fuse_method!(ioctl, FuseIoctlIn, FuseIoctlOut);
    fuse_method!(get_xattr, [u8], []);
    fuse_method!(set_xattr, [u8], ());
}
