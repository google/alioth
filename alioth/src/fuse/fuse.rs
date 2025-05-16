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
use std::fmt::Debug;
use std::fs::File;
use std::io::{Error as IoError, IoSlice, IoSliceMut};

use macros::trace_error;
use snafu::Snafu;

use crate::errors::DebugTrace;

use self::bindings::{
    FuseAttrOut, FuseCreateIn, FuseCreateOut, FuseEntryOut, FuseFlushIn, FuseForgetIn,
    FuseGetattrIn, FuseInHeader, FuseInitIn, FuseInitOut, FuseIoctlIn, FuseIoctlOut, FuseOpcode,
    FuseOpenIn, FuseOpenOut, FusePollIn, FusePollOut, FuseReadIn, FuseReleaseIn, FuseRename2In,
    FuseRenameIn, FuseSetupmappingFlag, FuseSetupmappingIn, FuseSyncfsIn, FuseWriteIn,
    FuseWriteOut,
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
    #[snafu(display("Invalid file handle"))]
    InvalidFileHandle,
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
            Error::InvalidFileHandle { .. } => libc::EBADF,
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
    ($name:ident, & $in_ty:ty, & $in_buf:ty, $out_ty:ty) => {
        fn $name(&mut self, hdr: &FuseInHeader, in_: &$in_ty, _buf: &$in_buf) -> Result<$out_ty> {
            fuse_no_impl!(hdr, in_)
        }
    };
    ($name:ident, & $in_ty:ty, &mut $out_buf:ty) => {
        fn $name(
            &mut self,
            hdr: &FuseInHeader,
            in_: &$in_ty,
            _buf: &mut $out_buf,
        ) -> Result<usize> {
            fuse_no_impl!(hdr, in_)
        }
    };
    ($name:ident, & $in_ty:ty, $out_ty:ty) => {
        fn $name(&mut self, hdr: &FuseInHeader, in_: &$in_ty) -> Result<$out_ty> {
            fuse_no_impl!(hdr, in_)
        }
    };
}

pub trait DaxRegion: Debug + Send + Sync + 'static {
    fn map(
        &self,
        m_offset: u64,
        fd: &File,
        f_offset: u64,
        len: u64,
        flag: FuseSetupmappingFlag,
    ) -> Result<()>;

    fn unmap(&self, m_offset: u64, len: u64) -> Result<()>;
}

pub trait Fuse {
    fuse_method!(init, &FuseInitIn, FuseInitOut);
    fuse_method!(get_attr, &FuseGetattrIn, FuseAttrOut);
    fuse_method!(open, &FuseOpenIn, FuseOpenOut);
    fuse_method!(open_dir, &FuseOpenIn, FuseOpenOut);
    fuse_method!(read_dir, &FuseReadIn, &mut [u8]);
    fuse_method!(release_dir, &FuseReleaseIn, ());
    fuse_method!(lookup, &[u8], FuseEntryOut);
    fuse_method!(forget, &FuseForgetIn, ());
    fuse_method!(read, &FuseReadIn, &mut [IoSliceMut]);
    fuse_method!(poll, &FusePollIn, FusePollOut);
    fuse_method!(flush, &FuseFlushIn, ());
    fuse_method!(release, &FuseReleaseIn, ());
    fuse_method!(syncfs, &FuseSyncfsIn, ());
    fuse_method!(ioctl, &FuseIoctlIn, FuseIoctlOut);
    fuse_method!(get_xattr, &[u8], &mut [u8]);
    fuse_method!(set_xattr, &[u8], ());
    fuse_method!(create, &FuseCreateIn, &[u8], FuseCreateOut);
    fuse_method!(write, &FuseWriteIn, &[IoSlice], FuseWriteOut);
    fuse_method!(unlink, &[u8], ());
    fuse_method!(rmdir, &[u8], ());
    fuse_method!(rename, &FuseRenameIn, &[u8], ());
    fuse_method!(rename2, &FuseRename2In, &[u8], ());
    fuse_method!(setup_mapping, &FuseSetupmappingIn, ());
    fuse_method!(remove_mapping, &[u8], ());
    fn set_dax_region(&mut self, dax_region: Box<dyn DaxRegion>);
}
