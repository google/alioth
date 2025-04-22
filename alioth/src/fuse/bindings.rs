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

use std::marker::PhantomData;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::c_enum;

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 43;
pub const FUSE_ROOT_ID: u64 = 1;
pub const FUSE_UNIQUE_RESEND: u64 = 1 << 63;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FAttrFlag: u32 {
        const MODE = 1 << 0;
        const UID = 1 << 1;
        const GID = 1 << 2;
        const SIZE = 1 << 3;
        const ATIME = 1 << 4;
        const MTIME = 1 << 5;
        const FH = 1 << 6;
        const ATIME_NOW = 1 << 7;
        const MTIME_NOW = 1 << 8;
        const LOCKOWNER = 1 << 9;
        const CTIME = 1 << 10;
        const KILL_SUIDGID = 1 << 11;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FOpenFlag: u32 {
        const DIRECT_IO = 1 << 0;
        const KEEP_CACHE = 1 << 1;
        const NONSEEKABLE = 1 << 2;
        const CACHE_DIR = 1 << 3;
        const STREAM = 1 << 4;
        const NOFLUSH = 1 << 5;
        const PARALLEL_DIRECT_WRITES = 1 << 6;
        const PASSTHROUGH = 1 << 7;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseInitFlag: u32 {
        const ASYNC_READ = 1 << 0;
        const POSIX_LOCKS = 1 << 1;
        const FILE_OPS = 1 << 2;
        const ATOMIC_O_TRUNC = 1 << 3;
        const EXPORT_SUPPORT = 1 << 4;
        const BIG_WRITES = 1 << 5;
        const DONT_MASK = 1 << 6;
        const SPLICE_WRITE = 1 << 7;
        const SPLICE_MOVE = 1 << 8;
        const SPLICE_READ = 1 << 9;
        const FLOCK_LOCKS = 1 << 10;
        const HAS_IOCTL_DIR = 1 << 11;
        const AUTO_INVAL_DATA = 1 << 12;
        const DO_READDIRPLUS = 1 << 13;
        const READDIRPLUS_AUTO = 1 << 14;
        const ASYNC_DIO = 1 << 15;
        const WRITEBACK_CACHE = 1 << 16;
        const NO_OPEN_SUPPORT = 1 << 17;
        const PARALLEL_DIROPS = 1 << 18;
        const HANDLE_KILLPRIV = 1 << 19;
        const POSIX_ACL = 1 << 20;
        const ABORT_ERROR = 1 << 21;
        const MAX_PAGES = 1 << 22;
        const CACHE_SYMLINKS = 1 << 23;
        const NO_OPENDIR_SUPPORT = 1 << 24;
        const EXPLICIT_INVAL_DATA = 1 << 25;
        const MAP_ALIGNMENT = 1 << 26;
        const SUBMOUNTS = 1 << 27;
        const HANDLE_KILLPRIV_V2 = 1 << 28;
        const SETXATTR_EXT = 1 << 29;
        const INIT_EXT = 1 << 30;
        const INIT_RESERVED = 1 << 31;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseInitFlag2: u32 {
        const SECURITY_CTX = 1 << 0;
        const HAS_INODE_DAX = 1 << 1;
        const CREATE_SUPP_GROUP = 1 << 2;
        const HAS_EXPIRE_ONLY = 1 << 3;
        const DIRECT_IO_ALLOW_MMAP = 1 << 4;
        const PASSTHROUGH = 1 << 5;
        const NO_EXPORT_SUPPORT = 1 << 6;
        const HAS_RESEND = 1 << 7;
        const ALLOW_IDMAP = 1 << 8;
        const OVER_IO_URING = 1 << 9;
        const REQUEST_TIMEOUT = 1 << 10;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseReleaseFlag: u32 {
        const FLUSH = 1 << 0;
        const FLOCK_UNLOCK = 1 << 1;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseGetattrFlag: u32 {
        const FN = 1 << 0;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseLockFlag: u32 {
        const FLOCK = 1 << 0;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseWriteFlag: u32 {
        const CACHE = 1 << 0;
        const LOCKOWNER = 1 << 1;
        const KILL_SUIDGID = 1 << 2;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseReadFlag: u32 {
        const LOCKOWNER = 1 << 1;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseIoctlFlag: u32 {
        const COMPAT = 1;
        const UNRESTRICTED = 2;
        const RETRY = 4;
        const BIT_32 = 8;
        const DIR = 16;
        const COMPAT_X32 = 32;
        const MAX_IOV = 256;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FusePollFlag: u32 {
        const SCHEDULE_NOTIFY = 1;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseFsyncFlag: u32 {
        const FDATASYNC = 1;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseAttrFlag: u32 {
        const SUBMOUNT = 1;
        const DAX = 2;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseOpenFlag: u32 {
        const KILL_SUIDGID = 1;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseSetattrFlag: u32 {
        const ACL_KILL_SGID = 1;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSxTime {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseStatx {
    pub mask: u32,
    pub blksize: u32,
    pub attributes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub __spare0: [u16; 1],
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub attributes_mask: u64,
    pub atime: FuseSxTime,
    pub btime: FuseSxTime,
    pub ctime: FuseSxTime,
    pub mtime: FuseSxTime,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub __spare2: [u64; 14],
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseFileLock {
    pub start: u64,
    pub end: u64,
    pub type_: u32,
    pub pid: u32,
}

c_enum! {
    #[derive(FromBytes, Immutable, IntoBytes)]
    pub struct FuseOpcode(u32);
    {
        LOOKUP = 1;
        FORGET = 2;
        GETATTR = 3;
        SETATTR = 4;
        READLINK = 5;
        SYMLINK = 6;
        MKNOD = 8;
        MKDIR = 9;
        UNLINK = 10;
        RMDIR = 11;
        RENAME = 12;
        LINK = 13;
        OPEN = 14;
        READ = 15;
        WRITE = 16;
        STATFS = 17;
        RELEASE = 18;
        FSYNC = 20;
        SETXATTR = 21;
        GETXATTR = 22;
        LISTXATTR = 23;
        REMOVEXATTR = 24;
        FLUSH = 25;
        INIT = 26;
        OPENDIR = 27;
        READDIR = 28;
        RELEASEDIR = 29;
        FSYNCDIR = 30;
        GETLK = 31;
        SETLK = 32;
        SETLKW = 33;
        ACCESS = 34;
        CREATE = 35;
        INTERRUPT = 36;
        BMAP = 37;
        DESTROY = 38;
        IOCTL = 39;
        POLL = 40;
        NOTIFY_REPLY = 41;
        BATCH_FORGET = 42;
        FALLOCATE = 43;
        READDIRPLUS = 44;
        RENAME2 = 45;
        LSEEK = 46;
        COPY_FILE_RANGE = 47;
        SETUPMAPPING = 48;
        REMOVEMAPPING = 49;
        SYNCFS = 50;
        TMPFILE = 51;
        STATX = 52;
        INIT_BSWAP_RESERVED = 436207616;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseForgetIn {
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseForgetOne {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseBatchForgetIn {
    pub count: u32,
    pub dummy: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseGetattrIn {
    pub getattr_flags: u32,
    pub dummy: u32,
    pub fh: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseStatxIn {
    pub getattr_flags: u32,
    pub reserved: u32,
    pub fh: u64,
    pub sx_flags: u32,
    pub sx_mask: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseStatxOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub flags: u32,
    pub spare: [u64; 2],
    pub stat: FuseStatx,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseMknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseRenameIn {
    pub newdir: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseRename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub open_flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub backing_id: i32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseFlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseStatfsOut {
    pub st: FuseKstatfs,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseFsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSetxattrIn {
    pub size: u32,
    pub flags: u32,
    pub setxattr_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseGetxattrIn {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseGetxattrOut {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseLkIn {
    pub fh: u64,
    pub owner: u64,
    pub lk: FuseFileLock,
    pub lk_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseLkOut {
    pub lk: FuseFileLock,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseAccessIn {
    pub mask: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub flags2: u32,
    pub unused: [u32; 11],
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub max_stack_depth: u32,
    pub request_timeout: u16,
    pub unused: [u16; 11],
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseInterruptIn {
    pub unique: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseBmapIn {
    pub block: u64,
    pub blocksize: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseBmapOut {
    pub block: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseIoctlIn {
    pub fh: u64,
    pub flags: u32,
    pub cmd: u32,
    pub arg: u64,
    pub in_size: u32,
    pub out_size: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseIoctlIovec {
    pub base: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseIoctlOut {
    pub result: i32,
    pub flags: u32,
    pub in_iovs: u32,
    pub out_iovs: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FusePollIn {
    pub fh: u64,
    pub kh: u64,
    pub flags: u32,
    pub events: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FusePollOut {
    pub revents: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyPollWakeupOut {
    pub kh: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseFallocateIn {
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: FuseOpcode,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub total_extlen: u16,
    pub padding: u16,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

c_enum! {
    #[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
    pub struct FuseDirentType(u32);
    {
        UNKNOWN = 0x0;
        FIFO = 0x1;
        CHR = 0x2;
        DIR = 0x4;
        BLK = 0x6;
        REG = 0x8;
        LNK = 0xa;
        SOCK = 0xc;
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseDirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub type_: FuseDirentType,
    pub name: PhantomData<[u8]>,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseDirentplus {
    pub entry_out: FuseEntryOut,
    pub dirent: FuseDirent,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyInvalInodeOut {
    pub ino: u64,
    pub off: i64,
    pub len: i64,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseNotifyInvalFlag: u32 {
        const EXPIRE_ONLY = 1 << 0;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyInvalEntryOut {
    pub parent: u64,
    pub namelen: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyDeleteOut {
    pub parent: u64,
    pub child: u64,
    pub namelen: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyStoreOut {
    pub nodeid: u64,
    pub offset: u64,
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyRetrieveOut {
    pub notify_unique: u64,
    pub nodeid: u64,
    pub offset: u64,
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseNotifyRetrieveIn {
    pub dummy1: u64,
    pub offset: u64,
    pub size: u32,
    pub dummy2: u32,
    pub dummy3: u64,
    pub dummy4: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseBackingMap {
    pub fd: i32,
    pub flags: u32,
    pub padding: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseLseekIn {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseLseekOut {
    pub offset: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseCopyFileRangeIn {
    pub fh_in: u64,
    pub off_in: u64,
    pub nodeid_out: u64,
    pub fh_out: u64,
    pub off_out: u64,
    pub len: u64,
    pub flags: u64,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FuseSetupmappingFlag: u32 {
        const WRITE = 1 << 0;
        const READ = 1 << 1;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSetupmappingIn {
    pub fh: u64,
    pub foffset: u64,
    pub len: u64,
    pub flags: u64,
    pub moffset: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseRemovemappingIn {
    pub count: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseRemovemappingOne {
    pub moffset: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSyncfsIn {
    pub padding: u64,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSecctx {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseSecctxHeader {
    pub size: u32,
    pub nr_secctx: u32,
}

c_enum! {
    #[derive(Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
    pub struct FuseExtType(u32);
    {
        MAX_NR_SECCTX = 31;
        EXT_GROUPS = 32;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseExtHeader {
    pub size: u32,
    pub type_: FuseExtType,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct FuseSuppGroups<const N: usize> {
    pub nr_groups: u32,
    pub groups: [u32; N],
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseUringEntInOut {
    pub flags: u64,
    pub commit_id: u64,
    pub payload_sz: u32,
    pub padding: u32,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseUringReqHeader {
    pub in_out: [u8; 128],
    pub op_in: [u8; 128],
    pub ring_ent_in_out: FuseUringEntInOut,
}

c_enum! {
    pub struct FuseUringCmd(u32);
    {
        INVALID = 0;
        REGISTER = 1;
        COMMIT_AND_FETCH = 2;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct FuseUringCmdReq {
    pub flags: u64,
    pub commit_id: u64,
    pub qid: u16,
    pub padding: [u8; 6],
}
