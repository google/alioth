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

use std::collections::HashMap;
use std::ffi::{CStr, OsStr};
use std::fs::{File, FileType, Metadata, OpenOptions, ReadDir, read_dir};
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::iter::{Enumerate, Peekable};
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirEntryExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zerocopy::IntoBytes;

use crate::align_up_ty;
use crate::fuse::bindings::{
    FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION, FUSE_ROOT_ID, FuseAttr, FuseAttrOut,
    FuseCreateIn, FuseCreateOut, FuseDirent, FuseDirentType, FuseEntryOut, FuseFlushIn,
    FuseForgetIn, FuseGetattrFlag, FuseGetattrIn, FuseInHeader, FuseInitIn, FuseInitOut,
    FuseOpenIn, FuseOpenOut, FuseReadIn, FuseReleaseIn, FuseSyncfsIn, FuseWriteIn, FuseWriteOut,
};
use crate::fuse::{Fuse, Result, error};

const MAX_BUFFER_SIZE: u32 = 1 << 20;

fn fuse_dir_type(e: FileType) -> FuseDirentType {
    if e.is_dir() {
        FuseDirentType::DIR
    } else if e.is_file() {
        FuseDirentType::REG
    } else if e.is_symlink() {
        FuseDirentType::LNK
    } else if e.is_socket() {
        FuseDirentType::SOCK
    } else if e.is_file() {
        FuseDirentType::FIFO
    } else if e.is_char_device() {
        FuseDirentType::CHR
    } else if e.is_block_device() {
        FuseDirentType::BLK
    } else {
        FuseDirentType::UNKNOWN
    }
}

fn convert_o_flags(flags: i32) -> Result<OpenOptions> {
    let mut opts = OpenOptions::new();
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => opts.read(true),
        libc::O_WRONLY => opts.write(true),
        libc::O_RDWR => opts.read(true).write(true),
        mode => return error::InvalidAccMode { mode }.fail(),
    };
    opts.append(flags & libc::O_APPEND == libc::O_APPEND);
    opts.truncate(flags & libc::O_TRUNC == libc::O_TRUNC);
    opts.create(flags & libc::O_CREAT == libc::O_CREAT);
    opts.create_new(flags & (libc::O_CREAT | libc::O_EXCL) == libc::O_CREAT | libc::O_EXCL);
    let all = libc::O_ACCMODE | libc::O_APPEND | libc::O_TRUNC | libc::O_CREAT | libc::O_EXCL;
    opts.custom_flags(flags & !all);
    Ok(opts)
}

#[derive(Debug)]
enum Handle {
    ReadDir(Box<Peekable<Enumerate<ReadDir>>>),
    File(File),
}

impl Handle {
    fn fh(&self) -> u64 {
        match self {
            Handle::File(f) => f.as_raw_fd() as u64,
            Handle::ReadDir(rd) => rd.as_ref() as *const Peekable<_> as u64,
        }
    }
}

#[derive(Debug)]
struct Node {
    lookup_count: u64,
    path: Box<Path>,
    handle: Option<Handle>,
}

#[derive(Debug)]
pub struct Passthrough {
    nodes: HashMap<u64, Node>,
}

impl Passthrough {
    pub fn new(path: PathBuf) -> Result<Self> {
        let node = Node {
            lookup_count: 1,
            path: path.into(),
            handle: None,
        };
        let nodes = HashMap::from([(FUSE_ROOT_ID, node)]);
        Ok(Passthrough { nodes })
    }

    fn get_node(&self, id: u64) -> Result<&Node> {
        match self.nodes.get(&id) {
            Some(node) => Ok(node),
            None => error::NodeId { id }.fail(),
        }
    }

    fn get_node_mut(&mut self, id: u64) -> Result<&mut Node> {
        match self.nodes.get_mut(&id) {
            Some(node) => Ok(node),
            None => error::NodeId { id }.fail(),
        }
    }

    fn convert_meta(&self, meta: &Metadata) -> FuseAttr {
        FuseAttr {
            ino: meta.ino(),
            size: meta.size(),
            blocks: meta.blocks(),
            atime: meta.atime() as _,
            mtime: meta.mtime() as _,
            ctime: meta.ctime() as _,
            atimensec: meta.atime_nsec() as _,
            mtimensec: meta.mtime_nsec() as _,
            ctimensec: meta.ctime_nsec() as _,
            mode: meta.mode(),
            nlink: meta.nlink() as _,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: meta.rdev() as _,
            blksize: meta.blksize() as _,
            flags: 0,
        }
    }
}

impl Fuse for Passthrough {
    fn init(&mut self, _hdr: &FuseInHeader, in_: &FuseInitIn) -> Result<FuseInitOut> {
        Ok(FuseInitOut {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: in_.max_readahead,
            flags: 0,
            max_background: u16::MAX,
            congestion_threshold: (u16::MAX / 4) * 3,
            max_write: MAX_BUFFER_SIZE,
            time_gran: 1,
            max_pages: 256,
            map_alignment: 0,
            flags2: 0,
            ..Default::default()
        })
    }

    fn get_attr(&mut self, hdr: &FuseInHeader, in_: &FuseGetattrIn) -> Result<FuseAttrOut> {
        let node = self.get_node(hdr.nodeid)?;
        log::trace!("get_attr: {in_:?} {:?}", node.path);

        let flag = FuseGetattrFlag::from_bits_retain(in_.getattr_flags);
        if flag.contains(FuseGetattrFlag::FH) {
            let Some(handle) = &node.handle else {
                return error::InvalidFileHandle.fail();
            };
            let fh = handle.fh();
            if in_.fh != fh {
                return error::InvalidFileHandle.fail();
            }
        }

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&node.path)?;
        let meta = file.metadata()?;
        Ok(FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            attr: self.convert_meta(&meta),
            dummy: 0,
        })
    }

    fn open_dir(&mut self, hdr: &FuseInHeader, in_: &FuseOpenIn) -> Result<FuseOpenOut> {
        let node = self.get_node_mut(hdr.nodeid)?;
        log::trace!("open_dir: {in_:?} {:?}", node.path);
        let handle = Handle::ReadDir(Box::new(read_dir(&node.path)?.enumerate().peekable()));
        let fh = handle.fh();
        node.handle = Some(handle);
        Ok(FuseOpenOut {
            fh,
            open_flags: 0,
            backing_id: 0,
        })
    }

    fn read_dir(
        &mut self,
        hdr: &FuseInHeader,
        in_: &FuseReadIn,
        mut buf: &mut [u8],
    ) -> Result<usize> {
        let node = self.get_node_mut(hdr.nodeid)?;
        log::trace!("read_dir: {:?}", node.path);

        let Some(Handle::ReadDir(read_dir)) = &mut node.handle else {
            return error::DirNotOpened.fail();
        };
        let Some((index, _)) = read_dir.peek() else {
            return Ok(0);
        };
        if *index as u64 != in_.offset {
            todo!("in_offset = {}, != {}", in_.offset, *index);
        }

        let mut total_len = 0;

        while let Some((index, entry)) = read_dir.peek() {
            let e = entry.as_ref()?;
            let name = e.file_name();
            let namelen = name.len();

            let dir_entry = FuseDirent {
                ino: e.ino(),
                off: *index as u64 + 1,
                namelen: namelen as _,
                type_: fuse_dir_type(e.file_type()?),
                name: PhantomData,
            };
            let aligned_namelen = align_up_ty!(namelen, FuseDirent);
            let len = size_of_val(&dir_entry) + aligned_namelen;
            let Some((p1, p2)) = buf.split_at_mut_checked(len) else {
                break;
            };
            let (b_entry, b_name) = p1.split_at_mut(size_of_val(&dir_entry));
            log::trace!("read_dir: {dir_entry:?} {name:?}");
            b_entry.copy_from_slice(dir_entry.as_bytes());
            b_name[..namelen].copy_from_slice(name.as_encoded_bytes());

            buf = p2;
            total_len += len;
            read_dir.next();
        }

        Ok(total_len)
    }

    fn release_dir(&mut self, hdr: &FuseInHeader, in_: &FuseReleaseIn) -> Result<()> {
        let node = self.get_node_mut(hdr.nodeid)?;
        node.handle = None;
        log::trace!("release_dir: {in_:?} {:?}", node.path);
        Ok(())
    }

    fn release(&mut self, hdr: &FuseInHeader, in_: &FuseReleaseIn) -> Result<()> {
        let node = self.get_node_mut(hdr.nodeid)?;
        node.handle = None;
        log::trace!("release: {in_:?} {:?}", node.path);
        Ok(())
    }

    fn lookup(&mut self, hdr: &FuseInHeader, in_: &[u8]) -> Result<FuseEntryOut> {
        let parent = self.get_node(hdr.nodeid)?;
        let p = OsStr::from_bytes(CStr::from_bytes_until_nul(in_)?.to_bytes());
        let path = parent.path.join(p).into_boxed_path();

        log::trace!("lookup: {path:?}");
        let mut entry;
        let (nodeid, node) =
            if let Some((nodeid, node)) = self.nodes.iter_mut().find(|(_, n)| n.path == path) {
                node.lookup_count += 1;
                (*nodeid, node)
            } else {
                let nodeid = path.as_os_str().as_bytes().as_ptr() as u64;
                let node = Node {
                    lookup_count: 1,
                    path,
                    handle: None,
                };
                entry = self.nodes.entry(nodeid).insert_entry(node);
                (nodeid, entry.get_mut())
            };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&node.path)?;
        let meta = file.metadata()?;
        Ok(FuseEntryOut {
            nodeid,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: self.convert_meta(&meta),
        })
    }

    fn forget(&mut self, hdr: &FuseInHeader, in_: &FuseForgetIn) -> Result<()> {
        let node = self.get_node_mut(hdr.nodeid)?;
        log::trace!(
            "forget: {:?}, ref_count {}, remove {}",
            node.path,
            node.lookup_count,
            in_.nlookup
        );
        node.lookup_count -= in_.nlookup;
        if node.lookup_count == 0 {
            self.nodes.remove(&hdr.nodeid);
        }
        Ok(())
    }

    fn open(&mut self, hdr: &FuseInHeader, in_: &FuseOpenIn) -> Result<FuseOpenOut> {
        let node = self.get_node_mut(hdr.nodeid)?;
        log::trace!("open: {:?} {in_:?}", node.path);
        let opts = convert_o_flags(in_.flags as i32)?;
        let handle = Handle::File(opts.open(&node.path)?);
        let fh = handle.fh();
        node.handle = Some(handle);
        Ok(FuseOpenOut {
            fh,
            open_flags: 0,
            backing_id: 0,
        })
    }

    fn read(
        &mut self,
        hdr: &FuseInHeader,
        in_: &FuseReadIn,
        iov: &mut [IoSliceMut],
    ) -> Result<usize> {
        let node = self.get_node(hdr.nodeid)?;
        log::trace!("read: {hdr:?} {in_:?} {:?}", node.path);
        let Some(Handle::File(f)) = &node.handle else {
            return error::FileNotOpened.fail();
        };
        let mut file = f;
        // TODO: use `read_vectored_at`
        // https://github.com/rust-lang/rust/issues/89517
        file.seek(SeekFrom::Start(in_.offset))?;
        let size = file.read_vectored(iov)?;
        Ok(size)
    }

    fn flush(&mut self, hdr: &FuseInHeader, in_: &FuseFlushIn) -> Result<()> {
        log::error!("flush: {hdr:?} {in_:?}");
        Ok(())
    }

    fn syncfs(&mut self, hdr: &FuseInHeader, in_: &FuseSyncfsIn) -> Result<()> {
        log::error!("syncfs: {hdr:?} {in_:?}");
        Ok(())
    }

    fn create(
        &mut self,
        hdr: &FuseInHeader,
        in_: &FuseCreateIn,
        buf: &[u8],
    ) -> Result<FuseCreateOut> {
        let parent = self.get_node_mut(hdr.nodeid)?;
        let opts = convert_o_flags(in_.flags as i32)?;
        let p = OsStr::from_bytes(CStr::from_bytes_until_nul(buf)?.to_bytes());
        let path = parent.path.join(p).into_boxed_path();
        let nodeid = path.as_os_str().as_bytes().as_ptr() as u64;
        let f = opts.open(&path)?;
        let meta = f.metadata()?;
        let handle = Handle::File(f);
        let fh = handle.fh();
        let node = Node {
            lookup_count: 1,
            path,
            handle: Some(handle),
        };
        self.nodes.insert(nodeid, node);
        Ok(FuseCreateOut {
            entry: FuseEntryOut {
                nodeid,
                generation: 0,
                entry_valid: 0,
                attr_valid: 0,
                entry_valid_nsec: 0,
                attr_valid_nsec: 0,
                attr: self.convert_meta(&meta),
            },
            open: FuseOpenOut {
                fh,
                open_flags: 0,
                backing_id: 0,
            },
        })
    }

    fn write(
        &mut self,
        hdr: &FuseInHeader,
        in_: &FuseWriteIn,
        buf: &[IoSlice],
    ) -> Result<FuseWriteOut> {
        let node = self.get_node(hdr.nodeid)?;
        let Some(Handle::File(f)) = &node.handle else {
            return error::FileNotOpened.fail();
        };
        let mut file = f;
        // TODO: use `write_vectored_at`
        // https://github.com/rust-lang/rust/issues/89517
        file.seek(SeekFrom::Start(in_.offset))?;
        let size = file.write_vectored(buf)? as u32;
        Ok(FuseWriteOut { size, padding: 0 })
    }
}
