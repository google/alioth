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

pub mod shared_dir;
#[cfg(target_os = "linux")]
pub mod vu;

use std::fmt::Debug;
use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use bitflags::bitflags;
use mio::Registry;
use mio::event::Event;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::fuse::bindings::{FuseInHeader, FuseOpcode, FuseOutHeader, FuseSetupmappingFlag};
use crate::fuse::{self, DaxRegion, Fuse};
use crate::hv::IoeventFd;
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::mem::{MemRegion, MemRegionType};
use crate::sync::notifier::Notifier;
#[cfg(target_os = "linux")]
use crate::virtio::dev::fs::vu::VuDaxRegion;
use crate::virtio::dev::{Result, Virtio, WakeEvent};
use crate::virtio::queue::{DescChain, QueueReg, Status, VirtQueue};
#[cfg(target_os = "linux")]
use crate::virtio::vu::conn::VuChannel;
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, IrqSender};
use crate::{ffi, impl_mmio_for_zerocopy};

impl DaxRegion for ArcMemPages {
    fn map(
        &self,
        m_offset: u64,
        fd: &File,
        f_offset: u64,
        len: u64,
        flag: FuseSetupmappingFlag,
    ) -> fuse::Result<()> {
        let fd = fd.as_raw_fd();

        let map_addr = self.addr() + m_offset as usize;

        let mut prot = 0;
        if flag.contains(FuseSetupmappingFlag::READ) {
            prot |= libc::PROT_READ;
        };
        if flag.contains(FuseSetupmappingFlag::WRITE) {
            prot |= libc::PROT_WRITE;
        }

        ffi!(
            unsafe {
                libc::mmap(
                    map_addr as _,
                    len as usize,
                    prot,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    fd,
                    f_offset as _,
                )
            },
            libc::MAP_FAILED
        )?;

        Ok(())
    }

    fn unmap(&self, m_offset: u64, len: u64) -> fuse::Result<()> {
        let map_addr = self.addr() + m_offset as usize;
        let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED;
        ffi!(
            unsafe { libc::mmap(map_addr as _, len as _, libc::PROT_NONE, flags, -1, 0) },
            libc::MAP_FAILED
        )?;

        Ok(())
    }
}

#[repr(C, align(4))]
#[derive(Debug, FromBytes, Immutable, IntoBytes)]
pub struct FsConfig {
    pub tag: [u8; 36],
    pub num_request_queues: u32,
    pub notify_buf_size: u32,
}

impl_mmio_for_zerocopy!(FsConfig);

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FsFeature: u128 {
        const NOTIFICATION = 1 << 0;
    }
}

#[derive(Debug)]
pub struct Fs<F> {
    name: Arc<str>,
    config: Arc<FsConfig>,
    fuse: F,
    feature: FsFeature,
    driver_feature: FsFeature,
    dax_region: Option<ArcMemPages>,
}

impl<F> Fs<F>
where
    F: Fuse,
{
    pub fn new(
        name: impl Into<Arc<str>>,
        mut fuse: F,
        config: FsConfig,
        dax_window: usize,
    ) -> Result<Self> {
        let mut feature = FsFeature::empty();
        if config.notify_buf_size > 0 {
            feature |= FsFeature::NOTIFICATION;
        }
        let mut dax_region = None;
        if dax_window > 0 {
            let prot = Some(libc::PROT_NONE);
            let region = ArcMemPages::from_anonymous(dax_window, prot, None)?;
            fuse.set_dax_region(Box::new(region.clone()));
            dax_region = Some(region);
        };
        Ok(Fs {
            name: name.into(),
            config: Arc::new(config),
            fuse,
            feature,
            driver_feature: FsFeature::empty(),
            dax_region,
        })
    }

    fn handle_msg(
        &mut self,
        hdr: &FuseInHeader,
        in_: &[IoSlice],
        out: &mut [IoSliceMut],
    ) -> fuse::Result<usize> {
        let name = &*self.name;
        let opcode = hdr.opcode;

        fn parse_in<'a, T>(bufs: &'a [IoSlice<'a>]) -> fuse::Result<(&'a T, &'a [u8])>
        where
            T: FromBytes + KnownLayout + Immutable,
        {
            let [buf] = bufs else {
                return Err(io::Error::from_raw_os_error(libc::EINVAL))?;
            };
            match T::ref_from_prefix(buf) {
                Ok((r, buf)) => Ok((r, buf)),
                Err(_) => Err(io::Error::from_raw_os_error(libc::EINVAL))?,
            }
        }

        fn parse_in_iov<'a, T>(bufs: &'a [IoSlice<'a>]) -> fuse::Result<(&'a T, &'a [IoSlice<'a>])>
        where
            T: FromBytes + KnownLayout + Immutable,
        {
            let [h, bufs @ ..] = bufs else {
                return Err(io::Error::from_raw_os_error(libc::EINVAL))?;
            };
            match T::ref_from_bytes(h) {
                Ok(r) => Ok((r, bufs)),
                Err(_) => Err(io::Error::from_raw_os_error(libc::EINVAL))?,
            }
        }

        macro_rules! opcode_branch {
            ($func:ident, &[u8],_) => {{
                let [in_] = in_ else {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL))?;
                };
                let ret = self.fuse.$func(hdr, in_)?;
                let size = ret.as_bytes().read_vectored(out)?;
                let in_s = String::from_utf8_lossy(in_);
                log::trace!("{name}: {opcode:?}\n{in_s:?}\n{ret:x?}");
                Ok(size)
            }};
            ($func:ident, &[u8], &mut[u8]) => {{
                let ([in_], [out]) = (in_, out) else {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL))?;
                };
                let size = self.fuse.$func(hdr, in_, out)?;
                let in_s = String::from_utf8_lossy(in_);
                log::trace!("{name}: {opcode:?}\n{in_s:?}\nsize = {size:?}",);
                Ok(size)
            }};
            ($func:ident, &_, &mut[u8]) => {{
                let [out] = out else {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL))?;
                };
                let (in_, _) = parse_in(in_)?;
                let size = self.fuse.$func(hdr, in_, out)?;
                log::trace!("{name}: {opcode:?}\n{in_:x?}\nsize = {size}");
                Ok(size)
            }};
            ($func:ident, &_, &mut[IoSliceMut]) => {{
                let (in_, _) = parse_in(in_)?;
                let size = self.fuse.$func(hdr, in_, out)?;
                log::trace!("{name}: {opcode:?}\n{in_:x?}\nsize = {size}");
                Ok(size)
            }};
            ($func:ident, &_,_) => {{
                let (in_, _) = parse_in(in_)?;
                let ret = self.fuse.$func(hdr, in_)?;
                let size = ret.as_bytes().read_vectored(out)?;
                log::trace!("{name}: {opcode:?}\n{in_:x?}\n{ret:x?}");
                Ok(size)
            }};
            ($func:ident, &_, &[u8],_) => {{
                let (in_, buf) = parse_in(in_)?;
                let ret = self.fuse.$func(hdr, in_, buf)?;
                let size = ret.as_bytes().read_vectored(out)?;
                log::trace!("{name}: {opcode:?}\n{in_:x?}\n{ret:x?}");
                Ok(size)
            }};
            ($func:ident, &_, &[IoSlice],_) => {{
                let (in_, bufs) = parse_in_iov(in_)?;
                let ret = self.fuse.$func(hdr, in_, bufs)?;
                let size = ret.as_bytes().read_vectored(out)?;
                log::trace!("{name}: {opcode:?}\n{in_:x?}\n{ret:x?}");
                Ok(size)
            }};
        }
        match opcode {
            FuseOpcode::INIT => opcode_branch!(init, &_, _),
            FuseOpcode::GETATTR => opcode_branch!(get_attr, &_, _),
            FuseOpcode::OPEN => opcode_branch!(open, &_, _),
            FuseOpcode::OPENDIR => opcode_branch!(open_dir, &_, _),
            FuseOpcode::READDIR => opcode_branch!(read_dir, &_, &mut [u8]),
            FuseOpcode::RELEASEDIR => opcode_branch!(release_dir, &_, _),
            FuseOpcode::LOOKUP => opcode_branch!(lookup, &[u8], _),
            FuseOpcode::FORGET => opcode_branch!(forget, &_, _),
            FuseOpcode::POLL => opcode_branch!(poll, &_, _),
            FuseOpcode::READ => opcode_branch!(read, &_, &mut [IoSliceMut]),
            FuseOpcode::FLUSH => opcode_branch!(flush, &_, _),
            FuseOpcode::RELEASE => opcode_branch!(release, &_, _),
            FuseOpcode::SYNCFS => opcode_branch!(syncfs, &_, _),
            FuseOpcode::IOCTL => opcode_branch!(ioctl, &_, _),
            FuseOpcode::GETXATTR => opcode_branch!(get_xattr, &[u8], &mut [u8]),
            FuseOpcode::SETXATTR => opcode_branch!(set_xattr, &[u8], _),
            FuseOpcode::CREATE => opcode_branch!(create, &_, &[u8], _),
            FuseOpcode::UNLINK => opcode_branch!(unlink, &[u8], _),
            FuseOpcode::RMDIR => opcode_branch!(rmdir, &[u8], _),
            FuseOpcode::RENAME => opcode_branch!(rename, &_, &[u8], _),
            FuseOpcode::WRITE => opcode_branch!(write, &_, &[IoSlice], _),
            FuseOpcode::RENAME2 => opcode_branch!(rename2, &_, &[u8], _),
            FuseOpcode::SETUPMAPPING => opcode_branch!(setup_mapping, &_, _),
            FuseOpcode::REMOVEMAPPING => opcode_branch!(remove_mapping, &[u8], _),
            _ => Err(io::Error::from_raw_os_error(libc::ENOSYS))?,
        }
    }

    fn handle_desc(&mut self, desc: &mut DescChain, _registry: &Registry) -> Result<u32> {
        let name = &*self.name;

        let (hdr_out, out) = match &mut desc.writable[..] {
            [] => (None, &mut [] as &mut _),
            [hdr, out @ ..] => {
                let Ok(hdr) = FuseOutHeader::mut_from_bytes(hdr) else {
                    log::error!("{name}: cannot parse FuseOutHeader");
                    return Ok(0);
                };
                (Some(hdr), out)
            }
        };

        let Some((hdr_in, mut in_)) = desc.readable.split_first() else {
            log::error!("{name}: cannot find opcode");
            return Ok(0);
        };

        let Ok((hdr_in, tail)) = FuseInHeader::ref_from_prefix(hdr_in) else {
            log::error!("{name}: cannot parse FuseInHeader");
            return Ok(0);
        };
        let opcode = hdr_in.opcode;

        let tails = [IoSlice::new(tail)];
        if !tail.is_empty() {
            if !in_.is_empty() {
                let len = tail.len();
                log::error!("{name}: {opcode:?}: cannot handle {len} bytes after header");
                return Ok(0);
            }
            in_ = &tails;
        }

        log::trace!("{name}: {opcode:?}, nodeid = {:#x}", hdr_in.nodeid);

        let ret = self.handle_msg(hdr_in, in_, out);
        if let Err(e) = &ret {
            log::error!("{}: {opcode:?}: {e:?}", self.name);
        };

        let Some(hdr_out) = hdr_out else {
            return Ok(0);
        };
        hdr_out.unique = hdr_in.unique;
        match ret {
            Ok(size) => {
                hdr_out.error = 0;
                hdr_out.len = (size + size_of_val(hdr_out)) as u32;
            }
            Err(e) => {
                hdr_out.error = -e.error_code();
                hdr_out.len = size_of_val(hdr_out) as u32;
            }
        }
        Ok(hdr_out.len)
    }
}

impl<F> VirtioMio for Fs<F>
where
    F: Fuse + Debug + Send + Sync + 'static,
{
    fn activate<'m, Q, S, E>(
        &mut self,
        feature: u128,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        self.driver_feature = FsFeature::from_bits_retain(feature);
        Ok(())
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        _event: &Event,
        _active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        unreachable!()
    }

    fn handle_queue<'m, Q, S, E>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let Some(Some(queue)) = active_mio.queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        if self.feature.contains(FsFeature::NOTIFICATION) && index == 1 {
            todo!("handle notification queue");
        }
        let irq_sender = active_mio.irq_sender;
        let registry = active_mio.poll.registry();
        queue.handle_desc(index, irq_sender, |chain| {
            let len = self.handle_desc(chain, registry)?;
            Ok(Status::Done { len })
        })
    }

    fn reset(&mut self, _registry: &Registry) {}
}

impl<F> Virtio for Fs<F>
where
    F: Fuse + Debug + Send + Sync + 'static,
{
    type Config = FsConfig;
    type Feature = FsFeature;

    fn id(&self) -> DeviceId {
        DeviceId::FileSystem
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn feature(&self) -> u128 {
        self.feature.bits() | FEATURE_BUILT_IN
    }

    fn num_queues(&self) -> u16 {
        let mut count = 1; // high priority queue
        if self.feature.contains(FsFeature::NOTIFICATION) {
            count += 1;
        }
        count + self.config.num_request_queues as u16 * 2
    }

    fn config(&self) -> Arc<FsConfig> {
        self.config.clone()
    }

    fn spawn_worker<S, E>(
        self,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }

    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        let dax_region = self.dax_region.as_ref()?;
        Some(Arc::new(MemRegion::with_dev_mem(
            dax_region.clone(),
            MemRegionType::Hidden,
        )))
    }

    #[cfg(target_os = "linux")]
    fn set_vu_channel(&mut self, channel: Arc<VuChannel>) {
        let vu_dax_region = VuDaxRegion { channel };
        self.fuse.set_dax_region(Box::new(vu_dax_region));
    }
}
