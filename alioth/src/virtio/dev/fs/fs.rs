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
use std::io::{self, IoSlice, IoSliceMut, Read};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use bitflags::bitflags;
use mio::Registry;
use mio::event::Event;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::fuse::bindings::{FuseInHeader, FuseOpcode, FuseOutHeader};
use crate::fuse::{self, Fuse};
use crate::hv::IoeventFd;
use crate::impl_mmio_for_zerocopy;
use crate::mem::mapped::RamBus;
use crate::virtio::dev::{Result, Virtio, WakeEvent};
use crate::virtio::queue::handlers::handle_desc;
use crate::virtio::queue::{Descriptor, Queue, VirtQueue};
use crate::virtio::worker::Waker;
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, IrqSender};

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
    pub struct FsFeature: u64 {
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
}

impl<F> Fs<F> {
    pub fn new(name: impl Into<Arc<str>>, fuse: F, config: FsConfig) -> Self {
        let mut feature = FsFeature::empty();
        if config.notify_buf_size > 0 {
            feature |= FsFeature::NOTIFICATION;
        }
        Fs {
            name: name.into(),
            config: Arc::new(config),
            fuse,
            feature,
            driver_feature: FsFeature::empty(),
        }
    }

    fn handle_msg(
        &mut self,
        hdr: &FuseInHeader,
        in_: &[IoSlice],
        out: &mut [IoSliceMut],
    ) -> fuse::Result<usize>
    where
        F: Fuse,
    {
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
            FuseOpcode::WRITE => opcode_branch!(write, &_, &[IoSlice], _),
            _ => Err(io::Error::from_raw_os_error(libc::ENOSYS))?,
        }
    }

    fn handle_desc(&mut self, desc: &mut Descriptor, _registry: &Registry) -> Result<usize>
    where
        F: Fuse,
    {
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
        Ok(hdr_out.len as usize)
    }
}

impl<F> VirtioMio for Fs<F>
where
    F: Fuse + Debug + Send + Sync + 'static,
{
    fn activate<'a, 'm, Q, S, E>(
        &mut self,
        feature: u64,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
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
        _active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        unreachable!()
    }

    fn handle_queue<'a, 'm, Q, S, E>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
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
        let name = self.name.clone();
        handle_desc(&name, index, queue, irq_sender, |desc| {
            let len = self.handle_desc(desc, registry)?;
            Ok(Some(len))
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

    fn feature(&self) -> u64 {
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
        queue_regs: Arc<[Queue]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }
}
