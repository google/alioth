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

#[cfg(test)]
#[path = "vmnet_test.rs"]
mod tests;

use std::ffi::CStr;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, IoSlice, IoSliceMut, Read};
use std::mem::{MaybeUninit, forget};
use std::num::NonZeroU16;
use std::os::fd::{AsFd, AsRawFd};
use std::os::raw::c_void;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::null;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::{FromBytes, IntoBytes};

use crate::hv::IoeventFd;
use crate::mem::mapped::RamBus;
use crate::net::MacAddr;
use crate::platform::block::{_NSConcreteStackBlock, BlockDescriptor, BlockLiteral};
use crate::platform::dispatch::{DispatchQueue, dispatch_queue_create};
use crate::platform::vmnet::{
    InterfaceEvent, OperationMode, VmPktDesc, VmnetInterface, VmnetInterfaceCompletionHandler,
    VmnetInterfaceEventCallback, VmnetReturn, vmnet_interface_set_event_callback,
    vmnet_mac_address_key, vmnet_mtu_key, vmnet_operation_mode_key, vmnet_read,
    vmnet_start_interface, vmnet_write,
};
use crate::platform::xpc::{
    XpcObject, xpc_dictionary_create, xpc_dictionary_get_string, xpc_dictionary_get_uint64,
    xpc_uint64_create,
};
use crate::sync::eventfd::EventFd;
// use crate::platform::if_tun::{TunFeature, tun_set_iff, tun_set_offload, tun_set_vnet_hdr_sz};
use crate::virtio::dev::net::{
    CtrlAck, CtrlClass, CtrlHdr, CtrlMq, CtrlMqParisSet, NetConfig, NetFeature, VirtioNetHdr,
};
use crate::virtio::dev::{DevParam, DeviceId, Result, Virtio, WakeEvent};
use crate::virtio::queue::{
    DescChain, QueueReg, Status, VirtQueue, copy_from_reader, copy_to_writer,
};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::worker::{Waker, WorkerApi};
use crate::virtio::{FEATURE_BUILT_IN, IrqSender, error};

#[derive(Debug)]
pub struct Net {
    name: Arc<str>,
    config: Arc<NetConfig>,
    feature: NetFeature,
    driver_feature: NetFeature,
    dispatch_queue: AtomicPtr<DispatchQueue>,
    interface: AtomicPtr<VmnetInterface>,
}

fn check_ret(ret: VmnetReturn) -> Result<()> {
    if ret == VmnetReturn::SUCCESS {
        return Ok(());
    }
    let kind = match ret {
        VmnetReturn::MEM_FAILURE => ErrorKind::OutOfMemory,
        VmnetReturn::INVALID_ARGUMENT => ErrorKind::InvalidInput,
        VmnetReturn::INVALID_ACCESS => ErrorKind::PermissionDenied,
        _ => ErrorKind::Other,
    };
    Err(io::Error::new(kind, format!("{ret:?}")).into())
}

impl Net {
    pub fn new(_: NetVmnetParam, name: impl Into<Arc<str>>) -> Result<Self> {
        let mode = unsafe { xpc_uint64_create(OperationMode::SHARED.raw() as u64) } as *const _;
        let desc = unsafe { xpc_dictionary_create(&vmnet_operation_mode_key, &mode, 1) };
        let dispatch_queue = unsafe { dispatch_queue_create(c"virtio-net".as_ptr(), null()) };
        let (sender, receiver) = mpsc::channel::<Result<NetConfig>>();

        #[repr(C)]
        struct StartBlock {
            block: VmnetInterfaceCompletionHandler,
            sender: *const Sender<Result<NetConfig>>,
        }

        fn start_callback_inner(ret: VmnetReturn, obj: *const XpcObject) -> Result<NetConfig> {
            check_ret(ret)?;
            let mtu = unsafe { xpc_dictionary_get_uint64(obj, vmnet_mtu_key) };
            let addr = unsafe { xpc_dictionary_get_string(obj, vmnet_mac_address_key) };
            let e = io::Error::new(ErrorKind::InvalidData, "Invalid mac address");
            let Ok(v) = unsafe { CStr::from_ptr(addr) }.to_str() else {
                return Err(e.into());
            };
            log::info!("get mac address {v:?}");

            let mut addr = [0u8; 6];
            let iter = v.split(':');
            let mut index = 0;
            for b_s in iter {
                let Some(b) = addr.get_mut(index) else {
                    return Err(e.into());
                };
                let Ok(v) = u8::from_str_radix(b_s, 16) else {
                    return Err(e.into());
                };
                *b = v;
                index += 1;
            }
            Ok(NetConfig {
                mtu: mtu as u16,
                max_queue_pairs: 1,
                mac: MacAddr(addr),
                ..Default::default()
            })
        }

        extern "C" fn start_callback(this: *mut c_void, ret: VmnetReturn, obj: *const XpcObject) {
            let this = unsafe { &*(this as *mut StartBlock) };
            let sender = unsafe { &*this.sender };

            if let Err(e) = sender.send(start_callback_inner(ret, obj)) {
                log::error!("failed to send config: {e:?}");
            }
        }

        static BLOCK_DESC: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: size_of::<StartBlock>() as _,
            copy_helper: None,
            dispose_helper: None,
            // signature: null(),
        };
        let handler = StartBlock {
            block: VmnetInterfaceCompletionHandler {
                isa: unsafe { _NSConcreteStackBlock },
                flags: 1 << 29,
                reserved: 0,
                invoke: start_callback,
                descriptor: &BLOCK_DESC as *const _,
            },
            sender: &sender as *const _,
        };
        let interface = unsafe { vmnet_start_interface(desc, dispatch_queue, &handler.block) };
        let config = match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(config)) => Ok(config),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                Err(io::Error::new(ErrorKind::Other, "failed to start vmnet interface").into())
            }
        }?;

        Ok(Net {
            name: name.into(),
            config: Arc::new(config),
            feature: NetFeature::MAC | NetFeature::MTU,
            driver_feature: NetFeature::empty(),
            dispatch_queue: AtomicPtr::new(dispatch_queue),
            interface: AtomicPtr::new(interface),
        })
    }
}

impl Virtio for Net {
    type Config = NetConfig;
    type Feature = NetFeature;

    fn id(&self) -> DeviceId {
        DeviceId::Net
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_queues(&self) -> u16 {
        let data_queues = self.config.max_queue_pairs << 1;
        if self.feature.contains(NetFeature::CTRL_VQ) {
            data_queues + 1
        } else {
            data_queues
        }
    }

    fn config(&self) -> Arc<NetConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u128 {
        self.feature.bits() | FEATURE_BUILT_IN
    }

    fn spawn_worker<S, E>(
        self,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }
}

impl VirtioMio for Net {
    fn reset(&mut self, registry: &Registry) {}

    fn activate<'m, Q, S, E>(
        &mut self,
        feature: u128,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let mut rx_eventfd = EventFd::new()?;
        active_mio
            .poll
            .registry()
            .register(&mut rx_eventfd, Token(0), Interest::READABLE)?;
        let interface = self.interface.load(Ordering::Acquire);
        let dispatch_queue = self.dispatch_queue.load(Ordering::Acquire);

        #[repr(C)]
        struct CallbackBlock {
            block: VmnetInterfaceEventCallback,
            eventfd: EventFd,
        }

        extern "C" fn callback_invoke(this: *mut c_void, _: InterfaceEvent, _: *const XpcObject) {
            let this = unsafe { &*(this as *mut CallbackBlock) };

            if let Err(e) = this.eventfd.trigger() {
                log::error!("failed to send config: {e:?}");
            }
        }

        static BLOCK_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: size_of::<CallbackBlock>() as _,
            copy_helper: None,
            dispose_helper: None,
            // signature: null(),
        };
        let callback = CallbackBlock {
            block: VmnetInterfaceEventCallback {
                isa: unsafe { _NSConcreteStackBlock },
                flags: 1 << 29,
                reserved: 0,
                invoke: callback_invoke,
                descriptor: &BLOCK_DESCRIPTOR as *const _,
            },
            eventfd: rx_eventfd,
        };

        let ret = unsafe {
            vmnet_interface_set_event_callback(
                interface,
                InterfaceEvent::PACKETS_AVAILABLE,
                dispatch_queue,
                &callback.block,
            )
        };
        check_ret(ret)?;
        forget(callback);
        Ok(())
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        event: &Event,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let token = event.token();
        let irq_sender = active_mio.irq_sender;
        if event.is_readable() {
            let index = (token.0 as u16) << 1;
            let Some(Some(queue)) = active_mio.queues.get_mut(index as usize) else {
                log::error!("{}: cannot find rx queue {index}", self.name);
                return Ok(());
            };
            let interface = self.interface.load(Ordering::Acquire);
            queue.handle_desc(index, irq_sender, read_from_vmnet(interface))?;
        }
        Ok(())
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
        let irq_sender = active_mio.irq_sender;
        if index == self.config.max_queue_pairs * 2 {
            unimplemented!()
        }
        let interface = self.interface.load(Ordering::Acquire);
        if index & 1 == 0 {
            queue.handle_desc(index, irq_sender, read_from_vmnet(interface))
        } else {
            log::info!("tx queue {index}");
            queue.handle_desc(index, irq_sender, write_to_vmnet(interface))
        }
    }
}

pub fn read_from_vmnet(
    interface: *mut VmnetInterface,
) -> impl FnMut(&mut DescChain) -> Result<Status> {
    move |chain: &mut DescChain| {
        let mut trim_len = size_of::<VirtioNetHdr>();
        let mut iov = Vec::with_capacity(chain.writable.len());

        for buf in chain.writable.iter_mut() {
            if trim_len > 0 {
                if let Some((_, tail)) = buf.split_at_mut_checked(trim_len) {
                    iov.push(libc::iovec {
                        iov_base: tail.as_ptr() as *mut c_void,
                        iov_len: tail.len(),
                    });
                    trim_len = 0;
                } else {
                    trim_len -= buf.len();
                }
            } else {
                iov.push(libc::iovec {
                    iov_base: buf.as_ptr() as *mut c_void,
                    iov_len: buf.len(),
                });
            }
        }

        let size = iov.iter().map(|s| s.iov_len).sum();
        let mut packets = VmPktDesc {
            vm_pkt_size: size,
            vm_pkt_iov: iov.as_mut_ptr() as *mut libc::iovec,
            vm_pkt_iovcnt: iov.len() as u32,
            vm_flags: 0,
        };
        let mut pktcnt = 1;
        // for buf in chain.writable.iter() {
        //     log::info!("before recive: {buf:02x?}");
        // }
        let ret = unsafe { vmnet_read(interface, &mut packets, &mut pktcnt) };
        check_ret(ret)?;
        if pktcnt == 0 {
            return Ok(Status::Break);
        }
        let hdr = VirtioNetHdr {
            num_buffers: 1,
            ..Default::default()
        };
        let _ = hdr.as_bytes().read_vectored(&mut chain.writable);
        log::info!("pkg count = {:?}, size = {:?}", pktcnt, packets.vm_pkt_size);
        // chain.writable[0][10] = 1;
        log::info!(
            "received: {:02x?}",
            &chain.writable[0][..packets.vm_pkt_size + 12]
        );
        Ok(Status::Done {
            len: packets.vm_pkt_size as u32 + 12,
        })
    }
}

pub fn write_to_vmnet(
    interface: *mut VmnetInterface,
) -> impl FnMut(&mut DescChain) -> Result<Status> {
    move |chain: &mut DescChain| {
        let mut trim_len = size_of::<VirtioNetHdr>();
        let mut iov = Vec::with_capacity(chain.readable.len());

        for buf in chain.readable.iter() {
            if trim_len > 0 {
                if let Some((_, tail)) = buf.split_at_checked(trim_len) {
                    iov.push(libc::iovec {
                        iov_base: tail.as_ptr() as *mut c_void,
                        iov_len: tail.len(),
                    });
                    trim_len = 0;
                } else {
                    trim_len -= buf.len();
                }
            } else {
                iov.push(libc::iovec {
                    iov_base: buf.as_ptr() as *mut c_void,
                    iov_len: buf.len(),
                });
            }
        }

        let size = iov.iter().map(|s| s.iov_len).sum();
        let mut packets = VmPktDesc {
            vm_pkt_size: size,
            vm_pkt_iov: iov.as_ptr() as *mut libc::iovec,
            vm_pkt_iovcnt: iov.len() as u32,
            vm_flags: 0,
        };
        let mut pktcnt = 1;
        let ret = unsafe { vmnet_write(interface, &mut packets, &mut pktcnt) };
        check_ret(ret)?;
        log::info!(
            "sent: {:02x?}",
            &chain.readable[0][..packets.vm_pkt_size + 12]
        );
        if pktcnt == 0 {
            return Ok(Status::Break);
        }
        Ok(Status::Done { len: 0 })
    }
}

#[derive(Debug, Deserialize, Clone, Help)]
pub struct NetVmnetParam {}

impl DevParam for NetVmnetParam {
    type Device = Net;
    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        Net::new(self, name)
    }
}
