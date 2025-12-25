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

use std::ffi::CStr;
use std::fmt::Debug;
use std::io::{self, ErrorKind, Read};
use std::ptr::null;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use libc::c_void;
use mio::event::Event;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::IntoBytes;

use crate::device::net::MacAddr;
use crate::hv::IoeventFd;
use crate::mem::mapped::RamBus;
use crate::sync::notifier::Notifier;
use crate::sys::block::{_NSConcreteStackBlock, BlockDescriptor, BlockFlag};
use crate::sys::dispatch::{DispatchQueue, dispatch_queue_create, dispatch_release};
use crate::sys::vmnet::{
    InterfaceEvent, OperationMode, VmPktDesc, VmnetInterface, VmnetInterfaceCompletionHandler,
    VmnetInterfaceEventCallback, VmnetReturn, VmnetStartInterfaceCompletionHandler,
    vmnet_allocate_mac_address_key, vmnet_enable_isolation_key, vmnet_interface_set_event_callback,
    vmnet_mac_address_key, vmnet_mtu_key, vmnet_operation_mode_key, vmnet_read,
    vmnet_start_interface, vmnet_stop_interface, vmnet_write,
};
use crate::sys::xpc::{
    XpcObject, xpc_bool_create, xpc_dictionary_create, xpc_dictionary_get_string,
    xpc_dictionary_get_uint64, xpc_uint64_create,
};
use crate::virtio::dev::net::{NetConfig, NetFeature, VirtioNetHdr};
use crate::virtio::dev::{DevParam, DeviceId, Result, Virtio, WakeEvent};
use crate::virtio::queue::{DescChain, QueueReg, Status, VirtQueue};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{FEATURE_BUILT_IN, IrqSender};

#[derive(Debug)]
pub struct Net {
    name: Arc<str>,
    config: Arc<NetConfig>,
    feature: NetFeature,
    dispatch_queue: AtomicPtr<DispatchQueue>,
    interface: AtomicPtr<VmnetInterface>,
    rx_notifier: Notifier,
}

fn check_ret(ret: VmnetReturn) -> Result<(), io::Error> {
    if ret == VmnetReturn::SUCCESS {
        return Ok(());
    }
    let kind = match ret {
        VmnetReturn::MEM_FAILURE => ErrorKind::OutOfMemory,
        VmnetReturn::INVALID_ARGUMENT => ErrorKind::InvalidInput,
        VmnetReturn::INVALID_ACCESS => ErrorKind::PermissionDenied,
        _ => ErrorKind::Other,
    };
    Err(io::Error::new(kind, format!("{ret:?}")))
}

impl Net {
    pub fn new(param: NetVmnetParam, name: impl Into<Arc<str>>) -> Result<Self> {
        let allocate_mac = param.mac.is_none();
        let keys = unsafe {
            [
                vmnet_operation_mode_key,
                vmnet_allocate_mac_address_key,
                vmnet_enable_isolation_key,
            ]
        };
        let vals = [
            unsafe { xpc_uint64_create(OperationMode::SHARED.raw() as u64) } as *const _,
            unsafe { xpc_bool_create(allocate_mac) } as *const _,
            unsafe { xpc_bool_create(false) } as *const _,
        ];
        let desc = unsafe { xpc_dictionary_create(keys.as_ptr(), vals.as_ptr(), 3) };
        let dispatch_queue = unsafe { dispatch_queue_create(c"virtio-net".as_ptr(), null()) };
        let (sender, receiver) = mpsc::channel::<Result<NetConfig>>();

        #[repr(C)]
        struct HandlerBlock {
            block: VmnetStartInterfaceCompletionHandler,
            sender: *const Sender<Result<NetConfig>>,
        }

        fn do_handler_invoke(ret: VmnetReturn, obj: *const XpcObject) -> Result<NetConfig> {
            check_ret(ret)?;
            let mtu = unsafe { xpc_dictionary_get_uint64(obj, vmnet_mtu_key) } as u16;
            let mac_addr = unsafe { xpc_dictionary_get_string(obj, vmnet_mac_address_key) };
            if mac_addr.is_null() {
                return Ok(NetConfig {
                    mtu,
                    max_queue_pairs: 1,
                    ..Default::default()
                });
            }
            let Ok(mac_addr) = unsafe { CStr::from_ptr(mac_addr) }.to_str() else {
                let e = io::Error::new(ErrorKind::InvalidData, "Invalid mac address string");
                return Err(e.into());
            };
            match mac_addr.parse() {
                Ok(mac) => Ok(NetConfig {
                    mtu,
                    max_queue_pairs: 1,
                    mac,
                    ..Default::default()
                }),
                Err(e) => {
                    let msg = format!("Invalid mac address: {e:?}");
                    Err(io::Error::new(ErrorKind::InvalidData, msg).into())
                }
            }
        }

        extern "C" fn handler_invoke(this: *mut c_void, ret: VmnetReturn, obj: *const XpcObject) {
            let this = unsafe { &*(this as *mut HandlerBlock) };
            let sender = unsafe { &*this.sender };

            let config = do_handler_invoke(ret, obj);
            if let Err(e) = sender.send(config) {
                log::error!("Failed to send config: {e:?}");
            }
        }

        static BLOCK_DESC: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: size_of::<HandlerBlock>() as _,
        };
        let handler = HandlerBlock {
            block: VmnetStartInterfaceCompletionHandler {
                isa: unsafe { _NSConcreteStackBlock },
                flags: BlockFlag::HAS_STRET,
                reserved: 0,
                invoke: handler_invoke,
                descriptor: &BLOCK_DESC as *const _,
            },
            sender: &sender as *const _,
        };
        let interface = unsafe { vmnet_start_interface(desc, dispatch_queue, &handler.block) };
        let mut config = match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(config)) => Ok(config),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::other("failed to start vmnet interface").into()),
        }?;

        if let Some(mac) = param.mac {
            config.mac = mac;
        }

        Ok(Net {
            name: name.into(),
            config: Arc::new(config),
            feature: NetFeature::MAC | NetFeature::MTU,
            dispatch_queue: AtomicPtr::new(dispatch_queue),
            interface: AtomicPtr::new(interface),
            rx_notifier: Notifier::new()?,
        })
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        let interface = self.interface.load(Ordering::Acquire);
        let dispatch_queue = self.dispatch_queue.load(Ordering::Acquire);

        let (sender, receiver) = mpsc::channel::<VmnetReturn>();

        #[repr(C)]
        struct HandlerBlock {
            block: VmnetInterfaceCompletionHandler,
            sender: *const Sender<VmnetReturn>,
        }

        extern "C" fn handler_invoke(this: *mut c_void, ret: VmnetReturn) {
            let this = unsafe { &*(this as *mut HandlerBlock) };
            let sender = unsafe { &*this.sender };

            if let Err(e) = sender.send(ret) {
                log::error!("Failed to send ret {ret:x?}: {e:?}");
            }
        }

        static BLOCK_DESC: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: size_of::<HandlerBlock>() as _,
        };
        let handler = HandlerBlock {
            block: VmnetInterfaceCompletionHandler {
                isa: unsafe { _NSConcreteStackBlock },
                flags: BlockFlag::HAS_STRET,
                reserved: 0,
                invoke: handler_invoke,
                descriptor: &BLOCK_DESC as *const _,
            },
            sender: &sender as *const _,
        };
        let ret = unsafe { vmnet_stop_interface(interface, dispatch_queue, &handler.block) };
        if let Err(e) = check_ret(ret) {
            log::error!("{}: failed to stop interface: {e:?}", self.name);
            return;
        }
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(ret) => {
                if let Err(e) = check_ret(ret) {
                    log::error!("{}: failed to stop interface: {e:?}", self.name);
                }
            }
            Err(e) => log::error!(
                "{}: failed to receive stop interface response: {e:?}",
                self.name
            ),
        }
        unsafe { dispatch_release(dispatch_queue) };
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
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }
}

impl VirtioMio for Net {
    fn reset(&mut self, registry: &Registry) {
        let interface = self.interface.load(Ordering::Acquire);

        let ret = unsafe {
            vmnet_interface_set_event_callback(
                interface,
                InterfaceEvent::PACKETS_AVAILABLE,
                null(),
                null(),
            )
        };
        if let Err(err) = check_ret(ret) {
            log::error!("{}: failed to reset event callback: {}", self.name, err);
        }

        let _ = registry.deregister(&mut self.rx_notifier);
    }

    fn activate<'m, Q, S, E>(
        &mut self,
        _feature: u128,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let registry = active_mio.poll.registry();
        registry.register(&mut self.rx_notifier, Token(0), Interest::READABLE)?;

        let interface = self.interface.load(Ordering::Acquire);
        let dispatch_queue = self.dispatch_queue.load(Ordering::Acquire);

        #[repr(C)]
        struct CallbackBlock {
            block: VmnetInterfaceEventCallback,
            notifier: *const Notifier,
        }

        extern "C" fn callback_invoke(this: *mut c_void, _: InterfaceEvent, _: *const XpcObject) {
            let this = unsafe { &*(this as *mut CallbackBlock) };
            let notifier = unsafe { &*this.notifier };

            if let Err(e) = notifier.notify() {
                log::error!("Failed to notify: {e:?}");
            }
        }

        static BLOCK_DESC: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: size_of::<CallbackBlock>() as _,
        };
        let callback = CallbackBlock {
            block: VmnetInterfaceEventCallback {
                isa: unsafe { _NSConcreteStackBlock },
                flags: BlockFlag::HAS_STRET,
                reserved: 0,
                invoke: callback_invoke,
                descriptor: &BLOCK_DESC as *const _,
            },
            notifier: &self.rx_notifier as *const Notifier,
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
        let token = event.token().0;
        let irq_sender = active_mio.irq_sender;
        if event.is_readable() {
            let index = (token as u16) << 1;
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
            queue.handle_desc(index, irq_sender, write_to_vmnet(interface))
        }
    }
}

fn read_from_vmnet(interface: *mut VmnetInterface) -> impl FnMut(&mut DescChain) -> Result<Status> {
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
            vm_pkt_iov: iov.as_mut_ptr(),
            vm_pkt_iovcnt: iov.len() as u32,
            vm_flags: 0,
        };
        let mut pktcnt = 1;
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

        Ok(Status::Done {
            len: (packets.vm_pkt_size + size_of::<VirtioNetHdr>()) as u32,
        })
    }
}

fn write_to_vmnet(interface: *mut VmnetInterface) -> impl FnMut(&mut DescChain) -> Result<Status> {
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

        if pktcnt == 0 {
            return Ok(Status::Break);
        }
        Ok(Status::Done { len: 0 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct NetVmnetParam {
    /// MAC address of the virtual NIC, e.g. 06:3a:76:53:da:3d.
    pub mac: Option<MacAddr>,
}

impl DevParam for NetVmnetParam {
    type Device = Net;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        Net::new(self, name)
    }
}
