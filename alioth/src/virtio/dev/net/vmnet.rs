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
use std::io::{ErrorKind, IoSlice};
use std::mem::MaybeUninit;
use std::num::NonZeroU16;
use std::os::fd::{AsFd, AsRawFd};
use std::os::raw::c_void;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::null;
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
use crate::platform::dispatch::dispatch_queue_create;
use crate::platform::vmnet::{
    OperationMode, VmnetInterfaceCompletionHandler, VmnetReturn, vmnet_mac_address_key,
    vmnet_mtu_key, vmnet_operation_mode_key, vmnet_start_interface,
};
use crate::platform::xpc::{
    XpcObject, xpc_dictionary_create, xpc_dictionary_get_string, xpc_dictionary_get_uint64,
    xpc_uint64_create,
};
// use crate::platform::if_tun::{TunFeature, tun_set_iff, tun_set_offload, tun_set_vnet_hdr_sz};
use crate::virtio::dev::net::{
    CtrlAck, CtrlClass, CtrlHdr, CtrlMq, CtrlMqParisSet, NetConfig, NetFeature,
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
}

#[derive(Debug, Deserialize, Clone, Help)]
pub struct NetVmnetParam {
    /// MAC address of the virtual NIC, e.g. 06:3a:76:53:da:3d.
    pub mac: MacAddr,
    /// Maximum transmission unit.
    pub mtu: u16,
    /// Number of pairs of transmit/receive queues. [default: 1]
    #[serde(alias = "qp")]
    pub queue_pairs: Option<NonZeroU16>,
    /// Path to the character device file of a tap interface.
    ///
    /// Required for MacVTap and IPVTap, e.g. /dev/tapX.
    /// Optional for TUN/TAP. [default: /dev/net/tun]
    pub tap: Option<PathBuf>,
    /// Name of a tap interface, e.g. tapX.
    ///
    /// Required for TUN/TAP. Optional for MacVTap and IPVTap.
    #[serde(alias = "if")]
    pub if_name: Option<String>,
    /// System API for asynchronous IO.
    #[serde(default)]
    pub api: WorkerApi,
}

#[repr(C)]
struct StartBlock {
    block: VmnetInterfaceCompletionHandler,
    sender: Sender<Result<NetConfig>>,
}

extern "C" fn start_callback(this: *mut c_void, ret: VmnetReturn, obj: *const XpcObject) {
    let this = unsafe { &*(this as *mut StartBlock) };

    if ret != VmnetReturn::SUCCESS {
        println!("failed to create vmnet: {ret:x?}");
        this.sender.send(error::InvalidBuffer.fail()).unwrap();
        return;
    }
    println!("vmnet created successfully");
    let config = NetConfig::default();
    if let Err(e) = this.sender.send(Ok(config)) {
        println!("failed to send config: {e}");
    }
    let mtu = unsafe { xpc_dictionary_get_uint64(obj, vmnet_mtu_key) };
    let mac = unsafe { xpc_dictionary_get_string(obj, vmnet_mac_address_key) };
    let mac = unsafe { CStr::from_ptr(mac) };
    println!("config sent succesfuly, {mtu} {mac:?}");
}

// static BLOCK_DESC: BlockDescriptor = BlockDescriptor {
//     reserved: 0,
//     size: size_of::<StartBlock>() as _,
//     copy_helper: None,
//     dispose_helper: None,
//     signature: null(),
// };

impl Net {
    // param: NetVmnetParam, name: impl Into<Arc<str>>
    pub fn new() -> Result<Self> {
        println!("will call xpc_uint64_create");
        let mode = unsafe { xpc_uint64_create(OperationMode::SHARED.raw() as u64) } as *const _;
        println!("{mode:x?} will call xpc_dictionary_create");
        let desc = unsafe { xpc_dictionary_create(&vmnet_operation_mode_key, &mode, 1) };
        println!("desc = {desc:x?} will call dispatch_queue_create");
        let dispatch_queue = unsafe { dispatch_queue_create(c"virtio-net".as_ptr(), null()) };
        println!("will call mpsc::channel");
        let (sender, receiver) = mpsc::channel();
        let block_desc = BlockDescriptor {
            reserved: 0,
            size: size_of::<StartBlock>() as _,
            copy_helper: None,
            dispose_helper: None,
            signature: null(),
        };
        let handler = StartBlock {
            block: VmnetInterfaceCompletionHandler {
                isa: unsafe { _NSConcreteStackBlock },
                flags: 1 << 29,
                reserved: 0,
                invoke: start_callback,
                descriptor: &block_desc as *const _,
            },
            sender,
        };
        println!("will call vmnet_start_interface");
        unsafe { vmnet_start_interface(desc, dispatch_queue, &handler.block) };
        let r = receiver.recv_timeout(Duration::from_secs(5));
        println!("{r:x?}");
        error::InvalidBuffer.fail()
    }
}
