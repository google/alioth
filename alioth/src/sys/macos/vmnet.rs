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

use libc::{c_char, c_void, iovec};

use crate::c_enum;
use crate::sys::block::Block;
use crate::sys::dispatch::DispatchQueue;
use crate::sys::xpc::XpcObject;

c_enum! {
    pub struct VmnetReturn(u32);
    {
        SUCCESS = 1000;
        FAILURE = 1001;
        MEM_FAILURE = 1002;
        INVALID_ARGUMENT = 1003;
        SETUP_INCOMPLETE = 1004;
        INVALID_ACCESS = 1005;
        PACKET_TOO_BIG = 1006;
        BUFFER_EXHAUSTED = 1007;
        TOO_MANY_PACKETS = 1008;
        SHARING_SERVICE_BUSY = 1009;
        NOT_AUTHORIZED = 1010;
    }
}

c_enum! {
    pub struct OperationMode(u32);
    {
        HOST = 1000;
        SHARED = 1001;
        BRIDGED = 1002;
    }
}

c_enum! {
    pub struct InterfaceEvent(u32);
    {
        PACKETS_AVAILABLE = 1 << 0;
    }
}

#[repr(transparent)]
pub struct VmnetInterface(c_void);

#[repr(transparent)]
pub struct VmnetNetworkConfiguration(c_void);

pub type VmnetInterfaceCompletionHandler =
    Block<extern "C" fn(*mut c_void, VmnetReturn, *const XpcObject)>;

pub type VmnetInterfaceEventCallback =
    Block<extern "C" fn(*mut c_void, InterfaceEvent, *const XpcObject)>;

#[repr(C)]
#[derive(Debug)]
pub struct VmPktDesc {
    pub vm_pkt_size: usize,
    pub vm_pkt_iov: *mut iovec,
    pub vm_pkt_iovcnt: u32,
    pub vm_flags: u32,
}

#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {
    pub static vmnet_operation_mode_key: *const c_char;
    pub static vmnet_interface_id_key: *const c_char;
    pub static vmnet_mac_address_key: *const c_char;
    pub static vmnet_mtu_key: *const c_char;
    pub static vmnet_max_packet_size_key: *const c_char;
    pub static vmnet_allocate_mac_address_key: *const c_char;
    pub static vmnet_enable_isolation_key: *const c_char;

    pub fn vmnet_start_interface(
        interface_desc: *const XpcObject,
        queue: *const DispatchQueue,
        handler: *const VmnetInterfaceCompletionHandler,
    ) -> *mut VmnetInterface;

    pub fn vmnet_stop_interface(
        interface: *mut VmnetInterface,
        queue: *const DispatchQueue,
        handler: *const VmnetInterfaceCompletionHandler,
    );

    pub fn vmnet_interface_set_event_callback(
        interface: *mut VmnetInterface,
        event_mask: InterfaceEvent,
        queue: *const DispatchQueue,
        callback: *const VmnetInterfaceEventCallback,
    ) -> VmnetReturn;

    pub fn vmnet_read(
        interface: *mut VmnetInterface,
        packets: *mut VmPktDesc,
        pktcnt: *mut i32,
    ) -> VmnetReturn;

    pub fn vmnet_write(
        interface: *mut VmnetInterface,
        packets: *mut VmPktDesc,
        pktcnt: *mut i32,
    ) -> VmnetReturn;

    pub fn vmnet_network_configuration_create(
        mode: OperationMode,
        status: *mut VmnetReturn,
    ) -> *mut VmnetNetworkConfiguration;
}
