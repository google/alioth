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

use std::ffi::{c_char, c_void};

use libc::iovec;

use crate::c_enum;
use crate::platform::dispatch::DispatchQueue;
use crate::platform::xpc::XpcObject;

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

#[repr(transparent)]
pub struct VmnetInterface(c_void);

#[repr(transparent)]
pub struct VmnetNetworkConfiguration(c_void);

pub type VmnetInterfaceCompletionHandler = extern "C" fn(VmnetReturn, *const XpcObject);

#[repr(C)]
#[derive(Debug)]
pub struct VmPktDesc {
    vm_pkt_size: usize,
    vm_pkt_iov: *mut iovec,
    vm_pkt_iovcnt: u32,
    vm_flags: u32,
}

#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {
    pub static vmnet_operation_mode_key: *const c_char;
    pub static vmnet_interface_id_key: *const c_char;

    pub fn vmnet_start_interface(
        interface: *const XpcObject,
        queue: *const DispatchQueue,
        handler: VmnetInterfaceCompletionHandler,
    ) -> *mut VmnetInterface;

    pub fn vmnet_stop_interface(
        interface: *mut VmnetInterface,
        queue: *const DispatchQueue,
        handler: VmnetInterfaceCompletionHandler,
    );

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
