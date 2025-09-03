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

use std::ffi::{c_char, c_void};

use crate::c_enum;
use crate::platform::macos::dispatch::DispatchQueue;
use crate::platform::macos::xpc::XpcObject;

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

pub type VmnetInterface = c_void;
pub type VmnetInterfaceCompletionHandler = extern "C" fn(VmnetReturn, *const XpcObject);

#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {

    pub static vmnet_operation_mode_key: *const c_char;
    pub static vmnet_interface_id_key: *const c_char;

    pub fn vmnet_start_interface(
        interface_desc: &mut XpcObject,
        queue: &mut DispatchQueue,
        handler: VmnetInterfaceCompletionHandler,
    ) -> *mut VmnetInterface;

    pub fn vmnet_stop_interface(
        interface_ref: &mut VmnetInterface,
        queue: &mut DispatchQueue,
        handler: VmnetInterfaceCompletionHandler,
    );
}
