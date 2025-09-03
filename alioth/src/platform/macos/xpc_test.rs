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

use std::ffi::c_char;

use crate::platform::xpc::{
    XpcObject, xpc_dictionary_create, xpc_dictionary_get_uint64, xpc_uint64_create,
};

#[test]
fn test_xpc_create() {
    unsafe {
        let v1 = xpc_uint64_create(123) as *const XpcObject;
        let key = b"key".as_ptr() as *const c_char;
        let dict = xpc_dictionary_create(&key, &v1, 1);
        let v = xpc_dictionary_get_uint64(dict, key);
        assert_eq!(v, 123);
    }
}
