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

use super::{
    XpcObject, xpc_dictionary_create, xpc_dictionary_get_uint64, xpc_release, xpc_uint64_create,
};

#[test]
fn test_xpc_create() {
    let key = c"key".as_ptr();
    let val: *mut XpcObject;
    let dict: *mut XpcObject;
    let num;
    unsafe {
        val = xpc_uint64_create(123);
        dict = xpc_dictionary_create(&key, &(val as *const XpcObject), 1);
        num = xpc_dictionary_get_uint64(dict, key);
    }
    assert_eq!(num, 123);
    unsafe {
        xpc_release(val);
        xpc_release(dict);
    }
}
