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
#[path = "xpc_test.rs"]
mod tests;

use libc::{c_char, c_void};

#[repr(transparent)]
pub struct XpcObject(c_void);

unsafe extern "C" {
    pub fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const *const XpcObject,
        count: usize,
    ) -> *mut XpcObject;
    pub fn xpc_release(object: *mut XpcObject);

    pub fn xpc_uint64_create(value: u64) -> *mut XpcObject;
    pub fn xpc_bool_create(value: bool) -> *mut XpcObject;

    pub fn xpc_dictionary_get_uint64(xdict: *const XpcObject, key: *const c_char) -> u64;
    pub fn xpc_dictionary_get_string(xdict: *const XpcObject, key: *const c_char) -> *const c_char;
}
