// Copyright 2024 Google LLC
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

use crate::bitflags;

bitflags! {
    pub struct Entry(u32) {
        /// Present
        P = 1 << 0;
        /// Read/write
        RW = 1 << 1;
        /// User/supervisor
        US = 1 << 2;
        /// Page-level write-through
        PWT = 1 << 3;
        /// Page-level cache disable
        PCD = 1 << 4;
        /// Accessed
        A = 1 << 5;
        /// Dirty
        D = 1 << 6;
        /// Page size
        PS = 1 << 7;
        /// Global
        G = 1 << 8;
    }
}
