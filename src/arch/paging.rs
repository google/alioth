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

use bitflags::bitflags;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Entry: u32 {
        /// Present
        const P = 1 << 0;
        /// Read/write
        const RW = 1 << 1;
        /// User/supervisor
        const US = 1 << 2;
        /// Page-level write-through
        const PWT = 1 << 3;
        /// Page-level cache disable
        const PCD = 1 << 4;
        /// Accessed
        const A = 1 << 5;
        /// Dirty
        const D = 1 << 6;
        /// Page size
        const PS = 1 << 7;
        /// Global
        const G = 1 << 8;
    }
}
