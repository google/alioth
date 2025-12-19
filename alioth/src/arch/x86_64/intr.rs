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

use bitfield::bitfield;

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct MsiAddrLo(u32);
    impl Debug;
    pub mode, set_mode : 2;
    pub redirection, set_redirection : 3;
    pub remappable, set_remappable : 4;
    pub reserved, set_reserved : 11, 5;
    pub dest_id, set_dest_id : 19, 12;
    pub identifier, _: 31, 20;
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct MsiAddrHi(u32);
    impl Debug;
    pub dest_id, set_dest_id : 31, 8;
}
