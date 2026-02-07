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

use crate::consts;

consts! {
    pub struct DeliveryMode(u8) {
        FIXED = 0b000;
        LOW_PRIORITY = 0b001;
        SMI = 0b010;
        NMI = 0b100;
        INIT = 0b101;
        STARTUP_IPI = 0b110;
        EXTINT = 0b111;
    }
}

consts! {
    pub struct TriggerMode(bool) {
        EDGE = false;
        LEVEL = true;
    }
}

consts! {
    pub struct DestinationMode(bool) {
        PHYSICAL = false;
        LOGICAL = true;
    }
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct MsiAddrLo(u32);
    impl Debug;
    pub mode, set_mode : 2;
    pub redirection, set_redirection : 3;
    pub remappable, set_remappable : 4;
    pub u8, virt_dest_id_hi, set_virt_dest_id_hi : 11, 5;
    pub u8, dest_id, set_dest_id : 19, 12;
    pub identifier, _: 31, 20;
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct MsiAddrHi(u32);
    impl Debug;
    pub dest_id_hi, set_dest_id_hi : 31, 8;
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct MsiData(u32);
    impl Debug;
    impl new;
    pub u8, vector, set_vector : 7, 0;
    pub u8, from into DeliveryMode, delivery_mode, set_delivery_mode : 11, 8;
    pub u8, level, set_level : 14;
    pub trigger_mode, set_trigger_mode : 15;
}
