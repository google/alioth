// Copyright 2026 Google LLC
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

use crate::arch::intr::DeliveryMode;

pub const IOREGSEL: u64 = 0x00;
pub const IOWIN: u64 = 0x10;

pub const IOAPICID: u8 = 0x00;
pub const IOAPICVER: u8 = 0x01;
pub const IOAPICARB: u8 = 0x02;
pub const IOREDTBL_BASE: u8 = 0x10;
pub const IOREDTBL_MAX: u8 = 0x3f;

pub const NUM_PINS: u8 = 24;

pub const IOAPIC_VER: u8 = 0x11;

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct RegId(u32);
    impl Debug;
    impl new;
    pub u8, id, set_id : 27, 24;
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct RegVer(u32);
    impl Debug;
    impl new;
    pub u8, version, set_version : 7, 0;
    pub u8, max_entry, set_max_entry : 23, 16;
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct RedirectEntry(u64);
    impl Debug;
    pub u8,	vector, set_vector : 7, 0;
    pub u8, from into DeliveryMode, delivery_mode, set_delivery_mode : 10, 8;
    pub dest_mode, set_dest_mode : 11;
    pub delivery_status, set_delivery_status : 12;
    pub riority, set_priority : 13;
    pub irr, set_irr : 14;
    pub trigger_mode, set_trigger_mode : 15;
    pub masked, set_masked : 16;
    pub u8, virt_dest_id_hi, set_virt_dest_id_hi : 55, 49;
    pub u8, dest_id, set_dest_id : 63, 56;
}
