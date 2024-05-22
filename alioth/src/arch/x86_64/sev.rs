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

use bitfield::bitfield;
use serde::{Deserialize, Serialize};

bitfield! {
    #[derive(Copy, Clone, Serialize, Deserialize)]
    pub struct Policy(u32);
    impl Debug;
    pub no_debug, set_no_debug: 0;
    pub no_ks, set_no_ks: 1;
    pub es, set_es: 2;
    pub no_send, set_no_send: 3;
    pub domain, set_domain: 4;
    pub sev, set_sev: 5;
    pub api_major, set_api_major: 16,23;
    pub api_minor, set_api_minor: 24,31;
}
