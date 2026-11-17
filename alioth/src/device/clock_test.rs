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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jiff::Timestamp;

use crate::device::clock::{Clock, SystemClock};

#[derive(Debug)]
pub struct TestClock {
    pub now: Timestamp,
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.now.as_nanosecond() as u64)
    }
}

impl TestClock {
    pub fn tick(&mut self) {
        self.now += Duration::from_secs(1);
    }
}

#[test]
fn test_system_clock() {
    let now = SystemClock.now();
    let sys_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let diff = sys_now - now;
    assert!(diff.as_secs() < 1);
}
