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

use parking_lot::{Condvar, Mutex};

use crate::hv::{IrqSender, Result};

#[derive(Debug)]
pub struct TestIrqSender {
    pub count: Mutex<u8>,
    pub condvar: Condvar,
}

impl TestIrqSender {
    pub fn new() -> Self {
        Self {
            count: Mutex::new(0),
            condvar: Condvar::new(),
        }
    }
}

impl IrqSender for TestIrqSender {
    fn send(&self) -> Result<()> {
        let mut count = self.count.lock();
        *count += 1;
        self.condvar.notify_one();
        Ok(())
    }
}
