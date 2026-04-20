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

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use mio::Token;
use parking_lot::Mutex;

use crate::device::Result;
use crate::device::console::Console;
use crate::sync::notifier::Notifier;

#[derive(Debug)]
pub struct TestConsole {
    pub notifier: Mutex<Notifier>,
    pub inbound: Mutex<VecDeque<u8>>,
    pub outbound: Mutex<VecDeque<u8>>,
}

impl TestConsole {
    pub fn new() -> Result<Self> {
        Ok(Self {
            notifier: Mutex::new(Notifier::new()?),
            inbound: Mutex::new(VecDeque::new()),
            outbound: Mutex::new(VecDeque::new()),
        })
    }
}

impl Read for &TestConsole {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(&mut *self.inbound.lock(), buf)
    }
}

impl Write for &TestConsole {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(&mut *self.outbound.lock(), buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut *self.outbound.lock())
    }
}

impl Console for TestConsole {
    const TOKEN_INPUT: Token = Token(0);

    fn activate(&self, registry: &mio::Registry) -> io::Result<()> {
        registry.register(
            &mut *self.notifier.lock(),
            Self::TOKEN_INPUT,
            mio::Interest::READABLE,
        )
    }

    fn deactivate(&self, registry: &mio::Registry) -> io::Result<()> {
        registry.deregister(&mut *self.notifier.lock())
    }
}
