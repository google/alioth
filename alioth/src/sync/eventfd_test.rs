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

use mio::{Events, Interest, Poll, Token};

use crate::sync::eventfd::EventFd;

#[test]
fn test_eventfd() {
    let mut fd = EventFd::new().unwrap();

    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut fd, Token(1), Interest::READABLE)
        .unwrap();

    fd.trigger().unwrap();

    let mut events = Events::with_capacity(1);
    poll.poll(&mut events, None).unwrap();

    let event = events.iter().next().unwrap();
    assert_eq!(event.token(), Token(1));
}
