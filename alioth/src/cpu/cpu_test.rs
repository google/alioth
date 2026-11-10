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

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use assert_matches::assert_matches;
use parking_lot::{Condvar, Mutex};

use crate::cpu::{Error, MpSync, State, barrier};

fn fixture_sync() -> Arc<(Mutex<MpSync>, Condvar)> {
    let sync = MpSync {
        state: State::Running,
        fatal: false,
        count: 0,
        generation: 0,
    };
    Arc::new((Mutex::new(sync), Condvar::new()))
}

/// Spawns `n` threads waiting at the barrier for `count` vCPUs, and returns
/// after all of them wait.
fn spawn_waiters(
    sync: &Arc<(Mutex<MpSync>, Condvar)>,
    n: u16,
    count: u16,
) -> Vec<thread::JoinHandle<Result<(), Error>>> {
    let handles = (0..n)
        .map(|_| {
            let sync = sync.clone();
            thread::spawn(move || barrier(&sync.0, &sync.1, count))
        })
        .collect();
    while sync.0.lock().count < n {
        thread::yield_now();
    }
    handles
}

#[test]
fn test_barrier() {
    let sync = fixture_sync();

    // The barrier is reusable.
    for _ in 0..2 {
        let waiters = spawn_waiters(&sync, 2, 3);

        // A notification for a state change does not release the waiters.
        sync.1.notify_all();
        thread::sleep(Duration::from_millis(100));
        assert!(waiters.iter().all(|w| !w.is_finished()));

        // The last vCPU releases them.
        barrier(&sync.0, &sync.1, 3).unwrap();
        for waiter in waiters {
            waiter.join().unwrap().unwrap();
        }
    }
}

#[test]
fn test_barrier_fatal() {
    let sync = fixture_sync();
    let waiters = spawn_waiters(&sync, 2, 3);

    sync.0.lock().fatal = true;
    sync.1.notify_all();

    for waiter in waiters {
        assert_matches!(waiter.join().unwrap(), Err(Error::PeerFailure { .. }));
    }
    assert_matches!(barrier(&sync.0, &sync.1, 3), Err(Error::PeerFailure { .. }));
}
