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

//! Non-blocking `#![no_std]` spinlocks (`Mutex` and `RwLock`) for `vmm-core`.
//!
//! All critical sections inside `vmm-core` are short, bounded device-state updates
//! (`IoApic`, `Serial`, `PciBus`, `VirtioPciDevice`, `Memory`) that never block on I/O,
//! making spinlocks safe for Motor OS Ring 0, Linux Kernel Ring 0, and Ring 3 Wasm.

use core::cell::UnsafeCell;
use core::fmt::{self, Debug, Formatter};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

pub struct Mutex<T: ?Sized> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(val: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(val),
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> Mutex<T> {
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        while self
            .state
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.state.load(Ordering::Relaxed) != 0 {
                core::hint::spin_loop();
            }
        }
        MutexGuard { lock: self }
    }
}

impl<T: ?Sized + Debug> Debug for Mutex<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let guard = self.lock();
        f.debug_tuple("Mutex").field(&&*guard).finish()
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
    }
}

const WRITER_BIT: u32 = 1 << 31;

pub struct RwLock<T: ?Sized> {
    /// Bits `0..31`: active reader count. Bit `31` (`WRITER_BIT`): exclusive writer active/waiting.
    state: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    pub const fn new(val: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(val),
        }
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> RwLock<T> {
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let mut cur = self.state.load(Ordering::Relaxed);
        loop {
            if (cur & WRITER_BIT) != 0 {
                core::hint::spin_loop();
                cur = self.state.load(Ordering::Relaxed);
                continue;
            }
            match self.state.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return RwLockReadGuard { lock: self },
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        // Claim WRITER_BIT first so new readers wait behind the writer.
        loop {
            let cur = self.state.load(Ordering::Relaxed);
            if (cur & WRITER_BIT) == 0
                && self
                    .state
                    .compare_exchange_weak(
                        cur,
                        cur | WRITER_BIT,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
        // Wait for any existing readers to drain.
        while self.state.load(Ordering::Acquire) != WRITER_BIT {
            core::hint::spin_loop();
        }
        RwLockWriteGuard { lock: self }
    }
}

impl<T: ?Sized + Debug> Debug for RwLock<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let guard = self.read();
        f.debug_tuple("RwLock").field(&&*guard).finish()
    }
}

pub struct RwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

pub struct RwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
    }
}
