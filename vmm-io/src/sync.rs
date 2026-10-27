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

use std::sync as std_sync;

pub type MutexGuard<'a, T> = std_sync::MutexGuard<'a, T>;
pub type RwLockReadGuard<'a, T> = std_sync::RwLockReadGuard<'a, T>;
pub type RwLockWriteGuard<'a, T> = std_sync::RwLockWriteGuard<'a, T>;

#[derive(Debug, Default)]
pub struct Mutex<T: ?Sized>(std_sync::Mutex<T>);

impl<T> Mutex<T> {
    pub const fn new(val: T) -> Self {
        Self(std_sync::Mutex::new(val))
    }
}

impl<T: ?Sized> Mutex<T> {
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Debug, Default)]
pub struct RwLock<T: ?Sized>(std_sync::RwLock<T>);

impl<T> RwLock<T> {
    pub const fn new(val: T) -> Self {
        Self(std_sync::RwLock::new(val))
    }
}

impl<T: ?Sized> RwLock<T> {
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Debug, Default)]
pub struct Condvar(std_sync::Condvar);

impl Condvar {
    pub const fn new() -> Self {
        Self(std_sync::Condvar::new())
    }

    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        self.0.wait(guard).unwrap_or_else(|e| e.into_inner())
    }

    pub fn notify_all(&self) {
        self.0.notify_all();
    }
}
