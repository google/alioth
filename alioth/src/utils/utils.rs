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

use std::sync::atomic::{AtomicU64, Ordering};

pub mod ioctls;

#[macro_export]
macro_rules! align_up {
    ($num:expr, $align:expr) => {{
        debug_assert_eq!(($align as u64).count_ones(), 1);
        let mask = $align - 1;
        ($num.wrapping_add(mask)) & !mask
    }};
}

#[macro_export]
macro_rules! assign_bits {
    ($dst:expr, $src:expr, $mask:expr) => {
        $dst = ($dst & !$mask) | ($src & $mask)
    };
}

#[macro_export]
macro_rules! mask_bits {
    ($dst:expr, $src:expr, $mask:expr) => {
        ($dst & !$mask) | ($src & $mask)
    };
}

pub fn get_low32(num: u64) -> u32 {
    num as u32
}

pub fn get_high32(num: u64) -> u32 {
    (num >> 32) as u32
}

pub fn get_atomic_low32(num: &AtomicU64) -> u32 {
    num.load(Ordering::Acquire) as u32
}

pub fn get_atomic_high32(num: &AtomicU64) -> u32 {
    (num.load(Ordering::Acquire) >> 32) as u32
}

pub fn set_low32(num: &mut u64, val: u32) {
    *num &= !0xffff_ffff;
    *num |= val as u64;
}

pub fn set_high32(num: &mut u64, val: u32) {
    *num &= 0xffff_ffff;
    *num |= (val as u64) << 32;
}

pub fn set_atomic_low32(num: &AtomicU64, val: u32) {
    let mut cur = num.load(Ordering::Acquire);
    set_low32(&mut cur, val);
    num.store(cur, Ordering::Release)
}

pub fn set_atomic_high32(num: &AtomicU64, val: u32) {
    let mut cur = num.load(Ordering::Acquire);
    set_high32(&mut cur, val);
    num.store(cur, Ordering::Release)
}

#[macro_export]
macro_rules! ffi {
    ($f:expr) => {{
        let ret = $f;
        if ret <= -1 {
            Err(::std::io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }};
    ($f:expr, $failure:ident) => {{
        let ret = $f;
        if ret == $failure {
            Err(::std::io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }};
}

#[macro_export]
macro_rules! unsafe_impl_zerocopy {
    ($ty:ty, $($name:ident), +) => {
         $(
            unsafe impl ::zerocopy::$name for $ty {
                fn only_derive_is_allowed_to_implement_this_trait()
                where
                    Self: Sized,
                {
                }
            }
         )+
    };
}

#[cfg(test)]
mod test {
    #[test]
    fn test_align_up() {
        assert_eq!(align_up!(0u64, 4), 0);
        assert_eq!(align_up!(1u64, 4), 4);
        assert_eq!(align_up!(3u64, 4), 4);

        assert_eq!(align_up!(u64::MAX, 1), u64::MAX);
        assert_eq!(align_up!(u64::MAX, 4), 0);
    }

    #[test]
    #[should_panic]
    fn test_align_up_panic() {
        let _ = align_up!(1u64, 3);
    }
}
