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

pub mod endian;
#[cfg(target_os = "linux")]
pub mod uds;

use std::sync::atomic::{AtomicU64, Ordering};

pub fn truncate_u64(val: u64, size: u64) -> u64 {
    val & (u64::MAX >> (64 - (size << 3)))
}

#[macro_export]
macro_rules! align_up {
    ($num:expr, $bits:expr) => {{
        let mask = (1 << $bits) - 1;
        ($num.wrapping_add(mask)) & !mask
    }};
}

#[macro_export]
macro_rules! align_up_ty {
    ($num:expr, $ty:ty) => {{
        let mask = ::core::mem::align_of::<$ty>() - 1;
        ($num.wrapping_add(mask)) & !mask
    }};
}

#[macro_export]
macro_rules! align_down {
    ($num:expr, $bits:expr) => {{
        let mask = (1 << $bits) - 1;
        $num & !mask
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

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn wrapping_sum<'a, T>(data: T) -> u8
where
    T: IntoIterator<Item = &'a u8>,
{
    data.into_iter().fold(0u8, |accu, e| accu.wrapping_add(*e))
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
    ($f:expr, $failure:expr) => {{
        let ret = $f;
        if ret == $failure {
            Err(::std::io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }};
}

#[macro_export]
macro_rules! c_enum {
    (
        $(#[$attr:meta])*
        $vs:vis struct $EnumName:ident($TyName:ty);
        {
            $( $(#[$vattr:meta])* $VARIANT:ident = $value:expr;)*
        }
    ) => {
        #[repr(transparent)]
        #[derive(PartialEq, Eq, Copy, Clone)]
        $(#[$attr])*
        $vs struct $EnumName($TyName);

        impl $EnumName {
            $($(#[$vattr])* pub const $VARIANT: $EnumName = $EnumName($value);)*

            #[allow(dead_code)]
            pub const fn raw(self) -> $TyName {
                self.0
            }
        }

        impl ::core::fmt::Debug for $EnumName {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(stringify!($EnumName))?;
                match *self {
                    $($EnumName::$VARIANT => {
                        f.write_str("::")?;
                        f.write_str(stringify!($VARIANT))
                    })*
                    _ => {
                        ::core::fmt::Write::write_char(f, '(')?;
                        ::core::fmt::Debug::fmt(&self.0, f)?;
                        ::core::fmt::Write::write_char(f, ')')
                    }
                }
            }
        }


        impl From<$EnumName> for $TyName {
            fn from(value: $EnumName) -> Self {
                value.0
            }
        }

        impl From<$TyName> for $EnumName {
            fn from(value: $TyName) -> Self {
                $EnumName(value)
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_align_up() {
        assert_eq!(align_up!(0u64, 2), 0);
        assert_eq!(align_up!(1u64, 2), 4);
        assert_eq!(align_up!(3u64, 2), 4);

        assert_eq!(align_up!(u64::MAX, 0), u64::MAX);
        assert_eq!(align_up!(u64::MAX, 2), 0);
    }
}
