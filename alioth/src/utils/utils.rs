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
