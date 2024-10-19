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

macro_rules! endian_impl {
    ($ne_type:ident, $ed_type:ident, $endian:expr, $opposite:expr) => {
        #[repr(transparent)]
        #[derive(
            ::zerocopy::Immutable, ::zerocopy::IntoBytes, ::zerocopy::FromBytes, Copy, Clone,
        )]
        pub struct $ed_type {
            v: $ne_type,
        }

        impl $ed_type {
            pub fn to_ne(self) -> $ne_type {
                #[cfg(target_endian = $endian)]
                {
                    self.v
                }
                #[cfg(target_endian = $opposite)]
                {
                    self.v.swap_bytes()
                }
            }
        }

        impl From<$ne_type> for $ed_type {
            fn from(value: $ne_type) -> Self {
                #[cfg(target_endian = $endian)]
                {
                    Self { v: value }
                }
                #[cfg(target_endian = $opposite)]
                {
                    Self {
                        v: value.swap_bytes(),
                    }
                }
            }
        }

        impl From<$ed_type> for $ne_type {
            fn from(value: $ed_type) -> Self {
                #[cfg(target_endian = $endian)]
                {
                    value.v
                }
                #[cfg(target_endian = $opposite)]
                {
                    value.v.swap_bytes()
                }
            }
        }

        impl ::core::fmt::Display for $ed_type {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #[cfg(target_endian = $endian)]
                {
                    ::core::fmt::Display::fmt(&self.v, f)
                }
                #[cfg(target_endian = $opposite)]
                {
                    ::core::fmt::Display::fmt(&self.v.swap_bytes(), f)
                }
            }
        }

        impl ::core::fmt::Debug for $ed_type {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(stringify!($ed_type))?;
                ::core::fmt::Write::write_char(f, '(')?;
                ::core::fmt::Debug::fmt(&self.to_ne(), f)?;
                ::core::fmt::Write::write_char(f, ')')
            }
        }

        impl From<[u8; ::core::mem::size_of::<$ne_type>()]> for $ed_type {
            fn from(value: [u8; ::core::mem::size_of::<$ne_type>()]) -> Self {
                Self {
                    v: $ne_type::from_ne_bytes(value),
                }
            }
        }
    };
}

macro_rules! endian_type {
    ($ne_type:ident, $le_type:ident, $be_type:ident) => {
        endian_impl!($ne_type, $le_type, "little", "big");
        endian_impl!($ne_type, $be_type, "big", "little");
    };
}

endian_type!(u32, Lu32, Bu32);
endian_type!(u64, Lu64, Bu64);
