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

use zerocopy::IntoBytes;

use crate::utils::endian::{Bu64, Lu32};

#[test]
fn test_little_endian() {
    let val = 0x12345678u32;
    let le_val = Lu32::from(val);
    assert_eq!(le_val.to_ne(), val);
    assert_eq!(u32::from(le_val), val);
    assert_eq!(format!("{le_val}"), format!("{val}"));
    assert_eq!(format!("{le_val:?}"), format!("Lu32({val})"));
    #[cfg(target_endian = "little")]
    assert_eq!(le_val.v, val);
    #[cfg(target_endian = "big")]
    assert_eq!(le_val.v, val.swap_bytes());

    let bytes = val.to_ne_bytes();
    let le_val = Lu32::from(bytes);
    assert_eq!(le_val.as_bytes(), bytes);
}

#[test]
fn test_big_endian() {
    let val = 0x1234567890abcdefu64;
    let be_val = Bu64::from(val);
    assert_eq!(be_val.to_ne(), val);
    assert_eq!(u64::from(be_val), val);
    assert_eq!(format!("{be_val}"), format!("{val}"));
    assert_eq!(format!("{be_val:?}"), format!("Bu64({val})"));
    #[cfg(target_endian = "little")]
    assert_eq!(be_val.v, val.swap_bytes());
    #[cfg(target_endian = "big")]
    assert_eq!(be_val.v, val);

    let bytes = val.to_ne_bytes();
    let be_val = Bu64::from(bytes);
    assert_eq!(be_val.as_bytes(), bytes);
}
