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

use serde::de::{self, Visitor};
use serde::Deserialize;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes, PartialEq, Eq)]
#[repr(transparent)]
pub struct MacAddr([u8; 6]);

struct MacAddrVisitor;

impl<'de> Visitor<'de> for MacAddrVisitor {
    type Value = MacAddr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a MAC address like ea:d7:a8:e8:c6:2f")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut addr = [0u8; 6];
        let iter = v.split(':');
        let mut index = 0;
        for b_s in iter {
            let Some(b) = addr.get_mut(index) else {
                return Err(E::custom("expect 6 bytes"));
            };
            let Ok(v) = u8::from_str_radix(b_s, 16) else {
                return Err(E::custom("expect bytes"));
            };
            *b = v;
            index += 1;
        }
        if index != 6 {
            return Err(E::custom("expect 6 bytes"));
        }
        Ok(MacAddr(addr))
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(MacAddrVisitor)
    }
}

#[cfg(test)]
mod test {
    use serde::de::value::Error;
    use serde::de::Visitor;

    use crate::net::MacAddr;

    use super::MacAddrVisitor;

    #[test]
    fn test_mac_addr_visitor() {
        assert_eq!(
            MacAddrVisitor.visit_borrowed_str::<Error>("ea:d7:a8:e8:c6:2f"),
            Ok(MacAddr([0xea, 0xd7, 0xa8, 0xe8, 0xc6, 0x2f]))
        );
        assert!(MacAddrVisitor
            .visit_borrowed_str::<Error>("ea:d7:a8:e8:c6")
            .is_err());
        assert!(MacAddrVisitor
            .visit_borrowed_str::<Error>("ea:d7:a8:e8:c6:ac:ac")
            .is_err());
        assert!(MacAddrVisitor
            .visit_borrowed_str::<Error>("ea:d7:a8:e8:c6:2g")
            .is_err());
    }
}
