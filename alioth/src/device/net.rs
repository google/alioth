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

use std::str::FromStr;

use serde::Deserialize;
use serde::de::{self, Visitor};
use serde_aco::{Help, TypedHelp};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes, PartialEq, Eq)]
#[repr(transparent)]
pub struct MacAddr([u8; 6]);

#[derive(Debug)]
pub enum Error {
    InvalidLength { len: usize },
    InvalidNumber { num: String },
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        let iter = s.split(':');
        let mut index = 0;
        for b_s in iter {
            let Ok(v) = u8::from_str_radix(b_s, 16) else {
                return Err(Error::InvalidNumber {
                    num: b_s.to_owned(),
                });
            };
            if let Some(b) = addr.get_mut(index) {
                *b = v;
            };
            index += 1;
        }
        if index != 6 {
            return Err(Error::InvalidLength { len: index });
        }
        Ok(MacAddr(addr))
    }
}

impl Help for MacAddr {
    const HELP: TypedHelp = TypedHelp::Custom { desc: "mac-addr" };
}

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
        match v.parse::<MacAddr>() {
            Ok(v) => Ok(v),
            Err(Error::InvalidLength { len }) => Err(E::invalid_length(len, &"6")),
            Err(Error::InvalidNumber { num }) => Err(E::invalid_value(
                de::Unexpected::Str(num.as_str()),
                &"hexadecimal",
            )),
        }
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
#[path = "net_test.rs"]
mod tests;
