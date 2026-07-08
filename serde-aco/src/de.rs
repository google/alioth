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

use std::collections::HashMap;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};

use crate::error::{Error, Result};

#[derive(Debug)]
pub struct Deserializer<'s, 'o> {
    input: &'s str,
    objects: Option<&'o HashMap<&'s str, &'s str>>,
    top_level: bool,
    key: &'s str,
}

impl<'s> de::Deserializer<'s> for &mut Deserializer<'s, '_> {
    type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        Err(Error::UnknownType)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        let s = self.consume_input();
        match s {
            "on" | "true" => visitor.visit_bool(true),
            "off" | "false" => visitor.visit_bool(false),
            _ => Err(Error::ExpectedBool),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_i8(self.parse_signed()?)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_i16(self.parse_signed()?)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_i32(self.parse_signed()?)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_i64(self.parse_signed()?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_u8(self.parse_unsigned()?)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_u16(self.parse_unsigned()?)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_u32(self.parse_unsigned()?)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_u64(self.parse_unsigned()?)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        let s = self.consume_input();
        visitor.visit_f32(s.parse().map_err(|_| Error::ExpectedFloat)?)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        let s = self.consume_input();
        visitor.visit_f64(s.parse().map_err(|_| Error::ExpectedFloat)?)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        if self.top_level {
            visitor.visit_borrowed_str(self.consume_all())
        } else {
            let id = self.consume_input();
            visitor.visit_borrowed_str(self.deref_id(id)?)
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        let id = self.consume_input();
        let s = self.deref_id(id)?;
        if id.starts_with("id_") && s.is_empty() {
            visitor.visit_none()
        } else {
            let mut sub_de = Deserializer {
                input: s,
                top_level: true,
                ..*self
            };
            visitor.visit_some(&mut sub_de)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        let s = self.consume_input();
        if s.is_empty() {
            visitor.visit_unit()
        } else {
            Err(Error::ExpectedUnit)
        }
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_nested(|de| visitor.visit_seq(CommaSeparated::new(de)))
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_nested(|de| visitor.visit_map(CommaSeparated::new(de)))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_nested(|de| visitor.visit_enum(Enum::new(de)))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_borrowed_str(self.consume_input())
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        Err(Error::Ignored(self.key.to_owned()))
    }
}

impl<'s, 'o> Deserializer<'s, 'o> {
    pub fn from_args(input: &'s str, objects: &'o HashMap<&'s str, &'s str>) -> Self {
        Deserializer {
            input,
            objects: Some(objects),
            top_level: true,
            key: "",
        }
    }

    pub fn from_arg(input: &'s str) -> Self {
        Deserializer {
            input,
            objects: None,
            top_level: true,
            key: "",
        }
    }

    fn end(&self) -> Result<()> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(Error::Trailing(self.input.to_owned()))
        }
    }

    fn deserialize_nested<F, V>(&mut self, f: F) -> Result<V>
    where
        F: FnOnce(&mut Self) -> Result<V>,
    {
        let mut sub_de;
        let de = if !self.top_level {
            let id = self.consume_input();
            let sub_input = self.deref_id(id)?;
            sub_de = Deserializer {
                input: sub_input,
                ..*self
            };
            &mut sub_de
        } else {
            self.top_level = false;
            self
        };
        let val = f(de)?;
        de.end()?;
        Ok(val)
    }

    fn consume_input_until(&mut self, end: char) -> Option<&'s str> {
        let len = self.input.find(end)?;
        let s = &self.input[..len];
        self.input = &self.input[len + end.len_utf8()..];
        Some(s)
    }

    fn consume_all(&mut self) -> &'s str {
        let s = self.input;
        self.input = "";
        s
    }

    fn consume_input(&mut self) -> &'s str {
        match self.consume_input_until(',') {
            Some(s) => s,
            None => self.consume_all(),
        }
    }

    fn deref_id(&self, id: &'s str) -> Result<&'s str> {
        if id.starts_with("id_") {
            if let Some(s) = self.objects.and_then(|objects| objects.get(id)) {
                Ok(s)
            } else {
                Err(Error::IdNotFound(id.to_owned()))
            }
        } else {
            Ok(id)
        }
    }

    fn parse_unsigned<T>(&mut self) -> Result<T>
    where
        T: TryFrom<u64>,
    {
        let s = self.consume_input();
        let (num, shift) = if let Some((num, "")) = s.split_once(['k', 'K']) {
            (num, 10)
        } else if let Some((num, "")) = s.split_once(['m', 'M']) {
            (num, 20)
        } else if let Some((num, "")) = s.split_once(['g', 'G']) {
            (num, 30)
        } else if let Some((num, "")) = s.split_once(['t', 'T']) {
            (num, 40)
        } else {
            (s, 0)
        };
        let n = if let Some(num_h) = num.strip_prefix("0x") {
            u64::from_str_radix(num_h, 16)
        } else if let Some(num_o) = num.strip_prefix("0o") {
            u64::from_str_radix(num_o, 8)
        } else if let Some(num_b) = num.strip_prefix("0b") {
            u64::from_str_radix(num_b, 2)
        } else {
            num.parse::<u64>()
        }
        .map_err(|_| Error::ExpectedInteger)?;

        let shifted_n = n.checked_shl(shift).ok_or(Error::Overflow)?;

        T::try_from(shifted_n).map_err(|_| Error::Overflow)
    }

    fn parse_signed<T>(&mut self) -> Result<T>
    where
        T: TryFrom<i64>,
    {
        let i = if self.input.starts_with('-') {
            let s = self.consume_input();
            s.parse().map_err(|_| Error::ExpectedInteger)
        } else {
            let n = self.parse_unsigned::<u64>()?;
            i64::try_from(n).map_err(|_| Error::Overflow)
        }?;
        T::try_from(i).map_err(|_| Error::Overflow)
    }
}

pub fn from_args<'s, 'o, T>(s: &'s str, objects: &'o HashMap<&'s str, &'s str>) -> Result<T>
where
    T: Deserialize<'s>,
{
    let mut deserializer = Deserializer::from_args(s, objects);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

pub fn from_arg<'s, T>(s: &'s str) -> Result<T>
where
    T: Deserialize<'s>,
{
    let mut deserializer = Deserializer::from_arg(s);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct CommaSeparated<'a, 's: 'a, 'o: 'a> {
    de: &'a mut Deserializer<'s, 'o>,
}

impl<'a, 's, 'o> CommaSeparated<'a, 's, 'o> {
    fn new(de: &'a mut Deserializer<'s, 'o>) -> Self {
        CommaSeparated { de }
    }
}

impl<'s> SeqAccess<'s> for CommaSeparated<'_, 's, '_> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'s>,
    {
        if self.de.input.is_empty() {
            return Ok(None);
        }
        seed.deserialize(&mut *self.de).map(Some)
    }
}

impl<'s> MapAccess<'s> for CommaSeparated<'_, 's, '_> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'s>,
    {
        if self.de.input.is_empty() {
            return Ok(None);
        }
        let Some(key) = self.de.consume_input_until('=') else {
            return Err(Error::ExpectedMapEq);
        };
        if key.contains(',') {
            return Err(Error::ExpectedMapEq);
        }
        self.de.key = key;
        let mut sub_de = Deserializer {
            input: key,
            key: "",
            ..*self.de
        };
        seed.deserialize(&mut sub_de).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'s>,
    {
        seed.deserialize(&mut *self.de)
    }
}

struct Enum<'a, 's: 'a, 'o: 'a> {
    de: &'a mut Deserializer<'s, 'o>,
}

impl<'a, 's, 'o> Enum<'a, 's, 'o> {
    fn new(de: &'a mut Deserializer<'s, 'o>) -> Self {
        Enum { de }
    }
}

impl<'s> EnumAccess<'s> for Enum<'_, 's, '_> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'s>,
    {
        let val = seed.deserialize(&mut *self.de)?;
        Ok((val, self))
    }
}

impl<'s> VariantAccess<'s> for Enum<'_, 's, '_> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'s>,
    {
        self.de.top_level = true;
        seed.deserialize(self.de)
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_seq(CommaSeparated::new(self.de))
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_map(CommaSeparated::new(self.de))
    }
}

#[cfg(test)]
#[path = "de_test.rs"]
mod tests;
