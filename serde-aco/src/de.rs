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

use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, VariantAccess, Visitor};
use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug)]
pub struct Deserializer<'s, 'o> {
    input: &'s str,
    objects: Option<&'o HashMap<&'s str, &'s str>>,
    in_value: bool,
}

impl<'s, 'o, 'a> de::Deserializer<'s> for &'a mut Deserializer<'s, 'o> {
    type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        let s = self.get_string_until(&[',']);
        match s {
            "on" | "true" => visitor.visit_bool(true),
            "off" | "false" => visitor.visit_bool(false),
            _ => Err(Error::ExpectedBool),
        }
    }

    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_i32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_i64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
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

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_borrowed_str(self.get_string_until(&[',']))
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        if self.in_value {
            let id = self.get_string_until(&[',']);
            let Some(objects) = self.objects else {
                return Err(Error::IdNotFound);
            };
            let obj_str = objects.get(&id).ok_or(Error::IdNotFound)?;
            let mut sub_de = Deserializer {
                input: obj_str,
                objects: self.objects,
                in_value: false,
            };
            visitor.visit_map(CommaSeparated::new(&mut sub_de))
        } else {
            visitor.visit_map(CommaSeparated::new(self))
        }
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
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        if self.in_value {
            let id = self.get_string_until(&[',']);
            let obj_str = if variants.contains(&id) {
                id
            } else {
                let Some(objects) = self.objects else {
                    return Err(Error::IdNotFound);
                };
                objects.get(&id).ok_or(Error::IdNotFound)?
            };
            let mut sub_de = Deserializer {
                input: obj_str,
                objects: self.objects,
                in_value: false,
            };
            visitor.visit_enum(Enum::new(&mut sub_de))
        } else {
            visitor.visit_enum(Enum::new(self))
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        visitor.visit_borrowed_str(self.get_string_until(&['=', ',']))
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        unimplemented!()
    }
}

impl<'s, 'o> Deserializer<'s, 'o> {
    pub fn from_args(input: &'s str, objects: &'o HashMap<&'s str, &'s str>) -> Self {
        Deserializer {
            input,
            objects: Some(objects),
            in_value: false,
        }
    }

    pub fn from_arg(input: &'s str) -> Self {
        Deserializer {
            input,
            objects: None,
            in_value: false,
        }
    }

    fn get_string_until(&mut self, ends: &[char]) -> &'s str {
        match self.input.find(ends) {
            Some(len) => {
                let s = &self.input[..len];
                self.input = &self.input[len..];
                s
            }
            None => {
                let s = self.input;
                self.input = "";
                s
            }
        }
    }

    fn parse_unsigned<T>(&mut self) -> Result<T>
    where
        T: TryFrom<u64>,
    {
        let s = self.get_string_until(&[',']);
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
}

pub fn from_args<'s, 'o, T>(s: &'s str, objects: &'o HashMap<&'s str, &'s str>) -> Result<T>
where
    T: Deserialize<'s>,
{
    let mut deserializer = Deserializer::from_args(s, objects);
    T::deserialize(&mut deserializer)
}

pub fn from_arg<'s, T>(s: &'s str) -> Result<T>
where
    T: Deserialize<'s>,
{
    let mut deserializer = Deserializer::from_arg(s);
    T::deserialize(&mut deserializer)
}

struct CommaSeparated<'a, 's: 'a, 'o: 'a> {
    de: &'a mut Deserializer<'s, 'o>,
    first: bool,
}

impl<'a, 's, 'o> CommaSeparated<'a, 's, 'o> {
    fn new(de: &'a mut Deserializer<'s, 'o>) -> Self {
        CommaSeparated { de, first: true }
    }
}

impl<'s, 'o> Deserializer<'s, 'o> {
    fn peek_char(&mut self) -> Option<char> {
        self.input.chars().next()
    }

    fn next_char(&mut self) -> Result<char> {
        let ch = self.peek_char().ok_or(Error::Eof)?;
        self.input = &self.input[ch.len_utf8()..];
        Ok(ch)
    }
}

impl<'a, 's, 'o> MapAccess<'s> for CommaSeparated<'a, 's, 'o> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'s>,
    {
        if self.de.peek_char().is_none() {
            return Ok(None);
        }
        if !self.first && self.de.next_char()? != ',' {
            return Err(Error::ExpectedMapComma);
        }
        self.first = false;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'s>,
    {
        let Ok('=') = self.de.next_char() else {
            return Err(Error::ExpectedMapEq);
        };
        self.de.in_value = true;
        let r = seed.deserialize(&mut *self.de);
        self.de.in_value = false;
        r
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

impl<'a, 's, 'o> EnumAccess<'s> for Enum<'a, 's, 'o> {
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

impl<'a, 's, 'o> VariantAccess<'s> for Enum<'a, 's, 'o> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'s>,
    {
        if self.de.next_char()? == ',' {
            seed.deserialize(self.de)
        } else {
            Err(Error::ExpectedMapComma)
        }
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        if self.de.next_char()? == ',' {
            de::Deserializer::deserialize_seq(self.de, visitor)
        } else {
            Err(Error::ExpectedMapComma)
        }
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'s>,
    {
        if self.de.next_char()? == ',' {
            de::Deserializer::deserialize_map(self.de, visitor)
        } else {
            Err(Error::ExpectedMapComma)
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use serde::Deserialize;

    use crate::{from_arg, from_args, Error};

    #[test]
    fn test_nested_struct() {
        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct Param {
            byte: u8,
            word: u16,
            dw: u32,
            long: u64,
            enable_1: bool,
            enable_2: bool,
            enable_3: Option<bool>,
            sub: SubParam,
            addr: Addr,
        }

        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct SubParam {
            b: u8,
            w: u16,
            enable: Option<bool>,
            s: String,
        }

        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct Addr(u32);

        assert_eq!(
            from_args::<Param>(
                "byte=0b10,word=0o7k,dw=0x8m,long=10t,enable_1=on,enable_2=off,sub=id1,addr=1g",
                &[("id1", "b=1,w=2,s=s1,enable=on")].into()
            )
            .unwrap(),
            Param {
                byte: 0b10,
                word: 0o7 << 10,
                dw: 0x8 << 20,
                long: 10 << 40,
                enable_1: true,
                enable_2: false,
                enable_3: None,
                sub: SubParam {
                    b: 1,
                    w: 2,
                    enable: Some(true),
                    s: "s1".to_owned(),
                },
                addr: Addr(1 << 30)
            }
        )
    }

    #[test]
    fn test_bool() {
        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct BoolStruct {
            val: bool,
        }
        assert_eq!(
            from_arg::<BoolStruct>("val=on").unwrap(),
            BoolStruct { val: true }
        );
        assert_eq!(
            from_arg::<BoolStruct>("val=off").unwrap(),
            BoolStruct { val: false }
        );
        assert_eq!(
            from_arg::<BoolStruct>("val=true").unwrap(),
            BoolStruct { val: true }
        );
        assert_eq!(
            from_arg::<BoolStruct>("val=false").unwrap(),
            BoolStruct { val: false }
        );
        assert_matches!(from_arg::<BoolStruct>("val=a"), Err(Error::ExpectedBool));
    }

    #[test]
    fn test_enum() {
        #[derive(Debug, Deserialize, PartialEq, Eq)]
        enum TestEnum {
            A { val: u32 },
            B(u64),
            C(u8, u8),
            D,
        }

        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct TestStruct {
            num: u32,
            e: TestEnum,
        }

        assert_eq!(
            from_args::<TestStruct>("num=3,e=id", &[("id", "A,val=1")].into()).unwrap(),
            TestStruct {
                num: 3,
                e: TestEnum::A { val: 1 }
            }
        );
        assert_eq!(
            from_arg::<TestStruct>("num=4,e=D").unwrap(),
            TestStruct {
                num: 4,
                e: TestEnum::D,
            }
        );
        assert_eq!(
            from_args::<TestStruct>("num=4,e=id_d", &[("id_d", "D")].into()).unwrap(),
            TestStruct {
                num: 4,
                e: TestEnum::D,
            }
        );
        assert_matches!(
            from_arg::<TestStruct>("num=4,e=id_d"),
            Err(Error::IdNotFound)
        );
        assert_matches!(
            from_args::<TestStruct>("num=4,e=id_d", &[].into()),
            Err(Error::IdNotFound)
        );
        assert_eq!(from_arg::<TestEnum>("B,1").unwrap(), TestEnum::B(1));
        assert_eq!(from_arg::<TestEnum>("D").unwrap(), TestEnum::D);
    }
}
