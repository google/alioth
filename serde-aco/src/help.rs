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

use std::ffi::{CStr, CString, OsStr, OsString};
use std::num::NonZero;
use std::path::{Path, PathBuf};

pub use serde_aco_derive::Help;

#[derive(Debug)]
pub struct FieldHelp {
    pub ident: &'static str,
    pub doc: &'static str,
    pub ty: TypedHelp,
}

#[derive(Debug)]
pub enum TypedHelp {
    Struct {
        name: &'static str,
        fields: Vec<FieldHelp>,
    },
    Enum {
        name: &'static str,
        variants: Vec<FieldHelp>,
    },
    FlattenedEnum {
        variants: Vec<FieldHelp>,
    },
    String,
    Int,
    Float,
    Bool,
    Unit,
    Custom {
        desc: &'static str,
    },
    Option(Box<TypedHelp>),
}

pub trait Help {
    fn help() -> TypedHelp;
}

macro_rules! impl_help_for_num_types {
    ($help_type:ident, $($ty:ty),+) => {
        $(impl Help for $ty {
            fn help() -> TypedHelp {
                TypedHelp::$help_type
            }
        })+
        $(impl Help for NonZero<$ty> {
            fn help() -> TypedHelp {
                TypedHelp::$help_type
            }
        })+
    };
}

macro_rules! impl_help_for_types {
    ($help_type:ident, $($ty:ty),+) => {
        $(impl Help for $ty {
            fn help() -> TypedHelp {
                TypedHelp::$help_type
            }
        })+
    };
}

impl_help_for_num_types!(Int, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
impl_help_for_types!(Float, f32, f64);
impl_help_for_types!(Bool, bool);
impl_help_for_types!(String, &str, String, CStr, CString, &OsStr, OsString, &Path, PathBuf);

impl<T> Help for Option<T>
where
    T: Help,
{
    fn help() -> TypedHelp {
        TypedHelp::Option(Box::new(T::help()))
    }
}
