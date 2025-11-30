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

use std::collections::HashSet;
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
        fields: &'static [FieldHelp],
    },
    Enum {
        name: &'static str,
        variants: &'static [FieldHelp],
    },
    String,
    Int,
    Float,
    Bool,
    Unit,
    Custom {
        desc: &'static str,
    },
    Array(&'static TypedHelp),
    Option(&'static TypedHelp),
}

pub trait Help {
    const HELP: TypedHelp;
}

macro_rules! impl_help_for_num_types {
    ($help_type:ident, $($ty:ty),+) => {
        $(impl Help for $ty {
            const HELP: TypedHelp = TypedHelp::$help_type;
        })+
        $(impl Help for NonZero<$ty> {
            const HELP: TypedHelp = TypedHelp::$help_type;
        })+
    };
}

macro_rules! impl_help_for_types {
    ($help_type:ident, $($ty:ty),+) => {
        $(impl Help for $ty {
            const HELP: TypedHelp = TypedHelp::$help_type;
        })+
    };
}

macro_rules! impl_help_for_array_types {
    ($($ty:ty),+) => {
        $(impl<T> Help for $ty where T: Help {
            const HELP: TypedHelp = TypedHelp::Array(&T::HELP);
        })+
    };
}

impl_help_for_num_types!(
    Int, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
);
impl_help_for_types!(Float, f32, f64);
impl_help_for_types!(Bool, bool);
impl_help_for_types!(
    String,
    &str,
    Box<str>,
    String,
    CStr,
    CString,
    &OsStr,
    OsString,
    &Path,
    Box<Path>,
    PathBuf
);
impl_help_for_array_types!(&[T], Box<[T]>, Vec<T>);

impl<T> Help for Option<T>
where
    T: Help,
{
    const HELP: TypedHelp = TypedHelp::Option(&T::HELP);
}

#[derive(Debug, Default)]
struct ExtraHelp<'a> {
    types: HashSet<&'static str>,
    helps: Vec<&'a TypedHelp>,
}

fn add_value_type(s: &mut String, v: &TypedHelp) {
    let type_s = match v {
        TypedHelp::Bool => "bool",
        TypedHelp::Int => "integer",
        TypedHelp::Float => "float",
        TypedHelp::String => "string",
        TypedHelp::Unit => todo!(),
        TypedHelp::Custom { desc } => desc,
        TypedHelp::Struct { name, .. } => name,
        TypedHelp::Enum { name, .. } => name,
        TypedHelp::Option(o) => return add_value_type(s, o),
        TypedHelp::Array(t) => {
            s.push_str("array<");
            add_value_type(s, t);
            s.push('>');
            return;
        }
    };
    s.push_str(type_s);
}

fn add_extra_help<'a>(extra: &mut ExtraHelp<'a>, v: &'a TypedHelp) {
    let v = match v {
        TypedHelp::Array(t) => t,
        TypedHelp::Option(t) => t,
        _ => v,
    };
    let (TypedHelp::Enum {
        name,
        variants: fields,
    }
    | TypedHelp::Struct { name, fields }) = v
    else {
        return;
    };
    if extra.types.insert(name) {
        extra.helps.push(v);
        for f in fields.iter() {
            add_extra_help(extra, &f.ty);
        }
    }
}

fn extra_help(s: &mut String, v: &TypedHelp) {
    s.push_str("# ");
    match v {
        TypedHelp::Struct { name, fields } => {
            struct_help(s, &mut None, name, fields, 2);
        }
        TypedHelp::Enum { name, variants } => {
            enum_help(s, &mut None, name, variants, 2);
        }
        _ => unreachable!(),
    }
}

fn next_line(s: &mut String, indent: usize) {
    s.push('\n');
    for _ in 0..indent {
        s.push(' ');
    }
}

fn one_key_val<'a>(s: &mut String, extra: &mut Option<&mut ExtraHelp<'a>>, f: &'a FieldHelp) {
    if f.ident.is_empty() {
        let fields = match f.ty {
            TypedHelp::Enum { variants, .. } => variants,
            _ => unreachable!(),
        };
        s.push('(');
        let mut need_separator = false;
        for field in fields {
            if need_separator {
                s.push('|');
            } else {
                need_separator = true;
            }
            one_key_val(s, extra, field)
        }
        s.push(')');
    } else {
        s.push_str(f.ident);
        s.push_str("=<");
        add_value_type(s, &f.ty);
        s.push('>');
        if let Some(extra) = extra {
            add_extra_help(extra, &f.ty)
        }
    }
}

fn key_val_pairs<'a>(
    s: &mut String,
    extra: &mut Option<&mut ExtraHelp<'a>>,
    variant: &str,
    fields: &'a [FieldHelp],
) {
    let mut add_comma = false;
    if !variant.is_empty() {
        s.push_str(variant);
        add_comma = true;
    }
    for f in fields.iter() {
        if add_comma {
            s.push(',');
        } else {
            add_comma = true;
        }
        one_key_val(s, extra, f);
    }
}

fn value_helps(s: &mut String, indent: usize, width: usize, fields: &[FieldHelp]) {
    for f in fields.iter() {
        if f.ident.is_empty() {
            let fields = match f.ty {
                TypedHelp::Enum { variants, .. } => variants,
                _ => unreachable!(),
            };
            value_helps(s, indent, width, fields)
        } else if f.doc.is_empty() {
            continue;
        } else {
            next_line(s, indent);
            let mut first_line = true;
            for line in f.doc.lines() {
                if first_line {
                    s.push_str(&format!("- {:width$}\t{}", f.ident, line, width = width));
                    first_line = false;
                } else {
                    next_line(s, indent + width + 2);
                    s.push('\t');
                    s.push_str(line);
                }
            }
        }
    }
}

fn fields_ident_len_max(fields: &[FieldHelp]) -> Option<usize> {
    let ident_len = |field: &FieldHelp| {
        if !field.ident.is_empty() {
            return Some(field.ident.len());
        }
        match field.ty {
            TypedHelp::Enum { variants, .. } => fields_ident_len_max(variants),
            TypedHelp::Struct { fields, .. } => fields_ident_len_max(fields),
            _ => unreachable!(),
        }
    };

    fields.iter().flat_map(ident_len).max()
}

fn field_helps(s: &mut String, indent: usize, fields: &[FieldHelp]) {
    let Some(width) = fields_ident_len_max(fields) else {
        return;
    };
    value_helps(s, indent, width, fields)
}

fn struct_help<'a>(
    s: &mut String,
    extra: &mut Option<&mut ExtraHelp<'a>>,
    desc: &str,
    fields: &'a [FieldHelp],
    indent: usize,
) {
    s.push_str(desc);
    next_line(s, indent);
    s.push_str("* ");
    key_val_pairs(s, extra, "", fields);
    field_helps(s, indent + 2, fields);
}

fn enum_all_unit_help(s: &mut String, variants: &[FieldHelp], indent: usize) -> bool {
    if variants.iter().any(|f| !matches!(f.ty, TypedHelp::Unit)) {
        return false;
    }
    let Some(width) = variants.iter().map(|f| f.ident.len()).max() else {
        return false;
    };
    for variant in variants.iter() {
        next_line(s, indent);
        s.push_str(&format!(
            "* {:width$}\t{}",
            variant.ident,
            variant.doc,
            width = width
        ));
    }
    true
}

fn enum_help<'a>(
    s: &mut String,
    extra: &mut Option<&mut ExtraHelp<'a>>,
    doc: &str,
    variants: &'a [FieldHelp],
    indent: usize,
) {
    s.push_str(doc);
    if enum_all_unit_help(s, variants, indent) {
        return;
    }
    if variants.is_empty() {
        next_line(s, indent);
        s.push_str("No options available");
    }
    for variant in variants.iter() {
        next_line(s, indent);
        s.push_str("* ");
        match &variant.ty {
            TypedHelp::Struct { fields, .. } => {
                key_val_pairs(s, extra, variant.ident, fields);
                next_line(s, indent + 2);
                s.push_str(variant.doc);
                field_helps(s, indent + 2, fields);
            }
            TypedHelp::Unit => {
                s.push_str(variant.ident);
                next_line(s, indent + 2);
                s.push_str(variant.doc);
            }
            TypedHelp::String
            | TypedHelp::Int
            | TypedHelp::Float
            | TypedHelp::Bool
            | TypedHelp::Custom { .. } => {
                s.push_str(variant.ident);
                s.push_str(",<");
                add_value_type(s, &variant.ty);
                s.push('>');
                next_line(s, indent + 2);
                s.push_str(variant.doc);
            }
            _ => todo!("{:?}", variant.ty),
        };
    }
}

pub fn help_text<T: Help>(doc: &str) -> String {
    let help = T::HELP;
    let mut s = String::new();
    let mut extra = ExtraHelp::default();
    match &help {
        TypedHelp::Struct { fields, .. } => {
            struct_help(&mut s, &mut Some(&mut extra), doc, fields, 0);
        }
        TypedHelp::Enum { variants, .. } => {
            enum_help(&mut s, &mut Some(&mut extra), doc, variants, 0)
        }
        _ => unreachable!("{:?}", help),
    }
    for h in extra.helps {
        next_line(&mut s, 0);
        extra_help(&mut s, h);
    }
    s
}
