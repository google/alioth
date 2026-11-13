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

use std::cmp::Ordering;
use std::iter::zip;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::ext::IdentExt;
use syn::meta::ParseNestedMeta;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Expr, ExprLit, Fields, FieldsNamed,
    FieldsUnnamed, Ident, Lit, Meta, MetaNameValue, Token, parse_macro_input,
};

fn get_doc_from_attrs(attrs: &[Attribute]) -> String {
    let mut lines = vec![];
    for attr in attrs.iter() {
        let Meta::NameValue(MetaNameValue {
            path,
            value: Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }),
            ..
        }) = &attr.meta
        else {
            continue;
        };
        if path.is_ident("doc") {
            let v = s.value();
            let mut trimmed = v.trim_end();
            if let Some(t) = trimmed.strip_prefix(' ') {
                trimmed = t;
            }
            if !trimmed.is_empty() {
                lines.push(trimmed.to_string());
            }
        }
    }
    lines.join("\n")
}

/// The serde attributes that decide how a type, field, or variant is
/// serialized.
#[derive(Debug, Default)]
struct SerdeAttrs {
    rename: Option<String>,
    rename_all: Option<String>,
    aliases: Vec<String>,
    default: bool,
    skip_serializing_if: bool,
    flatten: bool,
}

fn get_serde_attrs(attrs: &[Attribute]) -> SerdeAttrs {
    let mut serde_attrs = SerdeAttrs::default();
    for attr in attrs.iter() {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            continue;
        };
        for meta in nested {
            let (path, value) = match meta {
                Meta::Path(path) => (path, None),
                Meta::NameValue(MetaNameValue { path, value, .. }) => (path, Some(value)),
                Meta::List(_) => continue,
            };
            let value = match value {
                Some(Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                })) => Some(s.value()),
                _ => None,
            };
            if path.is_ident("default") {
                serde_attrs.default = true;
            } else if path.is_ident("skip_serializing_if") {
                serde_attrs.skip_serializing_if = true;
            } else if path.is_ident("flatten") {
                serde_attrs.flatten = true;
            } else if path.is_ident("rename") {
                serde_attrs.rename = value;
            } else if path.is_ident("rename_all") {
                serde_attrs.rename_all = value;
            } else if path.is_ident("alias") {
                serde_attrs.aliases.extend(value);
            }
        }
    }
    serde_attrs
}

fn to_snake_case(pascal: &str) -> String {
    let mut snake = String::new();
    for (i, c) in pascal.char_indices() {
        if i > 0 && c.is_uppercase() {
            snake.push('_');
        }
        snake.push(c.to_ascii_lowercase());
    }
    snake
}

fn to_pascal_case(snake: &str) -> String {
    let mut pascal = String::new();
    let mut capitalize = true;
    for c in snake.chars() {
        if c == '_' {
            capitalize = true;
        } else if capitalize {
            pascal.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            pascal.push(c);
        }
    }
    pascal
}

fn to_camel_case(pascal: &str) -> String {
    let mut chars = pascal.chars();
    let first = chars.next().map(|c| c.to_ascii_lowercase());
    first.into_iter().chain(chars).collect()
}

/// Applies a serde `rename_all` rule to a variant, whose name is in
/// PascalCase.
fn rename_variant(rule: &str, variant: &str) -> String {
    match rule {
        "PascalCase" => variant.to_owned(),
        "lowercase" => variant.to_ascii_lowercase(),
        "UPPERCASE" => variant.to_ascii_uppercase(),
        "camelCase" => to_camel_case(variant),
        "snake_case" => to_snake_case(variant),
        "SCREAMING_SNAKE_CASE" => to_snake_case(variant).to_ascii_uppercase(),
        "kebab-case" => to_snake_case(variant).replace('_', "-"),
        "SCREAMING-KEBAB-CASE" => to_snake_case(variant)
            .to_ascii_uppercase()
            .replace('_', "-"),
        _ => panic!("unknown rename rule {rule:?}"),
    }
}

/// Applies a serde `rename_all` rule to a field, whose name is in
/// snake_case.
fn rename_field(rule: &str, field: &str) -> String {
    match rule {
        "lowercase" | "snake_case" => field.to_owned(),
        "UPPERCASE" | "SCREAMING_SNAKE_CASE" => field.to_ascii_uppercase(),
        "PascalCase" => to_pascal_case(field),
        "camelCase" => to_camel_case(&to_pascal_case(field)),
        "kebab-case" => field.replace('_', "-"),
        "SCREAMING-KEBAB-CASE" => field.to_ascii_uppercase().replace('_', "-"),
        _ => panic!("unknown rename rule {rule:?}"),
    }
}

/// Returns the key in command-line options: the shortest one of the
/// serialized name and the aliases, preferring lowercase letters.
fn get_cli_ident(name: &str, aliases: &[String]) -> String {
    let keys = aliases.iter().map(String::as_str).chain([name]);
    let shortest = keys.min_by(|l, r| {
        if l.len() != r.len() {
            return l.len().cmp(&r.len());
        }
        for (a, b) in zip(l.chars(), r.chars()) {
            if a == b {
                continue;
            }
            if a.is_lowercase() == b.is_lowercase() {
                return a.cmp(&b);
            } else if a.is_lowercase() {
                return Ordering::Less;
            } else {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    });
    shortest.unwrap().to_owned()
}

fn has_aco_attr(attrs: &[Attribute], name: &str) -> bool {
    for attr in attrs.iter() {
        if !attr.path().is_ident("serde_aco") {
            continue;
        }
        let mut found = false;
        let has_name = |meta: ParseNestedMeta| {
            if meta.path.is_ident(name) {
                found = true;
            }
            Ok(())
        };
        if attr.parse_nested_meta(has_name).is_err() {
            continue;
        }
        if found {
            return true;
        }
    }
    false
}

fn is_hidden(attrs: &[Attribute]) -> bool {
    has_aco_attr(attrs, "hide")
}

fn is_flattened(attrs: &[Attribute]) -> bool {
    has_aco_attr(attrs, "flatten")
}

/// Derives the help of a struct, or of a struct variant if `struct_name` is
/// empty.
fn derive_named_struct_help(
    struct_name: &str,
    fields: &FieldsNamed,
    container: &SerdeAttrs,
) -> TokenStream2 {
    let mut field_docs = Vec::new();
    for field in &fields.named {
        if is_hidden(&field.attrs) {
            continue;
        }
        let attrs = get_serde_attrs(&field.attrs);
        let (ident, name) = if attrs.flatten || is_flattened(&field.attrs) {
            (String::new(), String::new())
        } else {
            let field_ident = field.ident.as_ref().unwrap().unraw().to_string();
            let name = match (attrs.rename, &container.rename_all) {
                (Some(name), _) => name,
                (None, Some(rule)) => rename_field(rule, &field_ident),
                (None, None) => field_ident,
            };
            (get_cli_ident(&name, &attrs.aliases), name)
        };
        let optional = container.default || attrs.default || attrs.skip_serializing_if;
        let ty = &field.ty;
        let doc = get_doc_from_attrs(&field.attrs);
        field_docs.push(quote! {
            FieldHelp {
                ident: #ident,
                name: #name,
                doc: #doc,
                ty: <#ty as Help>::HELP,
                optional: #optional,
            }
        })
    }

    quote! {
        TypedHelp::Struct{
            name: #struct_name,
            fields: &[#(#field_docs,)*],
        }
    }
}

fn derive_unnamed_struct_help(fields: &FieldsUnnamed) -> TokenStream2 {
    if let Some(first) = fields.unnamed.first() {
        let ty = &first.ty;
        quote! { <#ty as Help>::HELP }
    } else if fields.unnamed.is_empty() {
        quote! { TypedHelp::Unit }
    } else {
        panic!("Unnamed struct must have only one field")
    }
}

fn derive_struct_help(name: &Ident, data: &DataStruct, container: &SerdeAttrs) -> TokenStream2 {
    match &data.fields {
        Fields::Named(fields) => derive_named_struct_help(&name.to_string(), fields, container),
        Fields::Unnamed(fields) => derive_unnamed_struct_help(fields),
        Fields::Unit => quote! { TypedHelp::Unit },
    }
}

fn derive_enum_help(name: &Ident, data: &DataEnum, container: &SerdeAttrs) -> TokenStream2 {
    let mut variant_docs = vec![];
    for variant in data.variants.iter() {
        if is_hidden(&variant.attrs) {
            continue;
        }
        let doc = get_doc_from_attrs(&variant.attrs);
        let ty = match &variant.fields {
            Fields::Unit => quote! {TypedHelp::Unit},
            Fields::Named(fields) => derive_named_struct_help("", fields, &SerdeAttrs::default()),
            Fields::Unnamed(fields) => derive_unnamed_struct_help(fields),
        };
        let attrs = get_serde_attrs(&variant.attrs);
        let variant_ident = variant.ident.unraw().to_string();
        let name = match (attrs.rename, &container.rename_all) {
            (Some(name), _) => name,
            (None, Some(rule)) => rename_variant(rule, &variant_ident),
            (None, None) => variant_ident,
        };
        let ident = get_cli_ident(&name, &attrs.aliases);
        variant_docs.push(quote! {
            FieldHelp {
                ident: #ident,
                name: #name,
                doc: #doc,
                ty: #ty,
                optional: false,
            }
        })
    }
    let name = name.to_string();
    quote! {
        TypedHelp::Enum {
            name: #name,
            variants: &[#(#variant_docs,)*],
        }
    }
}

pub fn derive_help(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ty_name = &input.ident;
    let container = get_serde_attrs(&input.attrs);
    let body = match &input.data {
        Data::Struct(data) => derive_struct_help(ty_name, data, &container),
        Data::Enum(data) => derive_enum_help(ty_name, data, &container),
        Data::Union(_) => unimplemented!("Data::Union not supported"),
    };
    TokenStream::from(quote! {
        const _:() = {
            use ::serde_aco::{Help, TypedHelp, FieldHelp};
            impl Help for #ty_name {
                const HELP: TypedHelp = #body;
            }
        };
    })
}

#[cfg(test)]
#[path = "help_test.rs"]
mod tests;
