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

fn get_serde_aliases_from_attrs(ident: &Ident, attrs: &[Attribute]) -> Vec<String> {
    let mut aliases = vec![];
    for attr in attrs.iter() {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            continue;
        };
        for meta in nested {
            let Meta::NameValue(MetaNameValue {
                path,
                value:
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }),
                ..
            }) = meta
            else {
                continue;
            };
            if !path.is_ident("alias") {
                continue;
            }
            aliases.push(s.value());
        }
    }
    aliases.push(ident.to_string());
    aliases.sort_by(|l, r| {
        if l.len() != r.len() {
            l.len().cmp(&r.len())
        } else {
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
        }
    });
    aliases
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

fn derive_named_struct_help(name: &Ident, fields: &FieldsNamed) -> TokenStream2 {
    let mut field_docs = Vec::new();
    for field in &fields.named {
        if is_hidden(&field.attrs) {
            continue;
        }
        let aliases;
        let ident = if is_flattened(&field.attrs) {
            ""
        } else {
            aliases = get_serde_aliases_from_attrs(field.ident.as_ref().unwrap(), &field.attrs);
            &aliases[0]
        };
        let ty = &field.ty;
        let doc = get_doc_from_attrs(&field.attrs);
        field_docs.push(quote! {
            FieldHelp {
                ident: #ident,
                doc: #doc,
                ty: <#ty as Help>::HELP,
            }
        })
    }

    quote! {
        TypedHelp::Struct{
            name: stringify!(#name),
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

fn derive_struct_help(name: &Ident, data: &DataStruct) -> TokenStream2 {
    match &data.fields {
        Fields::Named(fields) => derive_named_struct_help(name, fields),
        Fields::Unnamed(fields) => derive_unnamed_struct_help(fields),
        Fields::Unit => quote! { TypedHelp::Unit },
    }
}

fn derive_enum_help(name: &Ident, data: &DataEnum) -> TokenStream2 {
    let mut variant_docs = vec![];
    for variant in data.variants.iter() {
        if is_hidden(&variant.attrs) {
            continue;
        }
        let doc = get_doc_from_attrs(&variant.attrs);
        let ty = match &variant.fields {
            Fields::Unit => quote! {TypedHelp::Unit},
            Fields::Named(fields) => derive_named_struct_help(name, fields),
            Fields::Unnamed(fields) => derive_unnamed_struct_help(fields),
        };
        let aliases = get_serde_aliases_from_attrs(&variant.ident, &variant.attrs);
        let ident = &aliases[0];
        variant_docs.push(quote! {
            FieldHelp {
                ident: #ident,
                doc: #doc,
                ty: #ty,
            }
        })
    }
    quote! {
        TypedHelp::Enum {
            name: stringify!(#name),
            variants: &[#(#variant_docs,)*],
        }
    }
}

pub fn derive_help(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ty_name = &input.ident;
    let body = match &input.data {
        Data::Struct(data) => derive_struct_help(ty_name, data),
        Data::Enum(data) => derive_enum_help(ty_name, data),
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
