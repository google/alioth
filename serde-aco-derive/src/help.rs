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
    parse_macro_input, Attribute, Data, DataEnum, DataStruct, DeriveInput, Expr, ExprLit, Fields,
    FieldsNamed, FieldsUnnamed, Ident, Lit, Meta, MetaNameValue, Token,
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

fn is_flattened(attrs: &[Attribute]) -> bool {
    for attr in attrs.iter() {
        if !attr.path().is_ident("serde_aco") {
            continue;
        }
        let mut flattened = false;
        let is_flatten = |meta: ParseNestedMeta| {
            if meta.path.is_ident("flatten") {
                flattened = true;
            }
            Ok(())
        };
        if attr.parse_nested_meta(is_flatten).is_err() {
            continue;
        }
        if flattened {
            return true;
        }
    }
    false
}

fn derive_named_struct_help(name: &Ident, fields: &FieldsNamed) -> TokenStream2 {
    let mut field_doc = vec![];
    let mut flatten_fields = vec![];
    for field in fields.named.iter() {
        let ident = field.ident.as_ref().unwrap();
        let aliases = get_serde_aliases_from_attrs(ident, &field.attrs);
        let ident = &aliases[0];
        let ty = &field.ty;
        let doc = get_doc_from_attrs(&field.attrs);
        let field_help = quote! {
            FieldHelp {
                ident: #ident,
                doc: #doc,
                ty: <#ty as Help>::help(),
            }
        };
        if is_flattened(&field.attrs) {
            flatten_fields.push(field_help);
        } else {
            field_doc.push(field_help);
        }
    }
    if flatten_fields.is_empty() {
        quote! {
            TypedHelp::Struct{
                name: stringify!(#name),
                fields: vec![#(#field_doc,)*],
            }
        }
    } else {
        quote! {{
            let mut fields = vec![#(#field_doc,)*];
            let mut flatted_fields = vec![#(#flatten_fields,)*];
            for mut field in flatted_fields {
                match field.ty {
                    TypedHelp::Enum { variants, .. } => field.ty = TypedHelp::FlattenedEnum { variants },
                    TypedHelp::Option(mut o) => match *o {
                        TypedHelp::Enum { variants, .. } => {
                            *o = TypedHelp::FlattenedEnum { variants };
                            field.ty = TypedHelp::Option(o);
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                };
                fields.push(field);
            }
            TypedHelp::Struct{
                name: stringify!(#name),
                fields,
            }
        }}
    }
}

fn derive_unnamed_struct_help(fields: &FieldsUnnamed) -> TokenStream2 {
    if let Some(first) = fields.unnamed.first() {
        let ty = &first.ty;
        quote! { <#ty as Help>::help() }
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
    let mut variants = vec![];
    for variant in data.variants.iter() {
        let doc = get_doc_from_attrs(&variant.attrs);
        let ty = match &variant.fields {
            Fields::Unit => quote! {TypedHelp::Unit},
            Fields::Named(fields) => derive_named_struct_help(name, fields),
            Fields::Unnamed(fields) => derive_unnamed_struct_help(fields),
        };
        let aliases = get_serde_aliases_from_attrs(&variant.ident, &variant.attrs);
        let ident = &aliases[0];
        variants.push(quote! {
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
            variants: vec![#(#variants,)*],
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
                fn help() -> TypedHelp {
                    #body
                }
            }
        };
    })
}
