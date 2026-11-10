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

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput};

pub fn derive_layout(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let syn::Data::Struct(ref data) = input.data else {
        panic!()
    };
    let syn::Fields::Named(ref fields) = data.fields else {
        panic!()
    };
    let name = input.ident;
    let layout_consts = fields.named.iter().map(|field| {
        let Some(ref field_ident) = field.ident else {
            panic!()
        };
        let type_ = &field.ty;
        let ident_upper = field_ident.to_string().to_uppercase();
        let const_field_size = format_ident!("SIZE_{}", ident_upper);
        let const_field_offset = format_ident!("OFFSET_{}", ident_upper);
        let const_field_layout = format_ident!("LAYOUT_{}", ident_upper);
        quote!(
            pub const #const_field_size: usize = ::core::mem::size_of::<#type_>();
            pub const #const_field_offset: usize = ::core::mem::offset_of!(#name, #field_ident);
            pub const #const_field_layout: (usize, usize) = (Self::#const_field_offset, Self::#const_field_size);
        )
    });
    TokenStream::from(quote!(
        impl #name {
            #(#layout_consts)*
        }
    ))
}
