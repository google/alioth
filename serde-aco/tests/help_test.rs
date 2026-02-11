// Copyright 2026 Google LLC
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

use assert_matches::assert_matches;
use serde_aco::{FieldHelp, Help, TypedHelp};

#[derive(Help)]
pub struct TestStruct {
    #[serde_aco(hide)]
    /// field1 is a string, hidden
    pub field1: String,
    /// field2 is a number
    pub field2: i32,
}

#[test]
fn test_struct_help() {
    let help = TestStruct::HELP;
    assert_matches!(
        help,
        TypedHelp::Struct {
            name: "TestStruct",
            fields: &[FieldHelp {
                ident: "field2",
                doc: "field2 is a number",
                ty: TypedHelp::Int
            }]
        }
    )
}

#[derive(Help)]
pub enum TestEnum {
    /// Variant1 is hidden
    #[serde_aco(hide)]
    Variant1,
    /// Variant2 has a field
    Variant2 {
        /// f is a u32
        f: u32,
    },
}

#[test]
fn test_enum_help() {
    let help = TestEnum::HELP;
    eprintln!("{:?}", help);
    assert_matches!(
        help,
        TypedHelp::Enum {
            name: "TestEnum",
            variants: &[FieldHelp {
                ident: "Variant2",
                doc: "Variant2 has a field",
                ty: TypedHelp::Struct {
                    name: "TestEnum",
                    fields: &[FieldHelp {
                        ident: "f",
                        doc: "f is a u32",
                        ty: TypedHelp::Int,
                    }],
                },
            }],
        }
    );
}
