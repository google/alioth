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

use assert_matches::assert_matches;
use serde::{Deserialize, Serialize};
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
                name: "field2",
                doc: "field2 is a number",
                ty: TypedHelp::Int,
                optional: false,
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
                name: "Variant2",
                doc: "Variant2 has a field",
                ty: TypedHelp::Struct {
                    name: "",
                    fields: &[FieldHelp {
                        ident: "f",
                        name: "f",
                        doc: "f is a u32",
                        ty: TypedHelp::Int,
                        optional: false,
                    }],
                },
                optional: false,
            }],
        }
    );
}

#[derive(Serialize, Deserialize, Help)]
#[serde(rename_all = "snake_case")]
pub enum TestRenamedEnum {
    #[serde(alias = "io")]
    IoUring,
    #[serde(rename = "epoll")]
    Mio,
}

#[test]
fn test_renamed_enum_help() {
    assert_matches!(
        TestRenamedEnum::HELP,
        TypedHelp::Enum {
            variants: &[
                FieldHelp {
                    ident: "io",
                    name: "io_uring",
                    ..
                },
                FieldHelp {
                    ident: "epoll",
                    name: "epoll",
                    ..
                },
            ],
            ..
        }
    );
}

#[derive(Serialize, Deserialize, Help)]
#[serde(rename_all = "camelCase")]
pub struct TestOptionalFields {
    pub required: u32,
    #[serde(default)]
    pub with_default: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<u32>,
    #[serde(alias = "q")]
    pub queue_pairs: u32,
    #[serde(flatten)]
    pub flattened: TestRenamedEnum,
}

#[test]
fn test_optional_fields_help() {
    assert_matches!(
        TestOptionalFields::HELP,
        TypedHelp::Struct {
            fields: &[
                FieldHelp {
                    ident: "required",
                    name: "required",
                    optional: false,
                    ..
                },
                FieldHelp {
                    ident: "withDefault",
                    name: "withDefault",
                    optional: true,
                    ..
                },
                FieldHelp {
                    ident: "skipped",
                    name: "skipped",
                    optional: true,
                    ..
                },
                FieldHelp {
                    ident: "q",
                    name: "queuePairs",
                    optional: false,
                    ..
                },
                FieldHelp {
                    ident: "",
                    name: "",
                    ty: TypedHelp::Enum {
                        name: "TestRenamedEnum",
                        ..
                    },
                    ..
                },
            ],
            ..
        }
    );
}

#[derive(Default, Serialize, Deserialize, Help)]
#[serde(default)]
pub struct TestDefaultStruct {
    pub field: u32,
}

#[test]
fn test_default_struct_help() {
    assert_matches!(
        TestDefaultStruct::HELP,
        TypedHelp::Struct {
            fields: &[FieldHelp { optional: true, .. }],
            ..
        }
    );
}
