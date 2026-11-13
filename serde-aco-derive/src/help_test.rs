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

use rstest::rstest;

use crate::help::{get_cli_ident, rename_field, rename_variant};

#[rstest]
#[case("PascalCase", "IoUring", "PageSize")]
#[case("lowercase", "iouring", "page_size")]
#[case("UPPERCASE", "IOURING", "PAGE_SIZE")]
#[case("camelCase", "ioUring", "pageSize")]
#[case("snake_case", "io_uring", "page_size")]
#[case("SCREAMING_SNAKE_CASE", "IO_URING", "PAGE_SIZE")]
#[case("kebab-case", "io-uring", "page-size")]
#[case("SCREAMING-KEBAB-CASE", "IO-URING", "PAGE-SIZE")]
fn test_rename(#[case] rule: &str, #[case] variant: &str, #[case] field: &str) {
    assert_eq!(rename_variant(rule, "IoUring"), variant);
    assert_eq!(rename_field(rule, "page_size"), field);
}

#[rstest]
#[case("tap", &[], "tap")]
#[case("io_uring", &["iouring", "io"], "io")]
#[case("amd_snp", &["snp", "SNP"], "snp")]
fn test_get_cli_ident(#[case] name: &str, #[case] aliases: &[&str], #[case] ident: &str) {
    let aliases: Vec<_> = aliases.iter().map(|a| a.to_string()).collect();
    assert_eq!(get_cli_ident(name, &aliases), ident);
}
