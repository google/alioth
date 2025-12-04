// Copyright 2025 Google LLC
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

use serde::de::Visitor;
use serde::de::value::Error;

use super::{MacAddr, MacAddrVisitor};

#[test]
fn test_mac_addr_visitor() {
    assert_eq!(
        MacAddrVisitor.visit_borrowed_str::<Error>("ea:d7:a8:e8:c6:2f"),
        Ok(MacAddr([0xea, 0xd7, 0xa8, 0xe8, 0xc6, 0x2f]))
    );
    assert!(
        MacAddrVisitor
            .visit_borrowed_str::<Error>("ea:d7:a8:e8:c6")
            .is_err()
    );
    assert!(
        MacAddrVisitor
            .visit_borrowed_str::<Error>("ea:d7:a8:e8:c6:ac:ac")
            .is_err()
    );
    assert!(
        MacAddrVisitor
            .visit_borrowed_str::<Error>("ea:d7:a8:e8:c6:2g")
            .is_err()
    );
}
