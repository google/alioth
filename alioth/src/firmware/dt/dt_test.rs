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

use crate::firmware::dt::PropVal;

#[test]
fn test_val_size() {
    assert_eq!(PropVal::Empty.size(), 0);
    assert_eq!(PropVal::U32(1).size(), 4);
    assert_eq!(PropVal::U64(1).size(), 8);
    assert_eq!(PropVal::String("s".to_owned()).size(), 2);
    assert_eq!(PropVal::Str("s").size(), 2);
    assert_eq!(PropVal::PHandle(1).size(), 4);
    assert_eq!(
        PropVal::StringList(vec!["s1".to_owned(), "s12".to_owned()]).size(),
        7
    );
    assert_eq!(PropVal::U32List(vec![1, 2]).size(), 8);
    assert_eq!(PropVal::U64List(vec![1, 3]).size(), 16);
    assert_eq!(PropVal::Bytes(vec![1, 2, 3, 4]).size(), 4);
}
