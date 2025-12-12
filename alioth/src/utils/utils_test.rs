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

#[test]
fn test_align_up() {
    assert_eq!(align_up!(0u64, 2), 0);
    assert_eq!(align_up!(1u64, 2), 4);
    assert_eq!(align_up!(3u64, 2), 4);

    assert_eq!(align_up!(u64::MAX, 0), u64::MAX);
    assert_eq!(align_up!(u64::MAX, 2), 0);
}
