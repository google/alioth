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

use crate::virtio::VirtioFeature;
use crate::virtio::dev::vsock::vhost_vsock::vring_base_init;

#[rstest]
#[case(VirtioFeature::VERSION_1, 0)]
#[case(VirtioFeature::VERSION_1 | VirtioFeature::RING_PACKED, (1 << 15) | (1 << 31))]
fn test_vring_base_init(#[case] feat: VirtioFeature, #[case] expected: u32) {
    assert_eq!(vring_base_init(feat.bits()), expected);
}
