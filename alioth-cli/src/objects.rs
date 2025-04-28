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

use std::collections::HashMap;

use alioth::errors::{DebugTrace, trace_error};
use snafu::Snafu;

pub const DOC_OBJECTS: &str = r#"Supply additional data to other command line flags.
* <id>,<value>

Any value that comes after an equal sign(=) and contains a comma(,)
or equal sign can be supplied using this flag. `<id>` must start
with `id_` and `<id>` cannot contain any comma or equal sign.

Example: assuming we are going a add a virtio-blk device backed by
`/path/to/disk,2024.img` and a virtio-fs device backed by a
vhost-user process listening on socket `/path/to/socket=1`, these
2 devices can be expressed in the command line as follows:
    --blk path=id_blk --fs vu,socket=id_fs,tag=shared-dir \
    -o id_blk,/path/to/disk,2024.img \
    -o id_fs,/path/to/socket=1"#;

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Invalid object key {key:?}, must start with `id_`"))]
    InvalidKey { key: String },
    #[snafu(display("Key {key:?} showed up more than once"))]
    DuplicateKey { key: String },
}

pub fn parse_objects(objects: &[String]) -> Result<HashMap<&str, &str>, Error> {
    let mut map = HashMap::new();
    for obj_s in objects {
        let (key, val) = obj_s.split_once(',').unwrap_or((obj_s, ""));
        if !key.starts_with("id_") {
            return error::InvalidKey {
                key: key.to_owned(),
            }
            .fail();
        }
        if map.insert(key, val).is_some() {
            return error::DuplicateKey {
                key: key.to_owned(),
            }
            .fail();
        }
    }
    Ok(map)
}
