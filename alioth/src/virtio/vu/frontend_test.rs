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

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use mio::Poll;

use crate::virtio::DeviceId;
use crate::virtio::vu::bindings::{VirtqState, VuFeature, VuFrontMsg};
use crate::virtio::vu::conn::VuSession;
use crate::virtio::vu::frontend::VuFrontend;
use crate::virtio::worker::mio::VirtioMio;

#[test]
fn test_vu_frontend_reset_stops_rings() {
    let (frontend_conn, backend_conn) = UnixStream::pair().unwrap();
    let backend = VuSession::from(backend_conn);
    let backend_thread = thread::spawn(move || {
        let mut fds = [const { None }; 8];
        let mut requests = vec![];
        while let Ok(msg) = backend.recv_msg(&mut fds) {
            let req = VuFrontMsg::from(msg.request);
            match req {
                VuFrontMsg::GET_VIRTQ_BASE => {
                    let mut virtq_base: VirtqState = backend.recv_payload().unwrap();
                    requests.push((req, virtq_base.index as u64));
                    virtq_base.val = 0;
                    backend.reply(req, &virtq_base, &[]).unwrap();
                }
                VuFrontMsg::SET_VIRTQ_ENABLE => {
                    let virtq_enable: VirtqState = backend.recv_payload().unwrap();
                    assert_eq!(virtq_enable.val, 0);
                    requests.push((req, virtq_enable.index as u64));
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                VuFrontMsg::SET_STATUS => {
                    let status: u64 = backend.recv_payload().unwrap();
                    requests.push((req, status));
                    backend.reply(req, &0u64, &[]).unwrap();
                }
                req => panic!("unexpected request: {req:?}"),
            }
        }
        requests
    });

    let mut frontend = VuFrontend {
        name: "vu-frontend".into(),
        session: Arc::new(VuSession::from(frontend_conn)),
        channel: None,
        id: DeviceId::NET,
        vu_feature: VuFeature::STATUS,
        device_feature: 0,
        num_queues: 2,
        err_fds: Box::default(),
    };
    let poll = Poll::new().unwrap();
    frontend.reset(poll.registry());
    drop(frontend);

    // Every ring is stopped before the device is reset.
    let requests = backend_thread.join().unwrap();
    assert_eq!(
        requests,
        [
            (VuFrontMsg::GET_VIRTQ_BASE, 0),
            (VuFrontMsg::SET_VIRTQ_ENABLE, 0),
            (VuFrontMsg::GET_VIRTQ_BASE, 1),
            (VuFrontMsg::SET_VIRTQ_ENABLE, 1),
            (VuFrontMsg::SET_STATUS, 0),
        ]
    );
}
