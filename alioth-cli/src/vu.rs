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

use std::marker::PhantomData;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::thread::spawn;

use alioth::errors::{DebugTrace, trace_error};
use alioth::mem::mapped::RamBus;
use alioth::virtio::dev::blk::BlkFileParam;
use alioth::virtio::dev::fs::shared_dir::SharedDirParam;
use alioth::virtio::dev::net::tap::NetTapParam;
use alioth::virtio::dev::{DevParam, Virtio, VirtioDevice};
use alioth::virtio::vu::backend::{VuBackend, VuEventfd, VuIrqSender};
use clap::{Args, Subcommand};
use serde::Deserialize;
use serde_aco::{Help, help_text};
use snafu::{ResultExt, Snafu};

use crate::objects::{DOC_OBJECTS, parse_objects};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Failed to parse {arg}"))]
    ParseArg {
        arg: String,
        error: serde_aco::Error,
    },
    #[snafu(display("Failed to parse objects"), context(false))]
    ParseObjects { source: crate::objects::Error },
    #[snafu(display("Failed to bind socket {socket:?}"))]
    Bind {
        socket: Box<Path>,
        error: std::io::Error,
    },
    #[snafu(display("Failed to accept connections"))]
    Accept { error: std::io::Error },
    #[snafu(display("Failed to create a VirtIO device"))]
    CreateVirtio { source: alioth::virtio::Error },
    #[snafu(display("Failed to create a vhost-user backend"))]
    CreateVu {
        source: alioth::virtio::vu::backend::Error,
    },
    #[snafu(display("vhost-user device runtime error"))]
    Runtime {
        source: alioth::virtio::vu::backend::Error,
    },
}

fn phantom_parser<T>(_: &str) -> Result<PhantomData<T>, &'static str> {
    Ok(PhantomData)
}

#[derive(Args, Debug, Clone)]
pub struct DevArgs<T>
where
    T: Help + Send + Sync + 'static,
{
    #[arg(short, long, value_name("PARAM"), help(help_text::<T>("Specify device parameters.")))]
    pub param: String,

    #[arg(short, long("object"), help(DOC_OBJECTS), value_name("OBJECT"))]
    pub objects: Vec<String>,

    #[arg(hide(true), value_parser(phantom_parser::<T>), default_value(""))]
    pub phantom: PhantomData<T>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DevType {
    /// VirtIO net device backed by TUN/TAP, MacVTap, or IPVTap.
    Net(DevArgs<NetTapParam>),
    /// VirtIO block device backed by a file.
    Blk(DevArgs<BlkFileParam>),
    /// VirtIO filesystem device backed by a shared host directory.
    Fs(DevArgs<SharedDirParam>),
}

#[derive(Args, Debug, Clone)]
#[command(arg_required_else_help = true)]
pub struct VuArgs {
    /// Path to a Unix domain socket to listen on.
    #[arg(short, long, value_name = "PATH")]
    pub socket: Box<Path>,

    #[command(subcommand)]
    pub ty: DevType,
}

fn create_dev<D, P>(
    name: String,
    args: &DevArgs<P>,
    memory: Arc<RamBus>,
) -> Result<VirtioDevice<VuIrqSender, VuEventfd>, Error>
where
    D: Virtio,
    P: DevParam<Device = D> + Help + for<'a> Deserialize<'a> + Send + Sync + 'static,
{
    let name: Arc<str> = name.into();
    let objects = parse_objects(&args.objects)?;
    let param: P = serde_aco::from_args(&args.param, &objects)
        .context(error::ParseArg { arg: &args.param })?;
    let dev = param.build(name.clone()).context(error::CreateVirtio)?;
    let dev = VirtioDevice::new(name, dev, memory, false).context(error::CreateVirtio)?;
    Ok(dev)
}

fn run_backend(mut backend: VuBackend) {
    let r = backend.run().context(error::Runtime);
    let name = backend.name();
    match r {
        Ok(()) => log::info!("{name}: done"),
        Err(e) => log::error!("{name}: {e:?}"),
    }
}

pub fn start(args: VuArgs) -> Result<(), Error> {
    let VuArgs { socket, ty } = args;
    let listener = UnixListener::bind(&socket).context(error::Bind { socket })?;
    let mut index = 0i32;
    loop {
        let memory = Arc::new(RamBus::new());
        let dev = match &ty {
            DevType::Net(args) => create_dev(format!("net-{index}"), args, memory.clone()),
            DevType::Blk(args) => create_dev(format!("blk-{index}"), args, memory.clone()),
            DevType::Fs(args) => create_dev(format!("fs-{index}"), args, memory.clone()),
        }?;
        let (conn, _) = listener.accept().context(error::Accept)?;
        let backend = VuBackend::new(conn, dev, memory).context(error::CreateVu)?;
        spawn(move || run_backend(backend));
        index = index.wrapping_add(1);
    }
}
