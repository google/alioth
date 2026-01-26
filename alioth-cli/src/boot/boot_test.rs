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
use std::path::Path;

use alioth::board::{BoardConfig, CpuConfig, CpuTopology};
#[cfg(target_arch = "x86_64")]
use alioth::device::fw_cfg::{FwCfgContentParam, FwCfgItemParam};
use alioth::device::net::MacAddr;
use alioth::loader::{Executable, Payload};
use alioth::mem::{MemBackend, MemConfig};
#[cfg(target_os = "linux")]
use alioth::vfio::{CdevParam, ContainerParam, GroupParam, IoasParam};
use alioth::virtio::dev::balloon::BalloonParam;
use alioth::virtio::dev::blk::BlkFileParam;
use alioth::virtio::dev::entropy::EntropyParam;
use alioth::virtio::dev::fs::shared_dir::SharedDirParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::fs::vu::VuFsParam;
#[cfg(target_os = "linux")]
use alioth::virtio::dev::net::tap::NetTapParam;
#[cfg(target_os = "macos")]
use alioth::virtio::dev::net::vmnet::NetVmnetParam;
use alioth::virtio::dev::vsock::UdsVsockParam;
use alioth::virtio::worker::WorkerApi;
use pretty_assertions::assert_eq;
use rstest::rstest;

use crate::boot::{
    BootArgs, parse_args, parse_blk_arg, parse_cpu_arg, parse_mem_arg, parse_net_arg,
    parse_payload_arg,
};

use super::{BlkParam, Config, FsParam, NetParam, VsockParam};

#[test]
fn test_parse_args() {
    let args = BootArgs {
        firmware: Some(Path::new("stage0.bin").into()),
        kernel: Some(Path::new("vmlinuz").into()),
        cmdline: Some(c"console=ttyS0".into()),
        initramfs: Some(Path::new("initramfs.cpio").into()),
        cpu: Some("count=16,topology=id_topo".into()),
        memory: Some("size=128G,backend=anon,shared=true".into()),
        pvpanic: true,
        #[cfg(target_arch = "x86_64")]
        fw_cfg: vec![
            "name=item1,file=file1".into(),
            "name=item2,string=string2".into(),
        ],
        entropy: true,
        net: vec![
            #[cfg(target_os = "linux")]
            "tap=/dev/tap86,mac=02:32:10:d0:00:01,mtu=1500".into(),
            #[cfg(target_os = "linux")]
            "if=tap1,mac=ea:c2:14:80:10:01,mtu=1500,queue_pairs=2,api=mio".into(),
            #[cfg(target_os = "macos")]
            "vmnet,mac=a0:d0:ea:8a:d3:37".into(),
        ],
        blk: vec![
            "file,path=ubuntu-25.04-server-cloudimg.raw".into(),
            "file,path=cloudinit.img,readonly=true".into(),
        ],
        coco: None,
        fs: vec![
            "dir,tag=home,path=/home,dax_window=1g".into(),
            #[cfg(target_os = "linux")]
            "vu,socket=fs.vsock,tag=vufs".into(),
        ],
        vsock: Some("uds,cid=3,path=vsock_3.sock".into()),
        balloon: Some("free_page_reporting=true".into()),
        #[cfg(target_os = "linux")]
        vfio_cdev: vec!["path=/dev/vfio/devices/vfio0,ioas=default".into()],
        #[cfg(target_os = "linux")]
        vfio_ioas: vec!["name=default,dev_iommu=/dev/iommu".into()],
        #[cfg(target_os = "linux")]
        vfio_group: vec!["path=/dev/vfio/26,container=gpu_container,devices=id_gpus".into()],
        #[cfg(target_os = "linux")]
        vfio_container: vec!["name=gpu_container,dev_vfio=/dev/vfio/vfio".into()],
        ..Default::default()
    };
    let objects = HashMap::from([
        ("id_topo", "smt=true,sockets=1,cores=8"),
        #[cfg(target_os = "linux")]
        ("id_gpus", "0000:06:0d.0,0000:06:0d.1"),
    ]);
    let config = parse_args(args, objects).unwrap();
    let want = Config {
        board: BoardConfig {
            cpu: CpuConfig {
                count: 16,
                topology: CpuTopology {
                    smt: true,
                    cores: 8,
                    sockets: 1,
                },
            },
            mem: MemConfig {
                size: 128 << 30,
                backend: MemBackend::Anonymous,
                shared: true,
                #[cfg(target_os = "linux")]
                transparent_hugepage: false,
            },
            coco: None,
        },
        payload: Payload {
            executable: Some(Executable::Linux(Path::new("vmlinuz").into())),
            initramfs: Some(Path::new("initramfs.cpio").into()),
            cmdline: Some(c"console=ttyS0".to_owned()),
            firmware: Some(Path::new("stage0.bin").into()),
        },
        net: vec![
            #[cfg(target_os = "linux")]
            NetParam::Tap(NetTapParam {
                mac: MacAddr([0x02, 0x32, 0x10, 0xd0, 0x00, 0x01]),
                mtu: 1500,
                tap: Some(Path::new("/dev/tap86").into()),
                ..Default::default()
            }),
            #[cfg(target_os = "linux")]
            NetParam::Tap(NetTapParam {
                mac: MacAddr([0xea, 0xc2, 0x14, 0x80, 0x10, 0x01]),
                mtu: 1500,
                if_name: Some("tap1".into()),
                queue_pairs: 2,
                api: WorkerApi::Mio,
                ..Default::default()
            }),
            #[cfg(target_os = "macos")]
            NetParam::Vmnet(NetVmnetParam {
                mac: Some(MacAddr([0xa0, 0xd0, 0xea, 0x8a, 0xd3, 0x37])),
            }),
        ],
        blk: vec![
            BlkParam::File(BlkFileParam {
                path: Path::new("ubuntu-25.04-server-cloudimg.raw").into(),
                readonly: false,
                api: WorkerApi::Mio,
            }),
            BlkParam::File(BlkFileParam {
                path: Path::new("cloudinit.img").into(),
                readonly: true,
                api: WorkerApi::Mio,
            }),
        ],
        fs: vec![
            FsParam::Dir(SharedDirParam {
                path: Path::new("/home").into(),
                tag: "home".into(),
                dax_window: 1 << 30,
            }),
            #[cfg(target_os = "linux")]
            FsParam::Vu(VuFsParam {
                socket: Path::new("fs.vsock").into(),
                tag: Some("vufs".into()),
                dax_window: 0,
            }),
        ],
        vsock: Some(VsockParam::Uds(UdsVsockParam {
            cid: 3,
            path: Path::new("vsock_3.sock").into(),
        })),
        entropy: Some(EntropyParam::default()),
        balloon: Some(BalloonParam {
            free_page_reporting: true,
        }),
        pvpanic: true,
        #[cfg(target_arch = "x86_64")]
        fw_cfg: vec![
            FwCfgItemParam {
                name: "item1".into(),
                content: FwCfgContentParam::File(Path::new("file1").into()),
            },
            FwCfgItemParam {
                name: "item2".into(),
                content: FwCfgContentParam::String("string2".into()),
            },
        ],
        #[cfg(target_os = "linux")]
        vfio_cdev: vec![CdevParam {
            path: Path::new("/dev/vfio/devices/vfio0").into(),
            ioas: Some("default".into()),
        }],
        #[cfg(target_os = "linux")]
        vfio_ioas: vec![IoasParam {
            name: "default".into(),
            dev_iommu: Some(Path::new("/dev/iommu").into()),
        }],
        #[cfg(target_os = "linux")]
        vfio_container: vec![ContainerParam {
            name: "gpu_container".into(),
            dev_vfio: Some(Path::new("/dev/vfio/vfio").into()),
        }],
        #[cfg(target_os = "linux")]
        vfio_group: vec![GroupParam {
            path: Path::new("/dev/vfio/26").into(),
            container: Some("gpu_container".into()),
            devices: vec!["0000:06:0d.0".into(), "0000:06:0d.1".into()],
        }],
    };
    assert_eq!(config, want);
}

#[rstest]
#[cfg_attr(target_os = "macos", case(
    "vmnet",
    NetParam::Vmnet(NetVmnetParam { mac: None })
))]
#[cfg_attr(target_os = "linux", case(
    "tap,tap=/dev/tap86,mac=02:32:10:d0:00:01,mtu=1500,api=iouring",
    NetParam::Tap(NetTapParam {
        mac: MacAddr([0x02, 0x32, 0x10, 0xd0, 0x00, 0x01]),
        mtu: 1500,
        tap: Some(Path::new("/dev/tap86").into()),
        api: WorkerApi::IoUring,
        ..Default::default()
    }),
))]
fn test_parse_net_arg(#[case] arg: &str, #[case] want: NetParam) {
    let objects = HashMap::new();
    assert_eq!(parse_net_arg(arg, &objects).unwrap(), want);
}

#[rstest]
#[case(
    Some("count=16,topology=id_topo".into()),
    0,
    HashMap::from([("id_topo", "cores=8,sockets=2,smt=false")]),
    CpuConfig {
        count: 16,
        topology: CpuTopology { smt: false, cores: 8, sockets: 2 },
    }
)]
#[case(
    None,
    16,
    HashMap::new(),
    CpuConfig {
        count: 16,
        topology: CpuTopology::default(),
    }
)]
fn test_parse_cpu_arg(
    #[case] arg: Option<Box<str>>,
    #[case] num_cpu: u16,
    #[case] objects: HashMap<&str, &str>,
    #[case] want: CpuConfig,
) {
    assert_eq!(parse_cpu_arg(arg, num_cpu, &objects).unwrap(), want,);
}

#[rstest]
#[case(
    None,
    "32G",
    MemConfig {
        size: 32 << 30,
        #[cfg(target_os = "linux")]
        backend: MemBackend::Memfd,
        #[cfg(target_os = "macos")]
        backend: MemBackend::Anonymous,
        ..Default::default()
    }
)]
#[cfg_attr(target_os = "linux", case(
    Some("size=32g,backend=memfd,shared=true,thp=true".into()),
    "",
    MemConfig {
        size: 32 << 30,
        backend: MemBackend::Memfd,
        shared: true,
        transparent_hugepage: true
    }
))]
fn test_parse_mem_arg(
    #[case] arg: Option<String>,
    #[case] mem_size: &str,
    #[case] want: MemConfig,
) {
    let objects = HashMap::new();
    let config = parse_mem_arg(arg, mem_size.to_owned(), &objects).unwrap();
    assert_eq!(config, want);
}

#[rstest]
#[case(
    BootArgs {
        kernel: Some(Path::new("vmlinuz").into()),
        cmdline: Some(c"console=ttyS0".into()),
        initramfs: Some(Path::new("initramfs.cpio").into()),
        ..Default::default()
    },
    Payload {
        firmware: None,
        initramfs: Some(Path::new("initramfs.cpio").into()),
        executable: Some(Executable::Linux(Path::new("vmlinuz").into())),
        cmdline: Some(c"console=ttyS0".into()),
    }
)]
#[cfg_attr(target_arch = "x86_64", case(
    BootArgs {
        pvh: Some(Path::new("vmlinux.bin").into()),
        cmdline: Some(c"console=ttyS0".into()),
        initramfs: Some(Path::new("initramfs.cpio").into()),
        ..Default::default()
    },
    Payload {
        firmware: None,
        initramfs: Some(Path::new("initramfs.cpio").into()),
        executable: Some(Executable::Pvh(Path::new("vmlinux.bin").into())),
        cmdline: Some(c"console=ttyS0".into()),
    }
))]
fn test_parse_payload_arg(#[case] mut args: BootArgs, #[case] want: Payload) {
    assert_eq!(parse_payload_arg(&mut args), want);
}

#[rstest]
#[case(
    "file,path=ubuntu-25.04-server-cloudimg.raw",
    BlkParam::File(BlkFileParam {
        path: Path::new("ubuntu-25.04-server-cloudimg.raw").into(),
        readonly: false,
        api: WorkerApi::Mio
    })
)]
#[case(
    "path=cloudinit.img,readonly=true",
    BlkParam::File(BlkFileParam {
        path: Path::new("cloudinit.img").into(),
        readonly: true,
        api: WorkerApi::Mio
    })
)]
#[case(
    "ubuntu-25.04-server-cloudimg.raw",
    BlkParam::File(BlkFileParam {
        path: Path::new("ubuntu-25.04-server-cloudimg.raw").into(),
        readonly: false,
        api: WorkerApi::Mio
    })
)]
#[cfg_attr(target_os = "linux", case(
    "file,path=ubuntu-25.04-server-cloudimg.raw,api=io_uring",
    BlkParam::File(BlkFileParam {
        path: Path::new("ubuntu-25.04-server-cloudimg.raw").into(),
        readonly: false,
        api: WorkerApi::IoUring
    })
))]
fn test_parse_blk_arg(#[case] arg: &str, #[case] want: BlkParam) {
    let objects = HashMap::new();
    assert_eq!(parse_blk_arg(arg, &objects), want);
}
