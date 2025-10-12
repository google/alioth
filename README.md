# Alioth

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/google/alioth/rust.yml)](https://github.com/google/alioth/actions/workflows/rust.yml)
[![Coverage Status](https://coveralls.io/repos/github/google/alioth/badge.svg?branch=main)](https://coveralls.io/github/google/alioth?branch=main)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/google/alioth)
[![Crates.io Version](https://img.shields.io/crates/v/alioth)](https://crates.io/crates/alioth)
[![Crates.io License](https://img.shields.io/crates/l/alioth)](LICENSE)
[![DeepWiki](https://img.shields.io/badge/DeepWiki-google%2Falioth-blue.svg)](https://deepwiki.com/google/alioth)

Alioth /AL-lee-oth/ is an experimental Type-2 hypervisor, written from scratch
in Rust. It runs on top of an existing operating system and leverages
[KVM](https.docs.kernel.org/virt/kvm/api.html) on Linux and Apple's
[Hypervisor](https://developer.apple.com/documentation/hypervisor) framework on
macOS to create and manage virtual machines.

> [!IMPORTANT]
>
> **Disclaimer**: Alioth is an experimental project and is NOT an officially
> supported Google product.

## Quick Start

First, install Alioth from source using Cargo:

```sh
cargo install alioth-cli --git https://github.com/google/alioth.git
```

Next, create an initramfs for your guest OS. You can use a tool like
[u-root](https://github.com/u-root/u-root) to do this.

Finally, boot a Linux kernel. This example starts a VM with 2 CPUs and 4 GiB of
memory:

```sh
case $(uname -m) in
   arm64 | aarch64)
       CONSOLE=ttyAMA0
      ;;
   x86_64)
       CONSOLE=ttyS0
      ;;
esac

alioth -l info --log-to-file \
    boot \
    --kernel /path/to/vmlinuz \
    --cmd-line "console=$CONSOLE" \
    --initramfs /path/to/initramfs \
    --memory size=4G \
    --num-cpu 2
```

## Features

- **Cross-Platform:** Runs on `x86_64` (Linux) and `aarch64` (Linux & macOS).
- **Confidential Computing:** Supports confidential VMs using AMD SEV, SEV-ES,
  and SEV-SNP. See [coco.md](docs/coco.md) for more details.
- **VirtIO Devices:**
  - `net`: Backed by a TAP device on Linux and
    [vmnet framework](https://developer.apple.com/documentation/vmnet) on macOS.
  - `vsock`: Backed by either the host's `/dev/vhost-vsock` or a Unix domain
    socket.
  - `blk`: Backed by a raw disk image.
  - `entropy`: Backed by the host's `/dev/urandom`.
  - `fs`: Backed by [virtiofsd](https://gitlab.com/virtio-fs/virtiofsd) with
    experimental Direct Access (DAX) support.
  - `balloon`: Free page reporting (Work in Progress).
- **Device Passthrough:** PCI device passthrough via
  [VFIO/IOMMUFD](https://docs.kernel.org/driver-api/vfio.html#iommufd-and-vfio-iommu-type1).
- **Other Emulated Devices:**
  - Serial Console: 16450 on `x86_64`, PL011 on `aarch64`.
  - [fw_cfg](https://www.qemu.org/docs/master/specs/fw_cfg.html): QEMU
    Firmware Configuration Device.
  - [pvpanic](https://www.qemu.org/docs/master/specs/pvpanic.html): QEMU
    PVPanic Device.

## Future Work

- [ ] Explore a better solution for ACPI DSDT generation to replace
      pre-compiled AML bytes.
- [ ] Increase test coverage across the codebase.
- [ ] Add comprehensive documentation for APIs and internal architecture.
- [ ] Focus on performance optimizations.

## Acknowledgments

The design and implementation of Alioth are heavily inspired by the following
projects:

- [QEMU](https://gitlab.com/qemu-project/qemu.git)
- [crosvm](https://chromium.googlesource.com/crosvm/crosvm/)
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
- [xhyve](https://github.com/machyve/xhyve)

The [error handling](docs/error-handling.md) approach is inspired by the
`stack_trace_debug` macro in
[GreptimeDB](https://github.com/GreptimeTeam/greptimedb).
