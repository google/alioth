# Alioth

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/google/alioth/rust.yml)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/google/alioth)
![Crates.io Version](https://img.shields.io/crates/v/alioth)
![Crates.io License](https://img.shields.io/crates/l/alioth)

Alioth /AL-lee-oth/ is an experimental
[KVM](https://docs.kernel.org/virt/kvm/api.html)-based type-2 hypervisor
(virtual machine monitor) in Rust implemented from scratch.

> [!IMPORTANT]
>
> Disclaimer: Alioth is not an officially supported Google product.

## Quick start

-   Install Alioth from source,

    ```sh
    cargo install alioth-cli --git https://github.com/google/alioth.git
    ```

-   Make an initramfs with
    [u-root](https://github.com/u-root/u-root?tab=readme-ov-file#examples).

-   Boot a Linux kernel with 2 CPUs and 4 GiB memory,

    ```sh
    alioth -l info --log-to-file \
        run \
        --kernel /path/to/vmlinuz \
        --cmd-line "console=ttyS0" \
        --initramfs /path/to/initramfs \
        --memory size=4G \
        --num-cpu 2
    ```

## Features

-   Runs on `x86_64` and `aarch64`.
-   Boots confidential VMs with AMD SEV, SEV-ES, or SEV-SNP, see
    [coco.md](docs/coco.md) for details.
-   VirtIO devices
    -   `net` backed by a tap device,
    -   `vsock` backed by host `/dev/vhost-vsock`,
    -   `blk` backed by a raw-formatted image,
    -   `entropy` backed by host `/dev/urandom`,
    -   `fs` backed by [virtiofsd](https://gitlab.com/virtio-fs/virtiofsd) with
        experimental Direct Access (DAX),
    -   (WIP) `balloon` with free page reporting.
-   PCI device passthrough based on
    [VFIO/IOMMUFD](https://docs.kernel.org/driver-api/vfio.html#iommufd-and-vfio-iommu-type1).
-   Other devices
    -   serial console: 16450 on `x86_64`, pl011 on `aarch64`,
    -   [fw_cfg](https://www.qemu.org/docs/master/specs/fw_cfg.html) (QEMU
        Firmware Configuration Device),
    -   [pvpanic](https://www.qemu.org/docs/master/specs/pvpanic.html).

## TODOs

-   [ ] explore a better solution to ACPI DSDT to replace the pre-compiled AML
    bytes,
-   [ ] increase test coverage,
-   [ ] add missing documents,
-   [ ](long term) port Alioth to Apple's
    [Hypervisor](https://developer.apple.com/documentation/hypervisor)
    framework,
-   [ ] performance, performance, and performance!

## Acknowledgment

The virtualization implementation in Alioth takes the following projects as
references,

-   [QEMU](https://gitlab.com/qemu-project/qemu.git)
-   [crosvm](https://chromium.googlesource.com/crosvm/crosvm/)
-   [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
-   [xhyve](https://github.com/machyve/xhyve)

The [error handling](docs/error-handling.md) practice is inspired by
[GreptimeDB](https://github.com/GreptimeTeam/greptimedb)'s
[`stack_trace_debug`](https://greptimedb.rs/common_macro/attr.stack_trace_debug.html).
