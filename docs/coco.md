# Confidential Compute (CoCo)

Alioth supports booting confidential guests on the following platforms:

-   AMD SEV [^sev]
-   Intel TDX [^tdx]

The implementation of both takes QEMU [^qemu-sev][^qemu-tdx] as a reference.

> [!IMPORTANT]
>
> Alioth confidential VMs should be used in testing environments only since the
> code base has not gone through any serious security reviews.

## Confidential Guest with Oak/stage0 Firmware

[Project Oak](https://github.com/project-oak/oak) provides a minimal firmware
(called `stage0`) for confidential computing. To use it with Alioth:

1.  Clone the Project Oak repository and build the `stage0` firmware:

    ```bash
    # In the Project Oak source tree
    # for AMD-SEV
    bazel build //stage0_bin:stage0_bin
    # for Intel-TDX
    bazel build //stage0_bin_tdx:stage0_bin_tdx
    ```

    The resulting firmware for SEV and TDX are at
    `bazel-bin/stage0_bin/stage0_bin` and
    `bazel-bin/stage0_bin_tdx/stage0_bin_tdx` respectively.

2.  Prepare the guest Linux kernel and the initramfs.

3.  Use the appropriate firmware and the following values for flag `--coco` to
    start a confidential VM:

    Type    | Flag values
    ------- | ---------------------
    SEV     | `sev,policy=0x01`
    SEV-ES  | `sev,policy=0x05`
    SEV-SNP | `snp,policy=0x30000`
    TDX     | `tdx,attr=0x10000000`

    For example, to launch an AMD-SNP guest:

    ```bash
    ./alioth boot \
        --memory size=1G \
        --cpu count=2 \
        --kernel /path/to/vmlinuz \
        --cmdline "console=ttyS0" \
        --initramfs /path/to/initramfs \
        --coco snp,policy=0x30000 \
        --firmware /path/to/stage0_bin
    ```

Note:

-   An SEV-SNP guest requires host Linux kernel 6.11 or above.
-   An Intel-TDX guest requires host Linux kernel 6.16 or above.
-   It is recommended to use the latest stable host kernel for the best
    compatibility and security.
-   The `stage0` firmware appends extra arguments (`-- --oak-dice=...
    --oak-event-log=... --oak-dice-length=...`) to the guest kernel command
    line. The init process in your initramfs must be able to handle these
    arguments, or it may fail and cause a kernel panic.

## Confidential Guest with UEFI-compatible Firmware

Work in progress.

[^sev]: [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/en/developer/sev.html)
[^tdx]: [Intel Trusted Execution Technology (TDX)](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
[^stage0]: [Oak/stage0 firmware](https://github.com/project-oak/oak/tree/main/stage0_bin)
[^qemu-sev]: [QEMU's doc on SEV](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html)
[^qemu-tdx]: [QEMU's doc on TDX](https://www.qemu.org/docs/master/system/i386/tdx.html)
