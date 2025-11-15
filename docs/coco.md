# Confidential Compute (coco)

Alioth supports booting confidential guests on the following platforms,

- AMD-SEV [^sev]

  The implementation takes QEMU [^qemu] as a reference.

> [!IMPORTANT]
>
> Alioth confidential VMs should be used in testing environments only since the
> code base has not gone through any serious security reviews.

## AMD-SEV guest with Oak/stage0 firmware

To launch an SEV guest,

1. build the stage0 firmware from Project Oak[^stage0],

2. prepare the guest Linux kernel and the initramfs,

3. launch the guest by

   ```bash
   ./alioth run -f /path/to/oak_stage0.bin \
       --hypervisor kvm,dev_sev=/dev/sev \
       --memory size=1G \
       --num-cpu 2 \
       --kernel /path/to/vmlinuz \
       --cmdline "console=ttyS0" \
       --initramfs /path/to/initramfs \
       --coco sev,policy=$POLICY
   ```

4. for SEV guests, `POLICY=0x1`, for SEV-ES guests, `POLICY=0x5`,

5. for SEV-SNP guests, pass `--coco snp,policy=0x30000` instead.

Note:

- An SEV-SNP guest requires host Linux kernel 6.11.

- Stage0 appends `-- --oak-dice=0x17000` to the guest kernel command line. Make
  sure the init process in the initramfs accepts or ignores this flag. If the
  init process fails to parse this flag and exits, the guest kernel would panic.

[^sev]:
    [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/en/developer/sev.html)

[^stage0]:
    [Oak/stage0 firmware](https://github.com/project-oak/oak/tree/main/stage0_bin)

[^qemu]:
    [QEMU's doc on SEV](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html)
