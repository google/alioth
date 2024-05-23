# Confidential Compute (coco)

Alioth supports booting confidential guests on the following platforms:

- AMD-SEV [^sev]

## AMD-SEV guest with Oak/Stage0 firmware

WARNING: the current implementation takes QEMU [^qemu] as a reference and should
be used in testing environments only.

To launch an SEV guest,

1. build the stage0 firmware from the Oak project[^stage0],
2. prepare the guest Linux kernel of ELF format, the initramfs, and the kernel
   command line in a text file,
3. for SEV guests, `POLICY=0x1`, for SEV-ES guests, `POLICY=0x5`,
4. launch the guest by
   ```bash
   ./alioth run -f /path/to/oak_stage0.bin \
       --mem-size 1G \
       --num-cpu 2 \
       --fw-cfg name=opt/stage0/elf_kernel,file=/path/to/elf_kernel \
       --fw-cfg name=opt/stage0/initramfs,file=/path/to/initramfs \
       --fw-cfg name=opt/stage0/cmdline,file=/path/to/cmdline.txt \
       --coco sev,policy=$POLICY
   ```

[^sev]:
    [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/en/developer/sev.html)

[^stage0]:
    [Oak/stage0 firmware](https://github.com/project-oak/oak/tree/main/stage0_bin)

[^qemu]:
    [QEMU's doc on SEV](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html)
