# Confidential Compute (coco)

Alioth supports booting confidential guests on the following platforms,

- AMD-SEV [^sev]

  The implementation takes QEMU [^qemu] as a reference.

> [!IMPORTANT]
>
> Alioth confidential VMs should be used in testing environments only since the
> code base has not gone through any serious security reviews.

## AMD-SEV guest with Oak/Stage0 firmware

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

To launch an SEV-SNP guest, pass `--coco snp,policy=0x30000` instead.

> [!NOTE]
>
> An SEV-SNP guest needs the host KVM to support `KVM_X86_SNP_VM`, which is
> scheduled to be merged into Linux 6.11.

As of 2024-06-25, to try out SEV-SNP with a bleeding edge host Linux kernel,

- checkout the branch `kvm-coco-queue` of the
  [Linux KVM tree](https://git.kernel.org/pub/scm/virt/kvm/kvm.git/),
- merge the branch `snp-host-latest` of
  [AMDESE/linux](https://github.com/AMDESE/linux),
- build and install the kernel on the test machine.

[^sev]:
    [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/en/developer/sev.html)

[^stage0]:
    [Oak/stage0 firmware](https://github.com/project-oak/oak/tree/main/stage0_bin)

[^qemu]:
    [QEMU's doc on SEV](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html)
