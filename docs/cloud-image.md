# Booting Cloud Images with Alioth

## Introduction

Cloud images (e.g., Ubuntu, Fedora) typically ship a complete operating system
as a single disk image file, containing both the Linux kernel and the initramfs.
A bootloader is usually required to extract these components from the disk image
to boot the system.

Instead of relying on traditional firmware like SeaBIOS or OVMF, Alioth takes a
different approach: it first boots into a minimal Linux kernel (the
"bootloader") and then uses
[kexec](https://man7.org/linux/man-pages/man8/kexec.8.html) to jump into the
Linux kernel contained within the cloud image. The idea is borrowed from
[LinuxBoot](https://linuxboot.org/).

This guide demonstrates how to boot Fedora 43 on an x86_64 Linux machine.

## Building Artifacts

First, clone the repository and build the Alioth binary and the bootloader
kernel.

```bash
git clone https://github.com/google/alioth
cd alioth

# Build Alioth
cargo build --release

# Build the bootloader kernel
bootloader/build.sh
```

The Alioth binary will be located at `target/release/alioth`, and the bootloader
kernel image at `target/bootloader-x86_64/kernel-x86_64`.

## Preparing Disk Images

### Download and Convert the Cloud Image

Download the Fedora 43 cloud image and convert it from QCOW2 to raw format, as
Alioth currently requires raw disk images.

```bash
wget https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2

./alioth img convert \
    -f qcow2 -O raw \
    Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2 \
    Fedora-Cloud-Base-Generic-43-1.6.x86_64.raw
```

### Create a Cloud-init Disk

Create a
[cloud-init NoCloud disk](https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html#example-creating-a-disk)
to configure the VM user and password.

```bash
truncate --size 64K /tmp/cloud-init.raw
mkfs.vfat -n CIDATA /tmp/cloud-init.raw

# Create user-data
mcopy -oi /tmp/cloud-init.raw - ::user-data <<EOF
#cloud-config
password: password
chpasswd:
  expire: False
EOF

# Create meta-data
mcopy -oi /tmp/cloud-init.raw - ::meta-data <<EOF
local-hostname: vm
EOF
```

## Booting the VM

Run the following command to start the VM.

```bash
./alioth -l info --log-to-file boot \
    -m size=4G -p count=4 \
    -k ./kernel-x86_64 \
    --entropy \
    --pvpanic \
    --blk file,path=Fedora-Cloud-Base-Generic-43-1.6.x86_64.raw \
    --blk file,path=/tmp/cloud-init.raw,readonly=true
```

Once the LinuxBoot splash screen appears, press `1` or `Enter` to select and
boot the Fedora Linux kernel.

When the login screen appears, log in using the username `fedora` and the
password `password`.
