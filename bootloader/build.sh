#!/bin/bash

set -eu

readonly ARCH=${ARCH:=$(uname -m)}
readonly TARGET_DIR=target/bootloader-${ARCH}
readonly LINUX_SRC=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.5.tar.xz

function fetch_source() {
    if [[ -d ${TARGET_DIR}/linux ]]; then
        return 0
    fi

    pushd ${TARGET_DIR}

    echo "Fetching Linux source..."
    wget ${LINUX_SRC} -O linux.tar.xz
    tar xf linux.tar.xz
    mv linux-* linux

    popd
}

function build_linux() {
    case ${ARCH} in
        x86|x86_64|amd64)
            local arch=x86
            local image=arch/x86/boot/bzImage
            ;;
        arm|arm64|aarch64)
            local arch=arm64
            local image=arch/arm64/boot/Image
            ;;
    esac

    local kconfig="${TARGET_DIR}/linux/.config"

    cp bootloader/config ${kconfig}
    cat bootloader/config-${arch} >> ${kconfig}
    echo 'CONFIG_INITRAMFS_SOURCE="../initramfs/initramfs.cpio"' \
        >> ${kconfig}

    make -C ${TARGET_DIR}/linux olddefconfig LLVM=1 ARCH=${arch}

    # Validate the configuration
    sort -b -o ${kconfig}.old.sorted ${kconfig}.old
    local missing=$(comm -23 ${kconfig}.old.sorted <(sort -b ${kconfig}))
    if [[ -n ${missing} ]]; then
        echo "Missing configuration options:"
        echo "${missing}"
        exit 1
    fi

    echo "Building Linux kernel..."
    make -C ${TARGET_DIR}/linux -j$((2 * $(nproc))) LLVM=1 ARCH=${arch}

    echo "Image: ${PWD}/${TARGET_DIR}/linux/${image}"
}


function build_initramfs() {
    mkdir -p ${TARGET_DIR}/initramfs
    pushd ${TARGET_DIR}/initramfs

    go install github.com/u-root/u-root@latest
    if [[ ! -f go.mod ]]; then
        go mod init initramfs

        go get github.com/u-root/u-root/cmds/boot/boot
        go get github.com/u-root/u-root/cmds/core/init
    fi

    case ${ARCH} in
        x86|x86_64|amd64)
            local goarch=amd64
            local cmdline="console=ttyS0 reboot=acpi"
            ;;
        arm|aarch64|arm64)
            local goarch=arm64
            local cmdline=console=ttyAMA0
            ;;
    esac

    echo "Building initramfs..."

    GOARCH=${goarch} u-root -o initramfs.cpio \
        -defaultsh '' -uinitcmd "boot -append '${cmdline}'" \
        github.com/u-root/u-root/cmds/boot/boot \
        github.com/u-root/u-root/cmds/core/init

    popd
}

function main() {
    build_initramfs

    fetch_source
    build_linux
}

main
