#!/bin/bash

set -eu

readonly ARCH=${ARCH:=$(uname -m)}
readonly TARGET_DIR=target/bootloader-${ARCH}
readonly LINUX_SRC=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.5.tar.xz

function fetch_source() {
    if [[ -d target/linux ]]; then
        return 0
    fi

    pushd target

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

    local kconfig="${TARGET_DIR}/.config"

    cp bootloader/config ${kconfig}
    cat bootloader/config-${arch} >> ${kconfig}

    local vars=(
        -f target/linux/Makefile
        -j$((2 * $(nproc)))
        LLVM=1
        ARCH=${arch}
        KBUILD_OUTPUT=${TARGET_DIR}
    )

    make olddefconfig ${vars[@]}

    # Validate the configuration
    sort -b -o ${kconfig}.old.sorted ${kconfig}.old
    local missing=$(comm -23 ${kconfig}.old.sorted <(sort -b ${kconfig}))
    if [[ -n ${missing} ]]; then
        echo "Missing configuration options:"
        echo "${missing}"
        exit 1
    fi

    echo "Building Linux kernel..."
    make ${vars[@]}

    echo "Image: ${TARGET_DIR}/${image}"
}


function build_initramfs() {
    go install github.com/u-root/u-root@latest

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

    pushd bootloader/initramfs
    GOARCH=${goarch} u-root -o ../../${TARGET_DIR}/initramfs.cpio \
        -defaultsh '' -uinitcmd "boot -append '${cmdline}'" \
        github.com/u-root/u-root/cmds/boot/boot \
        github.com/u-root/u-root/cmds/core/init
    popd
}

function main() {
    mkdir -p ${TARGET_DIR}

    build_initramfs

    fetch_source
    build_linux
}

main
