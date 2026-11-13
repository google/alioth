#!/bin/bash
set -e

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN_DIR="${MOTO_BIN:-target}"

SCRIPT_DIR="$(dirname $(readlink -f $0))"
cd "$SCRIPT_DIR"
mkdir -p "$BIN_DIR"

if [[ $# == 0 ]] ; then

   echo "kernel debug build"

   RUSTFLAGS="-C force-frame-pointers=yes " \
   cargo build --target x86_64-unknown-none.json -Zjson-target-spec \
      -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
      --no-default-features

   cargo clippy --target x86_64-unknown-none.json -Zjson-target-spec \
      -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
      --no-default-features

   strip -o "${BIN_DIR}/kernel" "${TARGET_DIR}/x86_64-unknown-none/debug/kernel"

elif [[ $# != 1 ]] ; then

   echo "kernel build.sh takes no or a single '--release' parameter"
   exit 1

elif [[ "$1" != "--release" ]] ; then

   echo "kernel build.sh takes no or a single '--release' parameter"
   exit 1

   else

   echo "kernel release build"

   RUSTFLAGS="-C force-frame-pointers=yes " \
   cargo build --release --target x86_64-unknown-none.json -Zjson-target-spec \
      -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
      --no-default-features

   cargo clippy --release --target x86_64-unknown-none.json -Zjson-target-spec \
      -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
      --no-default-features

   strip -o "${BIN_DIR}/kernel" "${TARGET_DIR}/x86_64-unknown-none/release/kernel"

fi

echo "kernel done"

