{
  runCommand,
  cpio,
  writeText,
  # A statically linked busybox for the guest, which may be a different
  # platform than the one building the initramfs
  busybox,
}:

let
  init = writeText "init" ''
    #!/bin/sh
    # The initramfs is unpacked into rootfs, which already lives in memory.
    # Mount devtmpfs first so that /dev/console exists for stdio.
    mount -t devtmpfs devtmpfs /dev
    exec </dev/console >/dev/console 2>&1
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t tmpfs tmpfs /tmp

    # Report and power off without a shell, e.g. in CI
    case " $(cat /proc/cmdline) " in
    *" alioth.smoke-test "*)
      echo "alioth-smoke-test: $(nproc) CPUs, $(awk '/MemTotal/ { print $2 }' /proc/meminfo) kB"
      poweroff -f
      ;;
    esac

    echo
    echo "Welcome to $(uname -sr) on Alioth. Exit the shell to power off."
    echo
    # Give the shell a controlling terminal so that job control and ^C work
    setsid cttyhack sh -l
    poweroff -f
  '';
in
runCommand "alioth-initramfs.cpio" { nativeBuildInputs = [ cpio ]; } ''
  mkdir root
  cd root
  mkdir dev proc sys tmp root
  cp -a ${busybox}/bin ${busybox}/sbin .
  install -m 0755 ${init} init
  find . -exec touch -h -d @0 {} +
  find . | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible --quiet > $out
''
