{
  lib,
  writeShellApplication,
  alioth,
  # The kernel and initramfs are built for the guest, which runs Linux on
  # the same architecture as the host
  kernel,
  initramfs,
}:

let
  console = if kernel.stdenv.hostPlatform.isAarch64 then "ttyAMA0" else "ttyS0";
in
writeShellApplication {
  name = "alioth-vm";
  text = ''
    exec ${lib.getExe alioth} boot \
      --kernel ${kernel}/${kernel.target} \
      --initramfs ${initramfs} \
      --cmdline "console=${console} quiet" \
      --cpu "count=''${ALIOTH_VM_CPUS:-2}" \
      --memory "size=''${ALIOTH_VM_MEMORY:-1G}" \
      "$@"
  '';
}
