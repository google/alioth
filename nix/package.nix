{
  lib,
  stdenv,
  rustPlatform,
  apple-sdk_15,
  darwin,
  darwinMinVersionHook,
}:

let
  inherit (lib.importTOML ../Cargo.toml) workspace;
in
rustPlatform.buildRustPackage {
  pname = "alioth";
  inherit ((lib.importTOML ../alioth-cli/Cargo.toml).package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions (
      [
        ../Cargo.toml
        ../Cargo.lock
      ]
      ++ map (lib.path.append ../.) workspace.members
    );
  };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isDarwin [ darwin.sigtool ];

  buildInputs = lib.optionals stdenv.hostPlatform.isDarwin [
    # The GIC APIs of Hypervisor.framework (hv_gic_*) need macOS 15
    apple-sdk_15
    (darwinMinVersionHook "15.0")
  ];

  # Checks use `debug_assert_eq!`
  checkType = "debug";

  separateDebugInfo = true;

  # Hypervisor.framework and vmnet.framework require entitlements to run
  # without root, see docs/macos-signing.md
  postFixup = lib.optionalString stdenv.hostPlatform.isDarwin ''
    codesign --entitlements alioth-cli/cli.entitlements --force --sign - $out/bin/alioth
  '';

  meta = {
    homepage = "https://github.com/google/alioth";
    description = "Experimental virtual machine monitor written from scratch in Rust";
    license = lib.licenses.asl20;
    mainProgram = "alioth";
    platforms = import ./platforms.nix;
  };
}
