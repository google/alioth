{
  lib,
  rustPlatform,
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

  # Checks use `debug_assert_eq!`
  checkType = "debug";

  separateDebugInfo = true;

  meta = {
    homepage = "https://github.com/google/alioth";
    description = "Experimental virtual machine monitor written from scratch in Rust";
    license = lib.licenses.asl20;
    mainProgram = "alioth";
    platforms = import ./platforms.nix;
  };
}
