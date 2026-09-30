{
  description = "Experimental virtual machine monitor written from scratch in Rust";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.crane.url = "github:ipetkov/crane";

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      eachSystem =
        f: nixpkgs.lib.genAttrs (import ./nix/platforms.nix) (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = eachSystem (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
          # Guests run Linux on the host's architecture
          guestPkgs = nixpkgs.legacyPackages.${builtins.replaceStrings [ "darwin" ] [ "linux" ] system};
        in
        {
          alioth = pkgs.callPackage ./nix/package.nix { craneLib = crane.mkLib pkgs; };
          default = self.packages.${system}.alioth;
          initramfs = pkgs.callPackage ./nix/initramfs.nix { inherit (guestPkgs.pkgsStatic) busybox; };
          vm = pkgs.callPackage ./nix/vm.nix {
            inherit (self.packages.${system}) alioth initramfs;
            kernel = guestPkgs.linux;
          };
        }
      );
    };
}
