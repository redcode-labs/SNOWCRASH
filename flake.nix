{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:gytis-ivaskevicius/flake-utils-plus";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages.snowcrash =
        nixpkgs.legacyPackages.${system}.callPackage ./snowcrash.nix {};

      defaultPackage = self.packages.${system}.snowcrash;
    });
}














