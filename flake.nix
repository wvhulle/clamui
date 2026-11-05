{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
    }:
    let
      inherit (nixpkgs) lib;

      outputsBySystem = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
        system:
        import ./nix/system-outputs.nix {
          inherit
            self
            nixpkgs
            crane
            rust-overlay
            system
            ;
        }
      );

      outputPerSystem =
        outputName: lib.mapAttrs (_system: systemOutputs: systemOutputs.${outputName}) outputsBySystem;
    in
    {
      homeManagerModules.default = import ./nix/home-manager-module.nix self;
      nixosModules.default = import ./nix/nixos-module.nix self;

      packages = outputPerSystem "packages";
      checks = outputPerSystem "checks";
      apps = outputPerSystem "apps";
      formatter = outputPerSystem "formatter";
      devShells = outputPerSystem "devShells";
    };
}
