{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
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
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        inherit (pkgs) lib;

        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustfmtToolchain = pkgs.rust-bin.selectLatestNightlyWith (
          nightly: nightly.minimal.override { extensions = [ "rustfmt" ]; }
        );

        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
        rustfmtCrane = (crane.mkLib pkgs).overrideToolchain rustfmtToolchain;

        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            (craneLib.fileset.commonCargoSources ./.)
            ./.rustfmt.toml
            ./Makefile
            ./po
            ./data
          ];
        };

        commonArgs = {
          inherit src;
          pname = "clamui";
          version = (lib.importTOML ./Cargo.toml).package.version;
          cargoExtraArgs = "--locked";
          strictDeps = true;
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.glib
          ];
          buildInputs = [
            pkgs.gtk4
            pkgs.libadwaita
          ];
          meta = {
            description = "Native GTK desktop frontend for host-installed ClamAV";
            license = lib.licenses.mit;
            mainProgram = "clamui";
            platforms = lib.platforms.linux;
          };
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        clamuiPackage = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false;
            CLAMUI_LOCALE_DIRECTORY = "${placeholder "out"}/share/locale";
            nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
              pkgs.gettext
              pkgs.gnumake
              pkgs.wrapGAppsHook4
            ];
            buildInputs = commonArgs.buildInputs ++ [ pkgs.adwaita-icon-theme ];
            postInstall = ''
              make install-data \
                TRANSLATION_BUILD_DIRECTORY="$TMPDIR/locale" DESTDIR="$out" PREFIX=
            '';
          }
        );

        tests = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });

        clippy = craneLib.cargoClippy (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );

        fmt = rustfmtCrane.cargoFmt {
          inherit src;
          pname = "clamui";
          inherit (commonArgs) version;
        };

        treefmtWrapper = pkgs.writeShellApplication {
          name = "treefmt";
          runtimeInputs = [
            pkgs.treefmt
            pkgs.nixfmt
            rustfmtToolchain
          ];
          text = ''
            exec treefmt "$@"
          '';
        };
      in
      {
        packages = {
          default = clamuiPackage;
          clamui = clamuiPackage;
          deps = cargoArtifacts;
        };

        checks = {
          inherit
            clamuiPackage
            tests
            clippy
            fmt
            ;
        };

        apps.default = {
          type = "app";
          program = lib.getExe self.packages.${system}.default;
        };

        formatter = treefmtWrapper;

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = [
            treefmtWrapper
            rustfmtToolchain
            pkgs.gettext
            pkgs.gnumake
            pkgs.nixfmt
            pkgs.sqlite
          ];
        };
      }
    );
}
