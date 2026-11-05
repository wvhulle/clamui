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
            ./AUTHORS
            ./Makefile
            ./xtask/assets
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
              pkgs.glib
              pkgs.gnumake
              pkgs.wrapGAppsHook4
            ];
            buildInputs = commonArgs.buildInputs ++ [
              pkgs.adwaita-icon-theme
              pkgs.dconf
            ];
            preFixup = ''
              gappsWrapperArgs+=(--prefix XDG_DATA_DIRS : "$out/share:${
                lib.makeSearchPath "share" [
                  pkgs.adwaita-icon-theme
                  pkgs.hicolor-icon-theme
                ]
              }")
            '';
            postInstall = ''
              make install-data \
                TRANSLATION_BUILD_DIRECTORY="$TMPDIR/locale" DESTDIR="$out" PREFIX=
            '';
          }
        );

        xtaskArgs = {
          inherit src;
          pname = "xtask";
          version = "0.1.0";
          cargoExtraArgs = "--locked --package xtask";
          strictDeps = true;
          meta.mainProgram = "xtask";
        };

        xtaskArtifacts = craneLib.buildDepsOnly xtaskArgs;

        xtaskPackage = craneLib.buildPackage (
          xtaskArgs
          // {
            cargoArtifacts = xtaskArtifacts;
            doCheck = false;
          }
        );

        xtaskTests = craneLib.cargoTest (xtaskArgs // { cargoArtifacts = xtaskArtifacts; });

        xtaskClippy = craneLib.cargoClippy (
          xtaskArgs
          // {
            cargoArtifacts = xtaskArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );

        screenshotRendering = import ./nix/screenshots.nix {
          inherit pkgs;
          clamui = clamuiPackage;
          xtask = xtaskPackage;
        };

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
          cargoExtraArgs = "--all";
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
          xtask = xtaskPackage;
          render-screenshots = screenshotRendering.renderScreenshots;
          inherit (screenshotRendering) screenshots;
        };

        checks = {
          inherit
            clamuiPackage
            tests
            clippy
            fmt
            xtaskTests
            xtaskClippy
            ;
          inherit (screenshotRendering) screenshots;
        };

        apps = {
          default = {
            type = "app";
            program = lib.getExe self.packages.${system}.default;
          };
          render-screenshots = {
            type = "app";
            program = lib.getExe screenshotRendering.renderScreenshots;
          };
        };

        formatter = treefmtWrapper;

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = [
            treefmtWrapper
            rustfmtToolchain
            pkgs.gettext
            pkgs.glib
            pkgs.gnumake
            pkgs.nixfmt
            pkgs.sqlite
          ];
          shellHook = ''
            export GSETTINGS_SCHEMA_DIR="$PWD/target/gschemas"
            mkdir -p "$GSETTINGS_SCHEMA_DIR"
            glib-compile-schemas --targetdir="$GSETTINGS_SCHEMA_DIR" data
          '';
        };
      }
    );
}
