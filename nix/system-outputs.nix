{
  self,
  nixpkgs,
  crane,
  rust-overlay,
  system,
}:
let
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ (import rust-overlay) ];
  };
  inherit (pkgs) lib;

  toolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustfmtToolchain = pkgs.rust-bin.selectLatestNightlyWith (
    nightly: nightly.minimal.override { extensions = [ "rustfmt" ]; }
  );

  craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
  rustfmtCrane = (crane.mkLib pkgs).overrideToolchain rustfmtToolchain;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      (craneLib.fileset.commonCargoSources ../.)
      ../.rustfmt.toml
      ../AUTHORS
      ../Makefile
      ../xtask/assets
      ../gtk_scene_capture/assets
      ../po
      ../data
    ];
  };

  commonArgs = {
    inherit src;
    pname = "clamui";
    version = (lib.importTOML ../Cargo.toml).package.version;
    cargoExtraArgs = "--locked";
    strictDeps = true;
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.glib
    ];
    buildInputs = [
      pkgs.gtk4
      pkgs.libadwaita
      pkgs.systemdLibs
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
          TRANSLATION_BUILD_DIRECTORY="$TMPDIR/locale" PREFIX="$out"
      '';
    }
  );

  settingsHelperArgs = {
    inherit src;
    pname = "clamui-settings-helper";
    version = "0.1.0";
    cargoExtraArgs = "--locked --package clamui-settings-helper";
    strictDeps = true;
    meta = {
      description = "Validates and applies runtime ClamAV setting changes for ClamUI";
      license = lib.licenses.mit;
      mainProgram = "clamui-settings-helper";
      platforms = lib.platforms.linux;
    };
  };

  settingsHelperArtifacts = craneLib.buildDepsOnly settingsHelperArgs;

  settingsHelperPackage = craneLib.buildPackage (
    settingsHelperArgs
    // {
      cargoArtifacts = settingsHelperArtifacts;
      doCheck = false;
    }
  );

  settingsHelperTests = craneLib.cargoTest (
    settingsHelperArgs // { cargoArtifacts = settingsHelperArtifacts; }
  );

  settingsHelperClippy = craneLib.cargoClippy (
    settingsHelperArgs
    // {
      cargoArtifacts = settingsHelperArtifacts;
      cargoClippyExtraArgs = "--all-targets -- --deny warnings";
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

  vmTests = import ../vm-tests {
    clamuiModule = self.nixosModules.default;
  };

  moduleChecks = import ./module-checks.nix {
    inherit self nixpkgs pkgs;
  };

  screenshotRendering = import ./screenshots.nix {
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
    settings-helper = settingsHelperPackage;
    render-screenshots = screenshotRendering.renderScreenshots;
    publish-screenshots = screenshotRendering.publishScreenshots;
    inherit (screenshotRendering) screenshots;
  };

  checks =
    moduleChecks
    // vmTests.checksFor pkgs
    // {
      inherit
        clamuiPackage
        tests
        clippy
        fmt
        xtaskTests
        xtaskClippy
        settingsHelperTests
        settingsHelperClippy
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
    publish-screenshots = {
      type = "app";
      program = lib.getExe screenshotRendering.publishScreenshots;
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
