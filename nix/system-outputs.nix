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
      ../migrations
    ];
  };

  commonArgs = {
    inherit src;
    pname = "lazaret";
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
      mainProgram = "lazaret";
      platforms = lib.platforms.linux;
    };
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  lazaretPackage = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      doCheck = false;
      LAZARET_LOCALE_DIRECTORY = "${placeholder "out"}/share/locale";
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

  clamavAdminArgs = {
    inherit src;
    pname = "lazaret-clamav-admin";
    version = "0.1.0";
    cargoExtraArgs = "--locked --package lazaret-clamav-admin";
    strictDeps = true;
    meta = {
      description = "Validates and applies runtime ClamAV setting changes for Lazaret";
      license = lib.licenses.mit;
      mainProgram = "lazaret-clamav-admin";
      platforms = lib.platforms.linux;
    };
  };

  clamavAdminArtifacts = craneLib.buildDepsOnly clamavAdminArgs;

  clamavAdminPackage = craneLib.buildPackage (
    clamavAdminArgs
    // {
      cargoArtifacts = clamavAdminArtifacts;
      doCheck = false;
    }
  );

  clamavAdminTests = craneLib.cargoTest (
    clamavAdminArgs // { cargoArtifacts = clamavAdminArtifacts; }
  );

  clamavAdminClippy = craneLib.cargoClippy (
    clamavAdminArgs
    // {
      cargoArtifacts = clamavAdminArtifacts;
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

  staticRustTarget = "${pkgs.stdenv.hostPlatform.parsed.cpu.name}-unknown-linux-musl";

  staticCraneLib = (crane.mkLib pkgs).overrideToolchain (
    toolchain.override { targets = [ staticRustTarget ]; }
  );

  staticXtaskArgs = xtaskArgs // {
    pname = "xtask-static";
    CARGO_BUILD_TARGET = staticRustTarget;
    CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
  };

  staticXtaskPackage = staticCraneLib.buildPackage (
    staticXtaskArgs
    // {
      cargoArtifacts = staticCraneLib.buildDepsOnly staticXtaskArgs;
      doCheck = false;
    }
  );

  ciTools = import ./ci-tools.nix {
    inherit pkgs;
    xtask = xtaskPackage;
    xtaskStatic = staticXtaskPackage;
    rustToolchain = toolchain;
  };

  xtaskTests = craneLib.cargoTest (xtaskArgs // { cargoArtifacts = xtaskArtifacts; });

  xtaskClippy = craneLib.cargoClippy (
    xtaskArgs
    // {
      cargoArtifacts = xtaskArtifacts;
      cargoClippyExtraArgs = "--all-targets -- --deny warnings";
    }
  );

  vmTests = import ../vm-tests {
    lazaretModule = self.nixosModules.default;
  };

  moduleChecks = import ./module-checks.nix {
    inherit self nixpkgs pkgs;
  };

  screenshotRendering = import ./screenshots.nix {
    inherit pkgs;
    lazaret = lazaretPackage;
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
    pname = "lazaret";
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
  developmentSchemas =
    pkgs.runCommand "lazaret-development-schemas"
      {
        nativeBuildInputs = [ pkgs.glib ];
      }
      ''
        mkdir -p "$out"
        cp ${../data/page.codeberg.wvhulle.Lazaret.gschema.xml} "$out/page.codeberg.wvhulle.Lazaret.gschema.xml"
        cp ${pkgs.glib.getSchemaPath pkgs.gtk4}/*.gschema.xml "$out"/
        cp ${pkgs.glib.getSchemaPath pkgs.gsettings-desktop-schemas}/*.gschema.xml "$out"/
        cp ${pkgs.glib.getSchemaPath pkgs.gsettings-desktop-schemas}/*.enums.xml "$out"/
        glib-compile-schemas --strict "$out"
      '';
in
{
  packages = {
    default = lazaretPackage;
    lazaret = lazaretPackage;
    deps = cargoArtifacts;
    xtask = xtaskPackage;
    clamav-admin = clamavAdminPackage;
    render-screenshots = screenshotRendering.renderScreenshots;
    publish-screenshots = screenshotRendering.publishScreenshots;
    push-to-cachix = screenshotRendering.cachixPush;
    inherit (screenshotRendering) screenshots;
  }
  // ciTools;

  checks =
    moduleChecks
    // vmTests.checksFor pkgs
    // {
      inherit
        lazaretPackage
        tests
        clippy
        fmt
        xtaskTests
        xtaskClippy
        clamavAdminTests
        clamavAdminClippy
        ;
      inherit (screenshotRendering) screenshots;
    };

  apps =
    lib.mapAttrs (_toolName: toolPackage: {
      type = "app";
      program = lib.getExe toolPackage;
    }) ciTools
    // {
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
      push-to-cachix = {
        type = "app";
        program = lib.getExe screenshotRendering.cachixPush;
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
    GSETTINGS_SCHEMA_DIR = developmentSchemas;
  };
}
