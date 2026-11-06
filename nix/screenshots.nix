{
  pkgs,
  lazaret,
  xtask,
}:
let
  screenshotFonts = pkgs.replaceVars ./screenshot-fonts.conf {
    fontDirectories = pkgs.makeFontsConf {
      fontDirectories = [ pkgs.adwaita-fonts ];
    };
  };

  renderScreenshots = pkgs.symlinkJoin {
    name = "render-screenshots";
    paths = [ xtask ];
    nativeBuildInputs = [ pkgs.makeWrapper ];
    postBuild = ''
      fixtureDirectory=$out/libexec/lazaret-fixture-programs
      mkdir -p $fixtureDirectory
      for programName in clamscan clamdscan freshclam clamd; do
        ln -s ${pkgs.lib.getExe xtask} $fixtureDirectory/$programName
      done
      for taskName in render-screenshots list-widgets; do
        makeWrapper $out/bin/xtask $out/bin/$taskName \
          --add-flags $taskName \
          --prefix PATH : ${
            pkgs.lib.makeBinPath [
              lazaret
              pkgs.dbus
              pkgs.grim
              pkgs.sqlite
              pkgs.sway
            ]
          } \
          --prefix PATH : ${pkgs.at-spi2-core}/libexec \
          --set LAZARET_FIXTURE_PROGRAM_DIRECTORY $fixtureDirectory \
          --set FONTCONFIG_FILE ${screenshotFonts}
      done
    '';
    meta.mainProgram = "render-screenshots";
  };

  publishScreenshots =
    pkgs.runCommand "publish-screenshots"
      {
        nativeBuildInputs = [ pkgs.makeBinaryWrapper ];
        meta.mainProgram = "publish-screenshots";
      }
      ''
        makeWrapper ${pkgs.lib.getExe xtask} $out/bin/publish-screenshots \
          --add-flags publish-screenshots \
          --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.gitMinimal ]}
      '';

  cachixPush =
    pkgs.runCommand "push-to-cachix"
      {
        nativeBuildInputs = [ pkgs.makeBinaryWrapper ];
        meta.mainProgram = "push-to-cachix";
      }
      ''
        makeWrapper ${pkgs.lib.getExe xtask} $out/bin/push-to-cachix \
          --add-flags push-to-cachix \
          --prefix PATH : ${
            pkgs.lib.makeBinPath [
              pkgs.cachix
              pkgs.nix
            ]
          }
      '';

  screenshots = pkgs.runCommand "lazaret-screenshots" { } ''
    ${pkgs.lib.getExe renderScreenshots} $out
  '';
in
{
  inherit
    cachixPush
    publishScreenshots
    renderScreenshots
    screenshots
    ;
}
