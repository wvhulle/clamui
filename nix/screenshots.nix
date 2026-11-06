{
  pkgs,
  clamui,
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
      for taskName in render-screenshots list-widgets; do
        makeWrapper $out/bin/xtask $out/bin/$taskName \
          --add-flags $taskName \
          --prefix PATH : ${
            pkgs.lib.makeBinPath [
              clamui
              pkgs.dbus
              pkgs.grim
              pkgs.sqlite
              pkgs.sway
            ]
          } \
          --prefix PATH : ${pkgs.at-spi2-core}/libexec \
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

  screenshots = pkgs.runCommand "clamui-screenshots" { } ''
    ${pkgs.lib.getExe renderScreenshots} $out
  '';
in
{
  inherit publishScreenshots renderScreenshots screenshots;
}
