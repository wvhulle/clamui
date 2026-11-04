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
      makeWrapper $out/bin/xtask $out/bin/render-screenshots \
        --add-flags render-screenshots \
        --prefix PATH : ${
          pkgs.lib.makeBinPath [
            clamui
            pkgs.dbus
            pkgs.grim
            pkgs.sqlite
            pkgs.sway
          ]
        } \
        --set FONTCONFIG_FILE ${screenshotFonts}
    '';
    meta.mainProgram = "render-screenshots";
  };

  screenshots = pkgs.runCommand "clamui-screenshots" { } ''
    ${pkgs.lib.getExe renderScreenshots} $out
  '';
in
{
  inherit renderScreenshots screenshots;
}
