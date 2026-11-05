clamuiFlake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  clamuiSettings = config.services.clamui;
in
{
  options.services.clamui = {
    enable = lib.mkEnableOption "ClamUI in the background for every graphical user session, so detections raise alerts";
    package = lib.mkOption {
      type = lib.types.package;
      default = clamuiFlake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "clamui.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The ClamUI package to run.";
    };
  };

  config = lib.mkIf clamuiSettings.enable {
    environment.systemPackages = [ clamuiSettings.package ];
    systemd.packages = [ clamuiSettings.package ];
    systemd.user.services.clamui = {
      wantedBy = [ "graphical-session.target" ];
      path = [ "/run/current-system/sw" ];
    };
  };
}
