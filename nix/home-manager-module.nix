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
    enable = lib.mkEnableOption "ClamUI in the background, so detections raise alerts";
    package = lib.mkOption {
      type = lib.types.package;
      default = clamuiFlake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "clamui.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The ClamUI package to run.";
    };
    settings = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.oneOf [
          lib.types.bool
          lib.types.int
          lib.types.str
        ]
      );
      default = { };
      example = {
        close-action = "minimize";
        notifications-enabled = true;
      };
      description = ''
        ClamUI preferences, written through dconf. Activation applies these values again, so a
        change made in the application lasts only until then. API keys stay in the system keyring
        and can't be set here.
      '';
    };
  };

  config = lib.mkIf clamuiSettings.enable {
    home.packages = [ clamuiSettings.package ];
    dconf.settings = lib.mkIf (clamuiSettings.settings != { }) {
      "io/github/wvhulle/ClamUI" = clamuiSettings.settings;
    };
    systemd.user.services.clamui = {
      Unit = {
        Description = "ClamUI detection alerts";
        PartOf = [ "graphical-session.target" ];
        After = [ "graphical-session.target" ];
        Requisite = [ "graphical-session.target" ];
      };
      Service = {
        ExecStart = "${lib.getExe clamuiSettings.package} --background";
        Environment = [
          "PATH=%h/.nix-profile/bin:/etc/profiles/per-user/%u/bin:/run/current-system/sw/bin:/usr/local/bin:/usr/bin"
        ];
        Restart = "on-failure";
      };
      Install.WantedBy = [ "graphical-session.target" ];
    };
  };
}
