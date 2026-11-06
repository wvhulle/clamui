lazaretFlake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  lazaretSettings = config.services.lazaret;
  apiKeyFileSettings = lib.filterAttrs (settingName: keyFilePath: keyFilePath != null) {
    virustotal-key-file = lazaretSettings.apiKeyFiles.virustotal;
    abuse-ch-key-file = lazaretSettings.apiKeyFiles.abuseCh;
  };
  isOutsideStore =
    keyFilePath: lib.hasPrefix "/" keyFilePath && !lib.hasPrefix builtins.storeDir keyFilePath;
in
{
  options.services.lazaret = {
    enable = lib.mkEnableOption "Lazaret in the background, so detections raise alerts";
    package = lib.mkOption {
      type = lib.types.package;
      default = lazaretFlake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "lazaret.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The Lazaret package to run.";
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
        Lazaret preferences, written through dconf. Activation applies these values again, so a
        change made in the application lasts only until then. Set API keys with `apiKeyFiles`.
      '';
    };
    apiKeyFiles = {
      virustotal = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = lib.literalExpression "config.age.secrets.virustotal-key.path";
        description = ''
          Runtime path of a file holding the VirusTotal API key, for example an agenix or
          sops-nix secret readable by your user. Only the path is stored, never the key. When set,
          Lazaret uses this file and doesn't offer to paste a key.
        '';
      };
      abuseCh = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = lib.literalExpression "config.age.secrets.abuse-ch-key.path";
        description = ''
          Runtime path of a file holding the abuse.ch Auth-Key used for MalwareBazaar lookups.
          Only the path is stored, never the key.
        '';
      };
    };
  };

  config = lib.mkIf lazaretSettings.enable {
    home.packages = [ lazaretSettings.package ];
    assertions = lib.mapAttrsToList (settingName: keyFilePath: {
      assertion = isOutsideStore keyFilePath;
      message = "services.lazaret.apiKeyFiles: ${keyFilePath} must be an absolute path outside the Nix store, so the key never ends up in it";
    }) apiKeyFileSettings;
    dconf.settings = lib.mkIf (lazaretSettings.settings != { } || apiKeyFileSettings != { }) {
      "page/codeberg/wvhulle/Lazaret" = lazaretSettings.settings // apiKeyFileSettings;
    };
    systemd.user.services.lazaret = {
      Unit = {
        Description = "Lazaret detection alerts";
        PartOf = [ "graphical-session.target" ];
        After = [ "graphical-session.target" ];
        Requisite = [ "graphical-session.target" ];
      };
      Service = {
        ExecStart = "${lib.getExe lazaretSettings.package} --background";
        Environment = [
          "PATH=%h/.nix-profile/bin:/etc/profiles/per-user/%u/bin:/run/current-system/sw/bin:/usr/local/bin:/usr/bin"
        ];
        Restart = "on-failure";
      };
      Install.WantedBy = [ "graphical-session.target" ];
    };
  };
}
