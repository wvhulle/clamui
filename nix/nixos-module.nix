clamuiFlake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  clamuiSettings = config.services.clamui;
  liveTuning = clamuiSettings.liveTuning;
  apiKeyFileSettings = lib.filterAttrs (settingName: keyFilePath: keyFilePath != null) {
    virustotal-key-file = clamuiSettings.apiKeyFiles.virustotal;
    abuse-ch-key-file = clamuiSettings.apiKeyFiles.abuseCh;
  };
  isOutsideStore =
    keyFilePath: lib.hasPrefix "/" keyFilePath && !lib.hasPrefix builtins.storeDir keyFilePath;
  clamavSettings = config.services.clamav;
  system = pkgs.stdenv.hostPlatform.system;
  mergedConfigPath = "/run/clamui/clamd.conf";
  helperBusName = "io.github.wvhulle.ClamUI.SettingsHelper";

  protectedSettings = builtins.filter (protectedKey: protectedKey != "") (
    lib.splitString "\n" (builtins.readFile ../data/protected-clamav-settings.txt)
  );
  isProtectedSetting =
    settingKey:
    builtins.any (protectedKey: lib.toLower protectedKey == lib.toLower settingKey) protectedSettings;
  refusedSettings = builtins.filter isProtectedSetting liveTuning.allowedSettings;

  helperDataFiles = pkgs.linkFarm "clamui-settings-helper-data" [
    {
      name = "share/polkit-1/actions/io.github.wvhulle.ClamUI.policy";
      path = ../data/io.github.wvhulle.ClamUI.policy;
    }
    {
      name = "share/dbus-1/system.d/${helperBusName}.conf";
      path = ../data/io.github.wvhulle.ClamUI.SettingsHelper.conf;
    }
    {
      name = "share/dbus-1/system-services/${helperBusName}.service";
      path = ../data/io.github.wvhulle.ClamUI.SettingsHelper.service;
    }
  ];
in
{
  options.services.clamui = {
    enable = lib.mkEnableOption "ClamUI in the background for every graphical user session, so detections raise alerts";
    package = lib.mkOption {
      type = lib.types.package;
      default = clamuiFlake.packages.${system}.default;
      defaultText = lib.literalExpression "clamui.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The ClamUI package to run.";
    };
    apiKeyFiles = {
      virustotal = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = lib.literalExpression "config.age.secrets.virustotal-key.path";
        description = ''
          Runtime path of a file holding the VirusTotal API key, for example an agenix or
          sops-nix secret owned by the desktop user. Only the path is stored, as a system-wide
          dconf default, never the key. When set, ClamUI uses this file and doesn't offer to
          paste a key.
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
    liveTuning = {
      enable = lib.mkEnableOption ''
        changing allowed clamd settings from ClamUI at runtime. Each change asks for administrator
        authorization. Changes are stored outside the Nix configuration, so they drift from it
        until you copy them over
      '';
      helperPackage = lib.mkOption {
        type = lib.types.package;
        default = clamuiFlake.packages.${system}.settings-helper;
        defaultText = lib.literalExpression "clamui.packages.\${pkgs.stdenv.hostPlatform.system}.settings-helper";
        description = "The root helper that validates and applies changes.";
      };
      allowedSettings = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "OnAccessMaxFileSize"
          "OnAccessIncludePath"
        ];
        description = ''
          The clamd settings that may change at runtime. Settings that run commands or change
          identity, such as VirusEvent or User, are refused here and again by the helper.
        '';
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf clamuiSettings.enable {
      environment.systemPackages = [ clamuiSettings.package ];
      systemd.packages = [ clamuiSettings.package ];
      systemd.user.services.clamui = {
        wantedBy = [ "graphical-session.target" ];
        path = [ "/run/current-system/sw" ];
      };
    })
    (lib.mkIf (apiKeyFileSettings != { }) {
      assertions = lib.mapAttrsToList (settingName: keyFilePath: {
        assertion = isOutsideStore keyFilePath;
        message = "services.clamui.apiKeyFiles: ${keyFilePath} must be an absolute path outside the Nix store, so the key never ends up in it";
      }) apiKeyFileSettings;
      programs.dconf = {
        enable = true;
        profiles.user.databases = [
          { settings."io/github/wvhulle/ClamUI" = apiKeyFileSettings; }
        ];
      };
    })
    (lib.mkIf liveTuning.enable {
      assertions = [
        {
          assertion = refusedSettings == [ ];
          message = "services.clamui.liveTuning.allowedSettings contains settings that can never change at runtime: ${lib.concatStringsSep ", " refusedSettings}";
        }
        {
          assertion = clamavSettings.daemon.enable;
          message = "services.clamui.liveTuning needs services.clamav.daemon.enable";
        }
      ];

      environment.etc."clamui/tunable-settings".text = lib.concatLines liveTuning.allowedSettings;
      environment.systemPackages = [ helperDataFiles ];
      services.dbus.packages = [ helperDataFiles ];
      security.polkit.enable = true;

      systemd.tmpfiles.rules = [ "d /var/lib/clamui 0755 root root -" ];

      systemd.services.clamui-settings-helper = {
        description = "ClamUI settings helper";
        requires = [ "clamui-settings-merge.service" ];
        after = [ "clamui-settings-merge.service" ];
        serviceConfig = {
          Type = "dbus";
          BusName = helperBusName;
          ExecStart = "${lib.getExe liveTuning.helperPackage} serve";
          ReadWritePaths = [
            "/var/lib/clamui"
            "/run/clamui"
          ];
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
        };
      };

      systemd.services.clamui-settings-merge = {
        description = "Merge runtime changes into the clamd configuration";
        before = [
          "clamav-daemon.service"
          "clamav-clamonacc.service"
          "clamdscan.service"
        ];
        requiredBy = [
          "clamav-daemon.service"
        ]
        ++ lib.optional clamavSettings.clamonacc.enable "clamav-clamonacc.service"
        ++ lib.optional clamavSettings.scanner.enable "clamdscan.service";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          RuntimeDirectory = "clamui";
          RuntimeDirectoryPreserve = true;
          ExecStart = "${lib.getExe liveTuning.helperPackage} merge";
        };
      };

      systemd.services.clamav-daemon.serviceConfig = {
        ExecStart = lib.mkForce "${clamavSettings.package}/bin/clamd --config-file=${mergedConfigPath}";
        RuntimeDirectoryPreserve = true;
      };
      systemd.services.clamav-clamonacc.serviceConfig.ExecStart =
        lib.mkIf clamavSettings.clamonacc.enable (
          lib.mkForce "${clamavSettings.package}/bin/clamonacc -F --fdpass --config-file=${mergedConfigPath}"
        );
      systemd.services.clamdscan.serviceConfig.ExecStart = lib.mkIf clamavSettings.scanner.enable (
        lib.mkForce "${clamavSettings.package}/bin/clamdscan --multiscan --fdpass --infected --allmatch --config-file=${mergedConfigPath} ${lib.concatStringsSep " " clamavSettings.scanner.scanDirectories}"
      );
    })
  ];
}
