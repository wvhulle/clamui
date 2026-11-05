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

  helperDataFiles = pkgs.runCommand "clamui-settings-helper-data" { } ''
    install -Dm644 ${../data/io.github.wvhulle.ClamUI.policy} $out/share/polkit-1/actions/io.github.wvhulle.ClamUI.policy
    install -Dm644 ${../data/io.github.wvhulle.ClamUI.SettingsHelper.conf} $out/share/dbus-1/system.d/${helperBusName}.conf
    install -Dm644 ${../data/io.github.wvhulle.ClamUI.SettingsHelper.service} $out/share/dbus-1/system-services/${helperBusName}.service
  '';
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
