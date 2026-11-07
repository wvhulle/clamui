lazaretFlake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  lazaretSettings = config.services.lazaret;
  liveTuning = lazaretSettings.liveTuning;
  apiKeyFileSettings = lib.filterAttrs (settingName: keyFilePath: keyFilePath != null) {
    virustotal-key-file = lazaretSettings.apiKeyFiles.virustotal;
    abuse-ch-key-file = lazaretSettings.apiKeyFiles.abuseCh;
  };
  isOutsideStore =
    keyFilePath: lib.hasPrefix "/" keyFilePath && !lib.hasPrefix builtins.storeDir keyFilePath;
  fangfrischUrlhausKeyFile =
    let
      configuredKeyFile = lib.attrByPath [
        "services"
        "clamav"
        "fangfrisch"
        "urlhaus"
        "authKeyFile"
      ] null config;
    in
    if configuredKeyFile != null && isOutsideStore (toString configuredKeyFile) then
      toString configuredKeyFile
    else
      null;
  declaredSecretsByPath =
    let
      secretsWithPaths =
        secretTool: declaredSecrets:
        lib.mapAttrsToList (secretName: secretSettings: {
          inherit secretName secretTool;
          secretPath = toString (secretSettings.path or "");
          secretOwner = secretSettings.owner or "root";
          secretGroup = secretSettings.group or "root";
          secretMode = secretSettings.mode or "0400";
        }) declaredSecrets;
    in
    secretsWithPaths "age.secrets" (lib.attrByPath [ "age" "secrets" ] { } config)
    ++ secretsWithPaths "sops.secrets" (lib.attrByPath [ "sops" "secrets" ] { } config);
  modeLetsOthersRead =
    secretMode:
    let
      modeDigits = lib.stringToCharacters secretMode;
      groupAndOtherDigits = lib.drop (builtins.length modeDigits - 2) modeDigits;
      digitHasReadBit = modeDigit: lib.toInt modeDigit >= 4;
    in
    builtins.any digitHasReadBit groupAndOtherDigits;
  rootOnlySecretWarnings = lib.concatMap (
    keyFilePath:
    map
      (
        declaredSecret:
        "services.lazaret.apiKeyFiles: ${keyFilePath} is the ${declaredSecret.secretTool}.${declaredSecret.secretName} secret, which only root can read, so Lazaret can't use it for online lookups. Set ${declaredSecret.secretTool}.${declaredSecret.secretName}.group = \"users\" and mode = \"0440\", or owner = your user."
      )
      (
        builtins.filter (
          declaredSecret:
          declaredSecret.secretPath == keyFilePath
          && builtins.elem declaredSecret.secretOwner [
            "root"
            "0"
          ]
          && !modeLetsOthersRead declaredSecret.secretMode
        ) declaredSecretsByPath
      )
  ) (builtins.attrValues apiKeyFileSettings);
  clamavSettings = config.services.clamav;
  system = pkgs.stdenv.hostPlatform.system;
  mergedConfigPath = "/run/lazaret/clamd.conf";
  adminBusName = "page.codeberg.wvhulle.Lazaret.ClamavAdmin";

  protectedSettings = builtins.filter (protectedKey: protectedKey != "") (
    lib.splitString "\n" (builtins.readFile ../data/protected-clamav-settings.txt)
  );
  isProtectedSetting =
    settingKey:
    builtins.any (protectedKey: lib.toLower protectedKey == lib.toLower settingKey) protectedSettings;
  refusedSettings = builtins.filter isProtectedSetting liveTuning.allowedSettings;

  adminServiceDataFiles = pkgs.linkFarm "lazaret-clamav-admin-data" [
    {
      name = "share/polkit-1/actions/page.codeberg.wvhulle.Lazaret.policy";
      path = ../data/page.codeberg.wvhulle.Lazaret.policy;
    }
    {
      name = "share/dbus-1/system.d/${adminBusName}.conf";
      path = ../data/page.codeberg.wvhulle.Lazaret.ClamavAdmin.conf;
    }
    {
      name = "share/dbus-1/system-services/${adminBusName}.service";
      path = ../data/page.codeberg.wvhulle.Lazaret.ClamavAdmin.service;
    }
  ];
in
{
  options.services.lazaret = {
    enable = lib.mkEnableOption "Lazaret in the background for every graphical user session, so detections raise alerts";
    package = lib.mkOption {
      type = lib.types.package;
      default = lazaretFlake.packages.${system}.default;
      defaultText = lib.literalExpression "lazaret.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The Lazaret package to run.";
    };
    apiKeyFiles = {
      virustotal = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = lib.literalExpression "config.age.secrets.virustotal-key.path";
        description = ''
          Runtime path of a file holding the VirusTotal API key, for example an agenix or
          sops-nix secret owned by the desktop user. Only the path is stored, as a system-wide
          dconf default, never the key. When set, Lazaret uses this file and doesn't offer to
          paste a key.
        '';
      };
      abuseCh = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = fangfrischUrlhausKeyFile;
        defaultText = lib.literalExpression "config.services.clamav.fangfrisch.urlhaus.authKeyFile";
        example = lib.literalExpression "config.age.secrets.abuse-ch-key.path";
        description = ''
          Runtime path of a file holding the abuse.ch Auth-Key used for MalwareBazaar lookups.
          Only the path is stored, never the key. Defaults to the key fangfrisch uses for URLhaus
          signature downloads, which the desktop user must be able to read.
        '';
      };
    };
    liveTuning = {
      enable = lib.mkEnableOption ''
        changing allowed clamd settings from Lazaret at runtime. Each change asks for administrator
        authorization. Changes are stored outside the Nix configuration, so they drift from it
        until you copy them over
      '';
      adminServicePackage = lib.mkOption {
        type = lib.types.package;
        default = lazaretFlake.packages.${system}.clamav-admin;
        defaultText = lib.literalExpression "lazaret.packages.\${pkgs.stdenv.hostPlatform.system}.clamav-admin";
        description = "The root admin service that validates and applies changes.";
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
          identity, such as VirusEvent or User, are refused here and again by the admin service.
        '';
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf lazaretSettings.enable {
      environment.systemPackages = [ lazaretSettings.package ];
      systemd.packages = [ lazaretSettings.package ];
      systemd.user.services.lazaret = {
        wantedBy = [ "graphical-session.target" ];
        path = [ "/run/current-system/sw" ];
      };
    })
    (lib.mkIf (apiKeyFileSettings != { }) {
      assertions = lib.mapAttrsToList (settingName: keyFilePath: {
        assertion = isOutsideStore keyFilePath;
        message = "services.lazaret.apiKeyFiles: ${keyFilePath} must be an absolute path outside the Nix store, so the key never ends up in it";
      }) apiKeyFileSettings;
      warnings = rootOnlySecretWarnings;
      programs.dconf = {
        enable = true;
        profiles.user.databases = [
          { settings."page/codeberg/wvhulle/Lazaret" = apiKeyFileSettings; }
        ];
      };
    })
    (lib.mkIf liveTuning.enable {
      assertions = [
        {
          assertion = refusedSettings == [ ];
          message = "services.lazaret.liveTuning.allowedSettings contains settings that can never change at runtime: ${lib.concatStringsSep ", " refusedSettings}";
        }
        {
          assertion = clamavSettings.daemon.enable;
          message = "services.lazaret.liveTuning needs services.clamav.daemon.enable";
        }
      ];

      environment.etc."lazaret/tunable-settings".text = lib.concatLines liveTuning.allowedSettings;
      environment.systemPackages = [ adminServiceDataFiles ];
      services.dbus.packages = [ adminServiceDataFiles ];
      security.polkit.enable = true;

      systemd.tmpfiles.rules = [ "d /var/lib/lazaret 0755 root root -" ];

      systemd.services.lazaret-clamav-admin = {
        description = "Lazaret ClamAV admin service";
        requires = [ "lazaret-settings-merge.service" ];
        after = [ "lazaret-settings-merge.service" ];
        serviceConfig = {
          Type = "dbus";
          BusName = adminBusName;
          ExecStart = "${lib.getExe liveTuning.adminServicePackage} serve";
          ReadWritePaths = [
            "/var/lib/lazaret"
            "/run/lazaret"
            "-/var/lib/clamav"
          ];
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
        };
      };

      systemd.services.lazaret-settings-merge = {
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
          RuntimeDirectory = "lazaret";
          RuntimeDirectoryPreserve = true;
          ExecStart = "${lib.getExe liveTuning.adminServicePackage} merge";
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
