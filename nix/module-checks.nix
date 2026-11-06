{
  self,
  nixpkgs,
  pkgs,
}:
let
  backgroundServiceSystem = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      self.nixosModules.default
      {
        services.lazaret.enable = true;
        boot.loader.grub.enable = false;
        fileSystems."/" = {
          device = "nodev";
          fsType = "tmpfs";
        };
        system.stateVersion = "25.11";
      }
    ];
  };

  liveTuningEvaluation =
    allowedSettings:
    nixpkgs.lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        self.nixosModules.default
        {
          services.clamav.daemon.enable = true;
          services.lazaret.liveTuning = {
            enable = true;
            inherit allowedSettings;
          };
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "nodev";
            fsType = "tmpfs";
          };
          system.stateVersion = "25.11";
        }
      ];
    };

  failedAssertions =
    allowedSettings:
    builtins.filter (moduleAssertion: !moduleAssertion.assertion)
      (liveTuningEvaluation allowedSettings).config.assertions;

  keyFileEvaluation =
    keyFilePath:
    nixpkgs.lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        self.nixosModules.default
        {
          services.lazaret.apiKeyFiles.abuseCh = keyFilePath;
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "nodev";
            fsType = "tmpfs";
          };
          system.stateVersion = "25.11";
        }
      ];
    };

  fangfrischKeyEvaluation =
    lazaretKeyModule:
    nixpkgs.lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        self.nixosModules.default
        lazaretKeyModule
        (
          { lib, ... }:
          {
            options.age.secrets = lib.mkOption {
              type = lib.types.attrsOf lib.types.attrs;
              default = { };
            };
            config = {
              services.clamav.fangfrisch.urlhaus.authKeyFile = "/run/agenix/urlhaus-auth-key";
              boot.loader.grub.enable = false;
              fileSystems."/" = {
                device = "nodev";
                fsType = "tmpfs";
              };
              system.stateVersion = "25.11";
            };
          }
        )
      ];
    };

  dconfKeyFileSettings =
    lazaretKeyModule:
    nixpkgs.lib.concatMap (dconfDatabase: [
      (dconfDatabase.settings."page/codeberg/wvhulle/Lazaret" or { })
    ]) (fangfrischKeyEvaluation lazaretKeyModule).config.programs.dconf.profiles.user.databases;

  urlhausSecretWarnings =
    secretSettings:
    builtins.filter (moduleWarning: nixpkgs.lib.hasInfix "age.secrets.urlhaus-auth-key" moduleWarning)
      (fangfrischKeyEvaluation {
        age.secrets.urlhaus-auth-key = {
          path = "/run/agenix/urlhaus-auth-key";
        }
        // secretSettings;
      }).config.warnings;

  failedKeyFileAssertions =
    keyFilePath:
    builtins.filter (moduleAssertion: !moduleAssertion.assertion)
      (keyFileEvaluation keyFilePath).config.assertions;

  homeManagerOptionStubs =
    { lib, ... }:
    {
      options = {
        assertions = lib.mkOption {
          type = lib.types.listOf lib.types.attrs;
          default = [ ];
        };
        home.packages = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
        };
        dconf.settings = lib.mkOption {
          type = lib.types.attrsOf lib.types.attrs;
          default = { };
        };
        systemd.user.services = lib.mkOption {
          type = lib.types.attrsOf lib.types.attrs;
          default = { };
        };
      };
    };

  homeManagerEvaluation = pkgs.lib.evalModules {
    specialArgs = { inherit pkgs; };
    modules = [
      self.homeManagerModules.default
      homeManagerOptionStubs
      {
        services.lazaret = {
          enable = true;
          settings.close-action = "minimize";
          apiKeyFiles.abuseCh = "/run/agenix/abuse-ch-key";
        };
      }
    ];
  };
in
assert failedAssertions [ "OnAccessMaxFileSize" ] == [ ];
assert failedAssertions [ "VirusEvent" ] != [ ];
assert failedAssertions [ "user" ] != [ ];
assert failedKeyFileAssertions "/run/agenix/abuse-ch-key" == [ ];
assert failedKeyFileAssertions "/nix/store/abc-abuse-ch-key" != [ ];
assert failedKeyFileAssertions "relative/abuse-ch-key" != [ ];
assert
  (keyFileEvaluation "/run/agenix/abuse-ch-key").config.programs.dconf.profiles.user.databases != [ ];
assert dconfKeyFileSettings { } == [ { abuse-ch-key-file = "/run/agenix/urlhaus-auth-key"; } ];
assert
  dconfKeyFileSettings { services.lazaret.apiKeyFiles.abuseCh = "/run/agenix/abuse-ch-key"; } == [
    { abuse-ch-key-file = "/run/agenix/abuse-ch-key"; }
  ];
assert !((keyFileEvaluation null).config.programs.dconf.profiles ? user);
assert urlhausSecretWarnings { } != [ ];
assert
  urlhausSecretWarnings {
    group = "users";
    mode = "0440";
  } == [ ];
assert urlhausSecretWarnings { owner = "wvhulle"; } == [ ];
{
  nixos-background-service = backgroundServiceSystem.config.systemd.user.units."lazaret.service".unit;
  home-manager-background-service = pkgs.writeText "lazaret-home-manager-service.json" (
    builtins.toJSON {
      service = homeManagerEvaluation.config.systemd.user.services.lazaret;
      settings = homeManagerEvaluation.config.dconf.settings;
    }
  );
}
