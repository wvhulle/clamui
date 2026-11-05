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
        services.clamui.enable = true;
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
          services.clamui.liveTuning = {
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

  homeManagerOptionStubs =
    { lib, ... }:
    {
      options = {
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
        services.clamui = {
          enable = true;
          settings.close-action = "minimize";
        };
      }
    ];
  };
in
assert failedAssertions [ "OnAccessMaxFileSize" ] == [ ];
assert failedAssertions [ "VirusEvent" ] != [ ];
assert failedAssertions [ "user" ] != [ ];
{
  nixos-background-service = backgroundServiceSystem.config.systemd.user.units."clamui.service".unit;
  home-manager-background-service = pkgs.writeText "clamui-home-manager-service.json" (
    builtins.toJSON {
      service = homeManagerEvaluation.config.systemd.user.services.clamui;
      settings = homeManagerEvaluation.config.dconf.settings;
    }
  );
}
