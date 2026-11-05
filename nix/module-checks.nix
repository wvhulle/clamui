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
  live-tuning-vm-test = pkgs.testers.runNixOSTest {
    name = "clamui-live-tuning";
    nodes.machine = {
      imports = [ self.nixosModules.default ];
      services.clamav.daemon.enable = true;
      services.clamui.liveTuning = {
        enable = true;
        allowedSettings = [
          "MaxThreads"
          "OnAccessMaxFileSize"
          "NotARealClamdOption"
        ];
      };
      systemd.tmpfiles.rules = [
        "d /var/lib/clamav 0755 clamav clamav -"
        "f /var/lib/clamav/fixture.hdb 0644 clamav clamav - 44d88612fea8a8f36de82e1278abb02f:68:Fixture.Eicar"
      ];
      virtualisation.memorySize = 2048;
    };
    testScript = ''
      def busctl_apply(key, value):
          return machine.execute(
              f"busctl --timeout=400 call io.github.wvhulle.ClamUI.SettingsHelper "
              f"/io/github/wvhulle/ClamUI/SettingsHelper "
              f"io.github.wvhulle.ClamUI.SettingsHelper ApplyChanges 'a(ss)' 1 {key} {value} 2>&1"
          )

      machine.wait_for_unit("clamui-settings-merge.service")
      machine.succeed("systemctl start clamav-daemon.service")
      machine.wait_for_unit("clamav-daemon.service")
      machine.wait_until_succeeds("clamdscan --config-file=/run/clamui/clamd.conf --ping 1", timeout=120)

      with subtest("the socket survives a daemon restart"):
          machine.succeed("test -S /run/clamav/clamd.ctl")
          machine.succeed("systemctl restart clamav-daemon.service")
          machine.succeed("test -S /run/clamav/clamd.ctl")
          machine.wait_until_succeeds("clamdscan --config-file=/run/clamui/clamd.conf --ping 1", timeout=120)

      with subtest("the daemon reads the merged configuration"):
          machine.succeed("systemctl cat clamav-daemon.service | grep -- --config-file=/run/clamui/clamd.conf")
          assert "DatabaseDirectory" in machine.succeed("cat /run/clamui/clamd.conf")

      with subtest("an allowed change is applied and clamd stays healthy"):
          status, output = busctl_apply("MaxThreads", "7")
          assert status == 0 and "applied" in output, output
          assert "MaxThreads 7" in machine.succeed("cat /run/clamui/clamd.conf")
          machine.wait_until_succeeds("clamdscan --config-file=/run/clamui/clamd.conf --ping 1", timeout=120)

      with subtest("protected and unlisted settings are refused by the helper"):
          for key, value in (("VirusEvent", "/bin/sh"), ("User", "root"), ("MaxFileSize", "1M")):
              status, output = busctl_apply(key, value)
              assert status != 0, output
          merged = machine.succeed("cat /run/clamui/clamd.conf")
          assert "VirusEvent" not in merged and "User root" not in merged and "MaxFileSize" not in merged

      with subtest("a protected key planted in the overrides is dropped at merge"):
          machine.succeed("printf 'VirusEvent /bin/sh\\nUser root\\nMaxThreads 5\\n' > /var/lib/clamui/clamd-overrides.conf")
          machine.succeed("systemctl restart clamui-settings-merge.service")
          merged = machine.succeed("cat /run/clamui/clamd.conf")
          assert "VirusEvent" not in merged and "User root" not in merged
          assert "MaxThreads 5" in merged

      def wait_for_clamd_after_merge():
          machine.succeed("systemctl reset-failed clamav-daemon.service")
          machine.succeed("systemctl restart clamui-settings-merge.service")
          machine.succeed("systemctl reset-failed clamav-daemon.service")
          machine.succeed("systemctl start clamav-daemon.service")
          machine.wait_until_succeeds("clamdscan --config-file=/run/clamui/clamd.conf --ping 1", timeout=120)

      with subtest("clamd still starts when the overrides cannot be used"):
          machine.succeed("printf 'not a valid line\\n\\0\\0' > /var/lib/clamui/clamd-overrides.conf")
          wait_for_clamd_after_merge()

      with subtest("an unhealthy restart restores the previous settings"):
          machine.succeed("printf 'MaxThreads 6\\n' > /var/lib/clamui/clamd-overrides.conf")
          wait_for_clamd_after_merge()
          machine.succeed("systemctl reset-failed clamav-daemon.service")
          status, output = busctl_apply("NotARealClamdOption", "rejected")
          assert status == 0 and "rolled-back" in output, output
          overrides = machine.succeed("cat /var/lib/clamui/clamd-overrides.conf")
          assert overrides.strip() == "MaxThreads 6", overrides
          assert "NotARealClamdOption" not in machine.succeed("cat /run/clamui/clamd.conf")
          machine.succeed("clamdscan --config-file=/run/clamui/clamd.conf --ping 1")
    '';
  };
  nixos-background-service = backgroundServiceSystem.config.systemd.user.units."clamui.service".unit;
  home-manager-background-service = pkgs.writeText "clamui-home-manager-service.json" (
    builtins.toJSON {
      service = homeManagerEvaluation.config.systemd.user.services.clamui;
      settings = homeManagerEvaluation.config.dconf.settings;
    }
  );
}
