{ lazaretModule }:
let
  machineModule = machineName: {
    imports = [
      lazaretModule
      ./shared/common.nix
      ./${machineName}/machine.nix
    ];
    networking.hostName = "lazaret-${machineName}";
  };

  machineDescriptions = {
    detection-alerts = "a desktop with on-access blocking, for alerts, the tray and quarantining a blocked file";
    scheduled-scan = "a desktop with a system scan timer, for Run Now through a real password prompt";
    signature-update = "updaters with no network and a fixture URLhaus key, for Update Now keeping keys out of the UI";
    live-tuning = "the root admin service, with real polkit prompts, refused settings and rollback";
  };
in
{
  inherit machineDescriptions;

  checksFor =
    pkgs:
    pkgs.lib.mapAttrs' (
      machineName: _machineDescription:
      pkgs.lib.nameValuePair "vm-${machineName}" (
        pkgs.testers.runNixOSTest (
          import ./${machineName}/check.nix {
            machine = machineModule machineName;
          }
        )
      )
    ) machineDescriptions;
}
