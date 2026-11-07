{ lib, pkgs, ... }:
{
  imports = [ ../shared/desktop-session.nix ];

  services.lazaret = {
    enable = true;
    liveTuning = {
      allowedSettings = [
        "MaxThreads"
        "OnAccessMaxFileSize"
        "DetectPUA"
      ];
      reductionLifetime = 30;
    };
  };

  services.clamav.daemon.settings.MaxThreads = 4;

  systemd.services.clamav-daemon.serviceConfig.ExecStartPre = [
    "${pkgs.bash}/bin/bash -c '! ${pkgs.gnugrep}/bin/grep -qx \"MaxThreads 3\" /etc/clamav/clamd.conf'"
  ];

  specialisation.newBase.configuration.services.clamav.daemon.settings.MaxThreads = lib.mkForce 11;

  environment.systemPackages = [
    pkgs.glib
    pkgs.util-linux
  ];
}
