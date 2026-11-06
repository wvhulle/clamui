{ pkgs, ... }:
{
  imports = [ ../shared/desktop-session.nix ];

  services.lazaret.enable = true;

  services.clamav = {
    clamonacc.enable = true;
    daemon.settings = {
      OnAccessIncludePath = [ "/home/sample-user/Downloads" ];
      OnAccessPrevention = true;
      OnAccessExtraScanning = true;
      OnAccessMaxFileSize = "100M";
    };
  };

  systemd.tmpfiles.rules = [
    "d /home/sample-user/Downloads 0755 sample-user users -"
  ];

  environment.systemPackages = [ pkgs.glib ];
}
