{ pkgs, ... }:
{
  imports = [ ../shared/desktop-session.nix ];

  services.lazaret.enable = true;

  services.clamav.scanner = {
    enable = true;
    interval = "Mon *-*-* 12:30:00";
    scanDirectories = [ "/var/lib/sample-scan" ];
  };

  systemd.tmpfiles.rules = [
    "d /var/lib/sample-scan 0755 root root -"
  ];

  environment.systemPackages = [ pkgs.glib ];
}
