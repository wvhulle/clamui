{ pkgs, ... }:
{
  system.stateVersion = "26.05";

  users.users.sample-user = {
    isNormalUser = true;
    uid = 1000;
    password = "sample-password";
    extraGroups = [
      "systemd-journal"
      "wheel"
    ];
  };

  services.clamav.daemon.enable = true;

  systemd.tmpfiles.rules = [
    "d /var/lib/clamav 0755 clamav clamav -"
    "f /var/lib/clamav/fixture.hdb 0644 clamav clamav - 44d88612fea8a8f36de82e1278abb02f:68:Win.Fixture.Agent-1"
  ];

  environment.systemPackages = [
    pkgs.sqlite
  ];

  virtualisation = {
    memorySize = 3072;
    cores = 2;
    restrictNetwork = true;
  };
}
