{ lib, pkgs, ... }:
{
  imports = [ ../shared/desktop-session.nix ];

  services.lazaret.enable = true;

  services.clamav = {
    updater.enable = true;
    fangfrisch = {
      enable = true;
      sanesecurity.enable = false;
      urlhaus.authKeyFile = ./urlhaus-fixture-key;
    };
  };

  systemd.services.clamav-fangfrisch.serviceConfig.ExecStart =
    lib.mkForce "${lib.getExe pkgs.fangfrisch} --conf \${RUNTIME_DIRECTORY}/fangfrisch.conf refresh";

  environment.systemPackages = [ pkgs.glib ];
}
