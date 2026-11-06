{ pkgs, ... }:
{
  imports = [ ../shared/desktop-session.nix ];

  services.lazaret = {
    enable = true;
    liveTuning = {
      enable = true;
      allowedSettings = [
        "MaxThreads"
        "OnAccessMaxFileSize"
        "NotARealClamdOption"
      ];
    };
  };

  services.clamav.daemon.settings.MaxThreads = 4;

  environment.systemPackages = [ pkgs.glib ];
}
