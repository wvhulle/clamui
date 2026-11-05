{ pkgs, ... }:
{
  programs.sway.enable = true;
  security.polkit.enable = true;

  services.greetd = {
    enable = true;
    settings = {
      default_session.command = "sway --config /etc/clamui-test/sway-session.conf";
      initial_session = {
        command = "sway --config /etc/clamui-test/sway-session.conf";
        user = "sample-user";
      };
    };
  };

  environment = {
    etc = {
      "clamui-test/sway-session.conf".source = ./sway-session.conf;
      "clamui-test/start-session-target.nu".source = ./start-session-target.nu;
    };
    pathsToLink = [ "/libexec" ];
    systemPackages = [
      pkgs.adwaita-icon-theme
      pkgs.mako
      pkgs.nushell
      pkgs.polkit_gnome
    ];
    sessionVariables = {
      SWAYSOCK = "/tmp/sway-ipc.sock";
      WLR_RENDERER = "pixman";
      WLR_LIBINPUT_NO_DEVICES = "1";
      XDG_CURRENT_DESKTOP = "sway";
    };
  };

  fonts.packages = [ pkgs.adwaita-fonts ];

  systemd.user.targets.clamui-test-session = {
    bindsTo = [ "graphical-session.target" ];
    wants = [ "graphical-session.target" ];
    after = [ "graphical-session-pre.target" ];
  };

  virtualisation.qemu.options = [
    "-vga none"
    "-device virtio-vga,xres=1280,yres=800"
  ];
}
