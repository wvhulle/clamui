#!/usr/bin/env nu

def main []: nothing -> nothing {
  dbus-update-activation-environment --systemd WAYLAND_DISPLAY SWAYSOCK XDG_CURRENT_DESKTOP
  systemctl --user start lazaret-test-session.target
}
