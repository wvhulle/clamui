# Install on NixOS

## Requirements

- NixOS with flakes enabled
- A graphical session with systemd user services

## Install ClamAV

Lazaret uses the ClamAV of your system. Turn on the daemon and signature updates, and on-access scanning if you want files blocked when they are opened:

```nix
services.clamav = {
  daemon.enable = true;
  updater.enable = true;
  clamonacc.enable = true;
};
```

## Install Lazaret

Add the flake as an input and import one of its modules:

```nix
{
  inputs.lazaret.url = "git+https://codeberg.org/wvhulle/lazaret";

  outputs = { nixpkgs, lazaret, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      modules = [
        lazaret.nixosModules.default
        { services.lazaret.enable = true; }
      ];
    };
  };
}
```

The flake uses the binary cache `wvhulle.cachix.org`. Accept its settings when Nix asks, or Nix builds Lazaret locally.

Choose one module:

- `lazaret.nixosModules.default` installs Lazaret for every user and is required for live tuning and system-wide key files.
- `lazaret.homeManagerModules.default` installs it for one user, from your Home Manager configuration. It also accepts `services.lazaret.settings`, which writes preferences through dconf:

  ```nix
  services.lazaret = {
    enable = true;
    settings = {
      close-action = "minimize";
      notifications-enabled = true;
    };
  };
  ```

  Activation applies these values again, so a change made in the app lasts only until the next switch.

Enable Lazaret in only one of them.

## Background alerts

`services.lazaret.enable` starts `lazaret --background` with your graphical session, so detections by clamd and on-access scanning raise a notification even when the window is closed. Check it with:

```sh
systemctl --user status lazaret.service
```

## Live tuning

Live tuning lets you change chosen clamd settings from the app. It is on whenever `services.lazaret.enable` and `services.clamav.daemon.enable` are both set, and by default allows the six switches on the Detection page. Each change shows what will happen and asks for an administrator password, and a change that leaves clamd unable to start is rolled back.

```nix
services.lazaret.liveTuning = {
  allowedSettings = [ "DetectPUA" "OnAccessMaxFileSize" "MaxThreads" ];
  reductionLifetime = 3600;
};
```

`allowedSettings` only accepts settings whose value type Lazaret knows, so settings that run commands or change identity, such as `VirusEvent` or `User`, fail evaluation. Changes are stored in `/var/lib/lazaret/live-overrides.toml`, outside your Nix files. A change that reduces protection, such as turning off PUA detection, ends on its own after `reductionLifetime` seconds (one day by default). The settings page shows a snippet of the permanent changes to copy into your configuration, and a button to go back to the system configuration.

Set `services.lazaret.liveTuning.enable = false` to keep clamd fully declarative.

## API keys for reputation lookups

Without configuration, keys you paste under **Submissions → Services & Keys** are kept in your keyring. To manage them as secrets instead, point Lazaret at files from agenix or sops-nix. Only the path ends up in the Nix store, and the file has to be readable by your user:

```nix
age.secrets.abuse-ch-key.owner = "alice";
services.lazaret.apiKeyFiles.abuseCh = config.age.secrets.abuse-ch-key.path;
services.lazaret.apiKeyFiles.virustotal = config.age.secrets.virustotal-key.path;
```

When a path is set, Lazaret reads that file and hides the paste field.

## Update

```sh
nix flake update lazaret
sudo nixos-rebuild switch
```

## Uninstall

Remove the module and `services.lazaret`, and switch. Your quarantine stays in `~/.local/share/lazaret` until you delete it.
