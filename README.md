# ClamUI

A native GTK desktop frontend for host-installed ClamAV, built with Relm4 and libadwaita. It scans files and folders through `clamdscan --fdpass`, falls back to `clamscan`, and manages a local quarantine.

This is a hard fork of [ClamUI](https://github.com/linx-systems/clamui). ClamAV itself is not bundled: `clamdscan` or `clamscan` must be on `PATH`.

## NixOS and Home Manager

The flake exports `nixosModules.default` and `homeManagerModules.default`. Either one runs ClamUI in the background, so detections raise alerts. Enable one per user. Neither configures ClamAV itself.

```nix
services.clamui.enable = true;
```

Optionally, let ClamUI change chosen `clamd` settings at runtime. Each change shows what will happen and asks for administrator authorization. Settings that run commands or change identity are refused, and changes that leave ClamAV unhealthy are rolled back. Changes live outside your Nix files until you copy them over.

```nix
services.clamui.liveTuning = {
  enable = true;
  allowedSettings = [ "OnAccessMaxFileSize" ];
};
```

API keys for the reputation check in Quarantine can come from agenix or sops-nix. Only the path ends up in your configuration; the secret has to be readable by your user. When a path is set, ClamUI uses that file and hides the paste field. Without it, keys you paste are kept in the system keyring.

```nix
age.secrets.abuse-ch-key.owner = "alice";
services.clamui.apiKeyFiles.abuseCh = config.age.secrets.abuse-ch-key.path;
```

## Develop

```sh
nix develop path:.
cargo test
nix flake check path:.
nix run path:.
nix build path:.#screenshots
nix run path:.#render-screenshots -- dist/screenshots
```

## License

MIT. See [LICENSE](LICENSE) and [AUTHORS](AUTHORS).
