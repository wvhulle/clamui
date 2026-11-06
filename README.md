# Lazaret

A native GTK desktop frontend for host-installed ClamAV, built with Relm4 and libadwaita. It scans files and folders through `clamdscan --fdpass`, falls back to `clamscan`, and manages a local quarantine.

Lazaret is a hard fork of [ClamUI](https://github.com/linx-systems/clamui). ClamAV itself is not bundled: `clamdscan` or `clamscan` must be on `PATH`.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan.png" width="800" alt="The Scan page, with a drop zone for files and folders above the scan options">

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/results-before-quarantine.png" width="800" alt="Scan results showing two threats found, with a button to quarantine both">

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/protection.png" width="800" alt="The Protection page, summarizing signatures, the daemon, on-access blocking and scheduled scans">

## NixOS and Home Manager

The flake exports `nixosModules.default` and `homeManagerModules.default`. Either one runs Lazaret in the background, so detections raise alerts. Enable one per user. Neither configures ClamAV itself.

```nix
services.lazaret.enable = true;
```

Optionally, let Lazaret change chosen `clamd` settings at runtime. Each change shows what will happen and asks for administrator authorization. Settings that run commands or change identity are refused, and changes that leave ClamAV unhealthy are rolled back. Changes live outside your Nix files until you copy them over.

```nix
services.lazaret.liveTuning = {
  enable = true;
  allowedSettings = [ "OnAccessMaxFileSize" ];
};
```

API keys for the reputation check in Quarantine can come from agenix or sops-nix. Only the path ends up in your configuration; the secret has to be readable by your user. When a path is set, Lazaret uses that file and hides the paste field. Without it, keys you paste are kept in the system keyring.

```nix
age.secrets.abuse-ch-key.owner = "alice";
services.lazaret.apiKeyFiles.abuseCh = config.age.secrets.abuse-ch-key.path;
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

Screenshots are rendered in a headless sway session. `xtask/src/page_screenshots.rs` lists each scenario as typed steps that find widgets by accessibility role and name, such as `WidgetTarget::button("Start Scan")`, so layout changes don't break them. To see the names on a page, run `nix build path:.#render-screenshots` and then `result/bin/list-widgets -- --page=scan`. On every push to `main`, CI renders them and publishes them to the `screenshots` branch.

## License

MIT. See [LICENSE](LICENSE) and [AUTHORS](AUTHORS).
