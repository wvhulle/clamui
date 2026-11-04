# ClamUI

A native GTK desktop frontend for host-installed ClamAV, built with Relm4 and libadwaita. It scans files and folders through `clamdscan --fdpass`, falls back to `clamscan`, and manages a local quarantine.

This is a hard fork of [ClamUI](https://github.com/linx-systems/clamui). ClamAV itself is not bundled: `clamdscan` or `clamscan` must be on `PATH`.

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
