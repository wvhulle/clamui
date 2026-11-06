# Lazaret

A GTK desktop front-end for the ClamAV that is already installed on your system. Lazaret scans files and folders through clamd, or with `clamscan` when clamd isn't running. It moves detections into a quarantine, raises alerts when the ClamAV services in the background find something, and schedules scans with systemd timers. It doesn't bundle a virus scanner of its own.

Lazaret is a hard fork of [ClamUI](https://github.com/linx-systems/clamui).

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-results.webp" width="800" alt="Recording of a scan that found two threats, moving both to quarantine">

More screenshots are in [usage](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/usage.md).

## Install

| System | Guide | Live tuning of clamd |
|---|---|---|
| NixOS | [NixOS module or Home Manager module](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/install/nixos.md) | yes |
| Debian 13, Ubuntu 26.04 | [`.deb` from the releases](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/install/debian-ubuntu.md) | yes |
| Other distributions | [Flatpak bundle from the releases](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/install/flatpak.md) | no |
| Anywhere else | [Build from source](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/install/from-source.md) | yes, with manual steps |

## Documentation

- [Usage](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/usage.md): scanning, quarantine, reputation lookups, protection status, alerts and scheduled scans.
- [Architecture](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/architecture.md): how Lazaret talks to ClamAV, systemd and the settings helper.
- [Development](https://codeberg.org/wvhulle/lazaret/src/branch/main/docs/development.md): building, testing, screenshots, translations and releases.

## Contributing

Issues and pull requests are welcome on [Codeberg](https://codeberg.org/wvhulle/lazaret). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE) and [AUTHORS](AUTHORS).
