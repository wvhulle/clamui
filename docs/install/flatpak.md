# Install as a Flatpak

Use the Flatpak bundle on distributions without a package. It is not on Flathub: it needs more access to your system than Flathub allows, because it runs the ClamAV of your system.

## Requirements

- Flatpak 1.12 or newer, on x86_64
- The GNOME 49 runtime from Flathub, which `flatpak` installs with the bundle

## Install ClamAV

Install ClamAV with your distribution's package manager, and start the daemon and signature updates:

- Fedora: `sudo dnf install clamav clamd clamav-update`, then `sudo systemctl enable --now clamd@scan clamav-freshclam`
- Arch Linux: `sudo pacman -S clamav`, then `sudo systemctl enable --now clamav-daemon clamav-freshclam`
- openSUSE: `sudo zypper install clamav`, then `sudo systemctl enable --now clamd freshclam`

## Install Lazaret

Download `lazaret-x86_64.flatpak` from the [releases](https://codeberg.org/wvhulle/lazaret/releases), check it against its `.sha256` file, and install it:

```sh
sha256sum --check lazaret-x86_64.flatpak.sha256
flatpak install --user lazaret-x86_64.flatpak
flatpak run page.codeberg.wvhulle.Lazaret
```

## What the sandbox allows

| Permission | Why |
|---|---|
| `--talk-name=org.freedesktop.Flatpak` | Runs `clamdscan`, `clamscan` and `freshclam` on your system with `flatpak-spawn --host` |
| `--filesystem=host` | Scans and quarantines files anywhere you choose |
| `--filesystem=host-etc:ro`, `host-os:ro` | Reads the ClamAV configuration and finds the ClamAV programs |
| `/var/lib/clamav:ro`, `/var/log/clamav:ro`, the journal | Shows the age of the signatures, the clamd log and background detections |
| `xdg-config/systemd`, the systemd D-Bus names | Writes and starts the timer for scheduled scans |
| `org.freedesktop.secrets` | Stores API keys in your keyring |
| `--share=network` | Reputation lookups by hash |

Running programs on the host is a sandbox escape: install the bundle only if you trust it, as you would a `.deb`.

## Background alerts

Turn on **Preferences → Start in the Background**. Lazaret then asks the Background portal to start `lazaret --background` with your session, and detections raise a notification even when the window is closed.

## Live tuning

Not available in the Flatpak. Changing clamd settings needs a helper that runs as root, and a Flatpak can't install one. Use the [Debian package](debian-ubuntu.md#live-tuning) or the [NixOS module](nixos.md#live-tuning), or edit `clamd.conf` yourself.

## API keys for reputation lookups

Keys you paste under **Submissions → Services & Keys** are kept in your keyring. To read them from files instead:

```sh
flatpak run --command=gsettings page.codeberg.wvhulle.Lazaret set page.codeberg.wvhulle.Lazaret virustotal-key-file /home/alice/.config/lazaret/virustotal.key
```

## Update

Install the bundle of the new release the same way.

## Uninstall

```sh
flatpak uninstall --user page.codeberg.wvhulle.Lazaret
```

Turn off scheduled scans first, or remove `~/.config/systemd/user/lazaret-scheduled-scan.*`. The quarantine stays in `~/.var/app/page.codeberg.wvhulle.Lazaret` until you delete it.
