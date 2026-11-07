# Build from source

## Requirements

- Rust 1.99 (the version in `rust-toolchain.toml`), for example through rustup
- GTK 4.16 and libadwaita 1.6 or newer, GLib and libsystemd, with their development headers
- `pkg-config`, `make`, `gettext` and `glib-compile-schemas`
- ClamAV: `clamdscan` or `clamscan` on `PATH`, and `freshclam`

On Debian and Ubuntu the build dependencies are:

```sh
sudo apt install rustup build-essential pkg-config gettext libgtk-4-dev libadwaita-1-dev libsystemd-dev libglib2.0-dev libglib2.0-bin
```

## Install Lazaret

```sh
git clone https://codeberg.org/wvhulle/lazaret.git
cd lazaret
make build
sudo make install
```

This installs into `/usr/local` by default. Set `PREFIX` to change that, for example `sudo make install PREFIX=/usr`. `make install` installs the app, its data files, the user service, and the ClamAV admin service with its polkit, D-Bus and systemd files.

## Background alerts

```sh
systemctl --user enable --now lazaret.service
```

## Live tuning

The steps are the same as for the Debian package, with the paths under your `PREFIX`. List the allowed settings in `/etc/lazaret/tunable-settings`, then install `$PREFIX/share/lazaret/clamav-daemon-live-tuning.conf` and `clamav-clamonacc-live-tuning.conf` as drop-ins for your clamd and clamonacc services. clamd must be socket-activated, because the admin service waits for the new clamd on that socket after a restart. Check the clamd path and service name for your distribution, and reload systemd and D-Bus afterwards:

```sh
sudo systemctl daemon-reload
sudo systemctl reload dbus
```

See [Debian and Ubuntu](debian-ubuntu.md#live-tuning) for the details.

## API keys for reputation lookups

See [Debian and Ubuntu](debian-ubuntu.md#api-keys-for-reputation-lookups). The `gsettings` keys are the same.

## Uninstall

There is no uninstall target. Remove the files that `make install` lists.
