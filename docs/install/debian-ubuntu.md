# Install on Debian and Ubuntu

## Requirements

- Debian 13 (trixie) or Ubuntu 26.04, on x86_64
- A desktop session with systemd user services

## Install ClamAV

```sh
sudo apt install clamav clamav-daemon clamav-freshclam clamdscan
```

`clamav-daemon` keeps the signatures in memory, so scans start at once, and `clamav-freshclam` keeps the signatures up to date. Lazaret falls back to `clamscan` when the daemon isn't running.

## Install Lazaret

Download `lazaret_<version>_amd64.deb` from the [releases](https://codeberg.org/wvhulle/lazaret/releases), check it against its `.sha256` file, and install it:

```sh
sha256sum --check lazaret_<version>_amd64.deb.sha256
sudo apt install ./lazaret_<version>_amd64.deb
```

The package installs the app, its ClamAV admin service and the systemd and D-Bus files the admin service needs. It recommends the ClamAV packages above, so `apt` installs them too unless you turn recommends off.

## Background alerts

To raise a notification when clamd or on-access scanning detects a file, start Lazaret in the background with your session:

```sh
systemctl --user enable --now lazaret.service
```

## Live tuning

Live tuning lets you change chosen clamd settings from the app, after an administrator password prompt. Only settings whose value type Lazaret knows can be allowed, so settings that run commands or change identity, such as `VirusEvent` or `User`, are never accepted, and a change that leaves clamd unable to start is rolled back. A change that reduces protection ends on its own after `/etc/lazaret/reduction-lifetime` seconds (one day if the file is missing). It is off until you allow settings and let clamd and clamonacc see the merged configuration.

1. List the settings you allow, one per line:

   ```sh
   printf 'DetectPUA\nMaxThreads\nOnAccessMaxFileSize\n' | sudo tee /etc/lazaret/tunable-settings
   ```

2. Let clamd and clamonacc read the configuration that Lazaret merges from `/etc/clamav/clamd.conf` and your changes. The drop-ins bind the merged file over `/etc/clamav/clamd.conf` for these services only, so their start commands stay unchanged:

   ```sh
   sudo install -Dm644 /usr/share/lazaret/clamav-daemon-live-tuning.conf \
     /etc/systemd/system/clamav-daemon.service.d/lazaret.conf
   sudo install -Dm644 /usr/share/lazaret/clamav-clamonacc-live-tuning.conf \
     /etc/systemd/system/clamav-clamonacc.service.d/lazaret.conf
   sudo systemctl daemon-reload
   sudo systemctl restart clamav-daemon
   ```

Without changes, the merged file is identical to `/etc/clamav/clamd.conf`. Changes are stored in `/var/lib/lazaret/live-overrides.toml`. To undo live tuning, remove the drop-ins, reload systemd and restart `clamav-daemon`.

## API keys for reputation lookups

Keys you paste under **Submissions → Services & Keys** are kept in your keyring. To read them from files instead, for example files managed by your configuration tooling, set the paths:

```sh
gsettings set page.codeberg.wvhulle.Lazaret virustotal-key-file /home/alice/.config/lazaret/virustotal.key
gsettings set page.codeberg.wvhulle.Lazaret abuse-ch-key-file /home/alice/.config/lazaret/abuse-ch.key
```

When a path is set, Lazaret reads that file and hides the paste field.

## Update

Install the `.deb` of the new release the same way. Your settings and quarantine are kept.

## Uninstall

```sh
systemctl --user disable --now lazaret.service
sudo apt remove lazaret
```

If you turned on live tuning, remove `/etc/systemd/system/clamav-daemon.service.d/lazaret.conf` first and restart `clamav-daemon`. Your quarantine stays in `~/.local/share/lazaret` until you delete it.
