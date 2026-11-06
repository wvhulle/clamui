# Development

## Build and test

```sh
nix develop path:.
cargo test
cargo clippy --all-targets
nix flake check path:.
```

`nix flake check` runs the unit tests, Clippy and formatting of the three crates, the checks of the NixOS and Home Manager modules, the screenshot render and four NixOS VM tests. Run one VM test on its own with:

```sh
nix build path:.#checks.x86_64-linux.vm-live-tuning
```

The VM tests are `vm-detection-alerts`, `vm-live-tuning`, `vm-scheduled-scan` and `vm-signature-update`. Each one boots a desktop session with real ClamAV services and drives Lazaret through its D-Bus actions.

`src/host_verification_tests.rs` holds tests that need a real ClamAV host. They are ignored by default:

```sh
cargo test host_ -- --ignored
```

## Run

```sh
nix run path:.
```

Debug builds use the application ID `page.codeberg.wvhulle.Lazaret.Devel` and their own data directory, so they run next to an installed Lazaret without touching its quarantine or settings.

## Rules for changes

- Keep only features that help block viruses or exploits. Lazaret adds value on top of a ClamAV that is already running.
- Never bundle the scan engine. Run `clamdscan --fdpass`, `clamscan` and `freshclam` from `PATH`, through `desktop_integration::flatpak_sandbox`, so the Flatpak keeps working.
- Talk to systemd through `src/systemd_bus/` and read the journal through `src/systemd_journal/`. Don't run `systemctl` or `journalctl`, and don't refresh on timers: react to bus signals and journal wakeups.
- The GUI never runs as root. `settings_helper/` is the only privileged code: it authorizes every request with polkit and enforces `data/protected-clamav-settings.txt` itself, so never rely on the UI for that.
- Model scanner output as `impl Stream`. Split it on bytes and decode lossily, because file names can be arbitrary bytes. Sanitize scanner text before showing it, and keep `set_use_markup: false` on rows that show file names.
- Keep quarantine file operations no-follow and integrity-checked, in this order: copy, pending row, remove source, commit. Never abort a move in progress.

[Architecture](architecture.md) explains the reasons behind these rules.

## Translations

User-facing strings go through `gettext` with literal strings, and untrusted values are substituted last. After changing strings, update the template:

```sh
make update-translation-template
```

To add a language, add its code to `po/LINGUAS` and create `po/<code>.po` from `po/lazaret.pot`.

## Screenshots

```sh
nix build path:.#screenshots
nix run path:.#render-screenshots -- dist/screenshots
```

Screenshots are rendered in a headless sway session with fixture ClamAV programs. `xtask/src/page_screenshots.rs` lists each scenario as typed steps that find widgets by accessibility role and name, such as `WidgetTarget::button("Start Scan")`, so layout changes don't break them. To see the names on a page, run `nix build path:.#render-screenshots` and then `result/bin/list-widgets -- --page=scan`.

On every push to `main`, CI renders the screenshots and pushes them, as wvhulle-bot, to the `screenshots` branch. The README and the guides link to that branch. Never commit images to `main`.

## Packaging

The Debian package is built inside a Debian container with the static xtask:

```sh
nix run path:.#prepare-ci-tools
podman run --rm -v $PWD:/src -w /src debian:trixie .ci-tools/xtask ci-build-debian-package
podman run --rm -v $PWD:/src -w /src ubuntu:26.04 .ci-tools/xtask check-debian-package-install
```

The install check installs the package with its recommended ClamAV packages and checks the shared libraries, the compiled settings schema, the helper's polkit, D-Bus and systemd files, and that merging without runtime changes leaves `clamd.conf` unchanged.

The Flatpak bundle is built from `page.codeberg.wvhulle.Lazaret.json`:

```sh
nix run path:.#build-flatpak-bundle -- dist
flatpak install --user dist/lazaret-x86_64.flatpak
```

## Releases

Releases are cut by [release-plz](https://release-plz.dev/) on Codeberg, configured in `release-plz.toml`:

1. On every push to `main`, `.woodpecker/release.yaml` opens or updates a release pull request. It bumps the version from the conventional commits since the last tag and writes the changelog.
2. Merging that pull request tags `v<version>` and creates a Codeberg release.
3. The release starts `.woodpecker/debian-package.yaml`, which attaches `lazaret_<version>_amd64.deb`, and `.forgejo/workflows/flatpak.yaml`, which attaches `lazaret-x86_64.flatpak`. Each file gets a `.sha256` next to it.

A weekly cron job, `.woodpecker/dependency-update-pr.yaml`, updates `Cargo.lock` and `flake.lock` on the `bot/dependency-updates` branch and opens a pull request. Everything automatic that pushes, opens pull requests or creates releases acts as `wvhulle-bot`, with the `bot_token` secret.
