# Lazaret contributor guide

The `lazaret` crate at the repository root, plus `xtask/` for repository tasks. It uses Relm4 and libadwaita. Source is organised by feature: `src/malware_scan/` and `src/file_quarantine/` hold logic next to pages. `data/` holds the desktop entry and icons, `po/` the translations.

- **Purpose:** Lazaret adds value on top of a backend that's already running. Keep only features related to virus or exploit blocking.
- **Host ClamAV:** never bundle the engine. Scanning runs `clamdscan --fdpass` or `clamscan` from `PATH`.
- **Host services:** use `src/systemd_bus/` (D-Bus) for units and `src/systemd_journal/` (libsystemd) for the journal. Don't run `systemctl` or `journalctl`, and don't refresh on timers: react to bus signals and journal wakeups.
- **Privilege:** the GUI never runs as root. `settings_helper/` is the only privileged code: it authorizes each request with polkit and enforces `data/protected-clamav-settings.txt` itself, so never rely on the UI for that. Its `nix/module-checks.nix` VM test must keep passing.
- **Scanner output:** model it as `impl Stream`. Split on bytes and decode lossily, because filenames can be arbitrary bytes. Sanitize scanner text before display, and keep `set_use_markup: false` on rows showing filenames.
- **Quarantine safety:** keep file operations no-follow and integrity-checked, and keep the order: copy, pending row, remove source, commit. Never abort a move in progress.
- **Translations:** use `gettext` with literal strings and substitute untrusted values last. Run `make update-translation-template` after changing strings.
- **Checks:** `nix flake check path:.`. `src/host_verification_tests.rs` holds ignored tests that need a real ClamAV host.
- **Screenshots:** `cargo xtask render-screenshots` renders each page in an isolated headless sway session with fixture ClamAV programs. `nix build path:.#screenshots` supplies its tools. Compare renders with `docs/feature-parity.md` when adding features.
