# ClamUI contributor guide

A single Rust crate at the repository root, on Relm4 and libadwaita. Source is organised by feature: `src/malware_scan/` and `src/file_quarantine/` hold logic next to pages. `data/` holds the desktop entry and icons, `po/` the translations.

- **Host ClamAV:** never bundle the engine. Scanning runs `clamdscan --fdpass` or `clamscan` from `PATH`.
- **Scanner output:** model it as `impl Stream`. Split on bytes and decode lossily, because filenames can be arbitrary bytes. Sanitize scanner text before display, and keep `set_use_markup: false` on rows showing filenames.
- **Quarantine safety:** keep file operations no-follow and integrity-checked, and keep the order: copy, pending row, remove source, commit. Never abort a move in progress.
- **Translations:** use `gettext` with literal strings and substitute untrusted values last. Run `make update-translation-template` after changing strings.
- **Checks:** `nix flake check path:.`. `src/host_verification_tests.rs` holds ignored tests that need a real ClamAV host.
