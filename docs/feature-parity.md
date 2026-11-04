# Feature parity with upstream ClamUI

Compares the headless renders from `nix build path:.#screenshots` with upstream's screenshots and sources on the `master` bookmark. Update this list as features land.

## Shell

- [x] Sidebar icons, using a `gtk::ListBox` with the `navigation-sidebar` style.
- [ ] Pages: Logs, Statistics, Audit, Network.
- [ ] Empty states with `adw::StatusPage`.

## Scan

- [ ] Target list: add, remove and review targets before starting, with an explicit Start Scan.
- [ ] Drag and drop with `gtk::DropTarget`.
- [ ] Profile selector with `adw::ComboRow`, and a Manage Profiles dialog.
- [ ] EICAR test button.
- [ ] Active backend label.
- [x] Scan paths passed on the command line.

## Scan results

- [ ] Results in an `adw::Dialog`, with files, directories and threats statistics.
- [ ] Severity badge per threat. Removed from this fork as unused; restore with the display.
- [ ] Per-threat Exclude and Copy Path actions.
- [ ] Quarantine All.
- [ ] Export results.

## Logs

- [ ] Scan and update history, persisted.
- [ ] History list with status, time and path, and a details pane.
- [ ] Copy and export a log entry, export all, clear all.
- [ ] ClamAV daemon log tab.

## Statistics

- [ ] Protection status and last scan.
- [ ] Timeframe selection: day, week, month, all time.
- [ ] Totals: scans, files, threats, clean scans, average duration.
- [ ] Scan activity trend and quick actions.

## Components

- [x] Status, version and install commands per component.
- [x] Per-component icons.

## Database

- [x] freshclam, service and definition status, updates and log.

Force update is deliberately not ported: upstream ran a shell script as root.

## Quarantine

- [x] List, restore and delete, including files blocked by on-access scanning.
- [ ] Storage summary: total size and item count.
- [ ] Search with `gtk::SearchEntry`.
- [ ] Refresh.
- [ ] Clear Old Items.

## Audit

- [ ] System security audit grouped by area, with status and suggested commands.
- [ ] Deep checks. Review the old `pkexec` use before porting.

## Network

- [ ] Local socket list, with no upstream screenshot; port from source.

## Profiles

- [ ] Default and custom profiles: run, edit, delete.
- [ ] Create, import, export and restore defaults.

## Preferences

Use `adw::PreferencesDialog` and `gio::Settings`.

- [ ] Behavior: close action, live scan progress.
- [ ] Exclusions.
- [ ] Database and scanner settings. Editing host ClamAV configuration needs a decision: only with an allowlist, because `VirusEvent` and `OnUpdateExecute` run commands.
- [ ] Scheduled scans with user systemd timers.
- [ ] On-access settings.
- [ ] VirusTotal: key storage, and confirmation before any upload.
- [ ] Debug logs.

## Desktop integration

- [ ] Tray with `ksni`.
- [ ] Notifications with `gio::Notification`.
- [ ] File manager actions.
