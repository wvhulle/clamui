# Feature parity with upstream ClamUI

Compares the headless renders from `nix build path:.#screenshots` with upstream's screenshots and sources on the `master` bookmark. Update this list as features land.

## Shell

- [x] Sidebar icons, using a `gtk::ListBox` with the `navigation-sidebar` style.
- [x] Pages: Logs, Statistics.
- [ ] Pages: Audit, Network.
- [ ] Empty states with `adw::StatusPage`.

## Scan

- [x] Target list: add, remove and review targets before starting, with an explicit Start Scan.
- [x] Drag and drop with `gtk::DropTarget`.
- [ ] Profile selector with `adw::ComboRow`, and a Manage Profiles dialog.
- [x] EICAR test button.
- [x] Active backend label.
- [x] Scan paths passed on the command line.

## Scan results

- [x] Results in an `adw::Dialog`, with files, directories and threats statistics.
- [x] Severity badge per threat.
- [x] Per-threat Copy Path.
- [x] Per-threat Exclude.
- [x] Quarantine All, with confirmation.
- [x] Export and copy results.

## Logs

- [x] Scan and update history, persisted.
- [x] History list with status, time and path, and a details pane.
- [x] Copy and export a log entry, export all as CSV or JSON, clear all.
- [x] ClamAV daemon log tab with live updates.

## Statistics

- [x] Protection status and last scan. Failed and cancelled scans don't count as protection, and scans run outside ClamUI aren't seen.
- [x] Timeframe selection: day, week, month, all time.
- [x] Totals: scans, files, threats, clean scans, average duration.
- [x] Scan activity trend and quick actions.

## Components

- [x] Status, version and install commands per component.
- [x] Per-component icons.

## Database

- [x] freshclam, service and definition status, updates and log.

Force update is deliberately not ported: upstream ran a shell script as root.

## Quarantine

- [x] List, restore and delete, including files blocked by on-access scanning.
- [x] Storage summary: total size and item count.
- [x] Search with `gtk::SearchEntry`.
- [x] Refresh.
- [x] Clear Old Items, after 30 days and with confirmation.

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

- [x] Live scan progress and scan backend choice.
- [ ] Close action and starting in the background, with the tray.
- [x] Exclusions: presets, custom paths and patterns.
- [ ] Database and scanner settings. Editing host ClamAV configuration needs a decision: only with an allowlist, because `VirusEvent` and `OnUpdateExecute` run commands.
- [ ] Scheduled scans with user systemd timers.
- [ ] On-access settings.
- [ ] VirusTotal: key storage, and confirmation before any upload.
- [ ] Debug logs.

## Desktop integration

- [ ] Tray with `ksni`.
- [ ] Notifications with `gio::Notification`.
- [ ] File manager actions.
