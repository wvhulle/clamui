# Feature parity with upstream ClamUI

Compares the headless renders from `nix build path:.#screenshots` with upstream's screenshots and sources on the `master` bookmark. Update this list as features land.

## Shell

- [x] Sidebar icons, using a `gtk::ListBox` with the `navigation-sidebar` style.
- [x] Pages: Protection, which replaces Audit and Statistics and opens first, and Logs.
- [x] Empty states with `adw::StatusPage`.

## Scan

- [x] Target list: add, remove and review targets before starting, with an explicit Start Scan.
- [x] Drag and drop with `gtk::DropTarget`.
- [x] Profile selector with `adw::ComboRow`, and a Manage Profiles dialog.
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

Deliberately removed: its protection status came from scan recency rather than from what the backend is doing, and its totals don't help anyone act.

## Components

- [x] Status, version and install commands per component.
- [x] Per-component icons.

## Database

- [x] freshclam, service and definition status, updates and log, in a dialog opened from the Protection page.

Force update is deliberately not ported: upstream ran a shell script as root.

## Quarantine

- [x] List, restore and delete, including files blocked by on-access scanning.
- [x] Storage summary: total size and item count.
- [x] Search with `gtk::SearchEntry`.
- [x] Refresh.
- [x] Clear Old Items, after 30 days and with confirmation.

## Audit

- [x] Firewall service, mandatory access control and intrusion prevention, with status and suggested commands, below the Protection timeline.
- [x] A row stating that ClamAV doesn't cover rootkits, with a copyable check command.

Only checks related to virus or exploit blocking are kept. SSH settings, open ports, firewall rule parsing, automatic updates, Portmaster, Lynis and chkrootkit are deliberately left out.

## Network

Deliberately removed: a socket list doesn't block anything.

## Profiles

- [x] Default and custom profiles: run, edit, delete.
- [x] Create, import, export and restore defaults.

## Preferences

Use `adw::PreferencesDialog` and `gio::Settings`.

- [x] Live scan progress and scan backend choice.
- [x] Close action and starting in the background, with the tray.
- [x] Exclusions: presets, custom paths and patterns.
- [x] Database and scanner settings, shown read-only. Editing is deliberately not ported: it needed a root helper, and `VirusEvent` and `OnUpdateExecute` run commands.
- [x] Scheduled scans with user systemd timers. There's no cron fallback: non-systemd hosts see that scheduling is unavailable.
- [x] On-access settings, shown read-only for the same reason.
- [x] VirusTotal: key in the system keyring, hash lookup first, and confirmation before any upload. There's no plaintext key fallback. Uploads use a generic file name, so the real name isn't shared.
- [x] Device auto-scan for removable and external drives, without auto-quarantine or network and internal volumes.

Debug logs and the in-app language picker are deliberately not ported: this fork has no debug logging, and the language follows the system locale.

## Desktop integration

- [x] Tray with `ksni`.
- [x] Notifications with `gio::Notification`, and over D-Bus from scheduled scans.
- [x] A second launch forwards its paths to the running window.
- [x] File manager actions for Nautilus, Nemo and Dolphin. Scan only, with no VirusTotal action.
