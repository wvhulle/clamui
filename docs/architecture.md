# Architecture

Lazaret is a desktop front-end for the ClamAV that is already installed on the host. It never bundles a scan engine and never runs as root. This page describes how the pieces fit together and which rules keep them safe. The rules for changing the code are in [development](development.md).

## Components

```mermaid
flowchart LR
    subgraph gui["lazaret (desktop user)"]
        scan["scans/manual_scan_page"]
        quarantine["findings/quarantine_page"]
        shell["application_window"]
        updates["signatures/database_updates_page"]
        detections["findings/detections_page"]
        schedules["scans/scheduled_scans_page"]
        lookups["host_services/threat_intel"]
        settings["shared_widgets/engine_settings"]
    end

    subgraph host["Host"]
        clamdscan["clamdscan / clamscan"]
        freshclam["freshclam"]
        clamd[("clamd socket")]
        systemd["systemd system and user managers"]
        journal[("systemd journal")]
        keyring["Secret Service keyring"]
    end

    helper["lazaret-settings-helper (root)"]
    polkit["polkit"]
    internet["VirusTotal, MalwareBazaar, CIRCL"]
    database[("quarantine and history databases")]

    scan -->|spawns| clamdscan
    clamdscan --> clamd
    shell -->|D-Bus| systemd
    updates -->|spawns| freshclam
    detections -->|reads| journal
    schedules -->|writes timer units, D-Bus| systemd
    quarantine --> database
    lookups -->|HTTPS| internet
    lookups --> keyring
    settings -->|system bus| helper
    helper -->|authorizes| polkit
    helper -->|restarts| systemd
```

The source follows the window as you see it. Each sidebar group has a directory under `src/` with one directory per page: `signatures/` (`signature_sources_page/`, `database_updates_page/`), `scans/` (`scan_engine_page/`, `on_access_page/`, `scheduled_scans_page/`, `manual_scan_page/`, `removable_drives_page/`), `findings/` (`detections_page/`, `quarantine_page/`, `trusted_detections_page/`) and `sharing/` (`online_lookups_page/`, `submissions_page/`). The subpages and dialogs you open from a page sit in directories inside it, for example `scans/manual_scan_page/exclusions_page/`. `application_window/` holds the window, the grouped sidebar, page routing, the tray, actions and startup arguments; it owns the protection evidence and passes each page the part it shows, and `preferences_dialog/` holds the Preferences dialog. Widgets that several pages share live in `shared_widgets/`. Code you never see on screen lives in `host_services/`, grouped by what it talks to: the ClamAV programs, the quarantine vault, systemd, the journal, the settings helper and online lookups, with the protection evidence the sidebar and the pages read in `host_services/protection_evidence/`. `headless_modes/` holds the scheduled scan that runs without a window. `settings_helper/` is the only code that runs with privileges, and `xtask/` holds the repository tasks: screenshots and recordings, packaging and releases.

The interface follows the Elm architecture through Relm4. The window shell owns startup, the tray and the close behaviour. A page navigation component owns the sidebar, the page stack and the settings subpages. Every page and dialog keeps its state in a plain model that only `update` changes, in answer to messages from widgets, child components, GTK actions and finished commands. Settings stored in GSettings are mirrored into the models that show them: a change sends a message, and `update` writes it back. Work that waits on the host runs as a command, and its outcome returns as a message, so no state is shared between widgets.

Lazaret talks to the host in three ways, and never through shell commands like `systemctl` or `journalctl`:

- It spawns the ClamAV programs found on `PATH`: `clamdscan --fdpass`, `clamscan` and `freshclam`. It only runs a copy that the desktop user can't replace: the file, every directory above it and every symbolic link on the way must be out of the user's control. Copies the user could replace, such as one in `~/.local/bin`, are skipped and reported on the Scan Engine and Database Updates pages. That way malware running as the user can't plant a fake `clamdscan` that reports every file as clean.
- It talks to systemd over D-Bus (`src/host_services/systemd_bus/`), for unit states, starting units and installing timers.
- It reads the journal through libsystemd (`src/host_services/systemd_journal/`).

Pages react to D-Bus signals and journal wakeups. They don't refresh on timers.

## Scanning

```mermaid
sequenceDiagram
    participant Page as Scan page
    participant Builder as scanner_command_builder
    participant Scanner as clamdscan or clamscan
    participant Parser as scanner_output_parser

    Page->>Builder: targets, profile, exclusions
    Builder->>Scanner: clamdscan --ping 1
    alt clamd answers
        Builder->>Scanner: clamdscan --fdpass --file-list
    else no clamd
        Builder->>Scanner: clamscan -r --tempdir
    end
    loop every output line
        Scanner-->>Parser: raw bytes
        Parser-->>Page: sanitized scan event
    end
    Scanner-->>Page: exit status and summary
```

When clamd answers a ping, Lazaret scans through it and passes file descriptors with `--fdpass`, so clamd can read files the desktop user can read. Otherwise it falls back to `clamscan`. The scanner's output is a stream (`impl Stream`) of byte lines. File names can be arbitrary bytes, so lines are split as bytes and decoded lossily. Scanner text is sanitized before it is shown, and rows that show file names never interpret markup.

## Quarantine

```mermaid
sequenceDiagram
    participant Page as Quarantine action
    participant Moves as quarantine_file_moves
    participant Database as quarantine database
    participant Source as detected file

    Page->>Moves: move detected file
    Moves->>Source: open without following links
    Moves->>Moves: copy into the quarantine directory, hash, fsync
    Moves->>Database: insert pending row with the hash
    Moves->>Source: unlink, after checking it is still the same file
    Moves->>Database: commit row
```

A move always runs in this order: copy, pending row, remove source, commit. Every open is no-follow, and the payload is checked against the hash before the source is removed. A crash at any step leaves either the original file or a complete, recorded copy. A pending row tells the next start which step to finish. A move that has started is never aborted.

Payloads are stored neutralized: a header with a random per-file key, followed by the content XORed with that key. Other scanners, indexers and thumbnailers then see nothing they recognize, and a payload can't be run by accident. The recorded SHA-256 is always that of the original content, and every read decodes the payload first. A payload stored raw, such as one renamed into quarantine because on-access scanning blocked reading it, is neutralized afterwards by writing an encoded copy next to it, checking its hash and renaming it over the raw file. A crash leaves either the raw or the encoded payload, and both read back the same.

Quarantined content is checked again by piping the decoded payload into `clamdscan -` (or `clamscan -` without clamd), so it never has to be written back to disk to be scanned. This happens before every restore and after every successful signature update.

## Live tuning

```mermaid
sequenceDiagram
    participant Settings as Settings page
    participant Helper as lazaret-settings-helper
    participant Polkit as polkit
    participant Clamd as clamd

    Settings->>Helper: change MaxThreads to 8 (system bus)
    Helper->>Polkit: authorize page.codeberg.wvhulle.Lazaret.apply-settings
    Polkit-->>Helper: allowed after a password prompt
    Helper->>Helper: check allowlist and protected settings
    Helper->>Helper: write overrides, merge into /run/lazaret/clamd.conf
    Helper->>Clamd: restart clamav-daemon
    alt clamd answers on its socket
        Helper-->>Settings: applied
    else unhealthy
        Helper->>Helper: restore previous overrides, restart again
        Helper-->>Settings: rolled back
    end
```

The helper is started by D-Bus activation. It authorizes each request with polkit, so the GUI is never trusted. It only accepts settings listed in `/etc/lazaret/tunable-settings`. It always refuses settings from `data/protected-clamav-settings.txt`, the settings that run commands or change identity, even when they are on the allowlist. Changes are stored in `/var/lib/lazaret/clamd-overrides.conf` and merged with `/etc/clamav/clamd.conf` into `/run/lazaret/clamd.conf`, which clamd is configured to read. Without any overrides, the merged file equals the base file.

The Detection settings page maps to `DetectPUA`, `HeuristicAlerts`, `AlertOLE2Macros`, `AlertEncrypted`, `ScanArchive` and `AlertExceedsMax`. A switch can only change when its key is in `/etc/lazaret/tunable-settings`. `clamscan` doesn't read `clamd.conf`, so every `clamscan` run gets the same values as `--detect-pua=…` and similar flags, read from the configuration clamd uses.

## Trusted detections

The helper also maintains two ClamAV allowlists in the signature directory: `lazaret-local.sfp` (SHA-256 and size of trusted files) and `lazaret-local.ign2` (ignored detection names). Each change has its own polkit action, `page.codeberg.wvhulle.Lazaret.trust-detection`, and the prompt names the exact hash or detection name. Heuristic detections can only be trusted by hash. Ignored names are written unpinned, without the `:md5` of the database entry: `sigtool --find-sigs` matches by regular expression, can return several entries for one name and prints bytecode signatures decoded rather than as stored, so Lazaret can't compute that MD5 reliably. Pinned lines that someone else wrote are kept, and stop ignoring removes them by name. The lists are never read or written through a symbolic link, and lines that don't fit their format are dropped. After a change the helper asks clamd to reload its signatures.

Every settings change and trust request, also refused ones, is written by the helper to the system journal with `LAZARET_ACTION`, `LAZARET_SUBJECT`, `LAZARET_OUTCOME`, `LAZARET_REQUESTER_UID`, `LAZARET_WEAKENS_PROTECTION` and `LAZARET_PROTECTION_REDUCTION`, the kind of reduction. Trust requests also record the exact `LAZARET_SHA256` or `LAZARET_SIGNATURE_NAME`, so Lazaret attributes each trust entry by exact match. When the helper can't read the clamd configuration, it records a change as `current-values-unknown` rather than as harmless. Lazaret reads these records back only from `_SYSTEMD_UNIT=lazaret-settings-helper.service` with `_UID=0`, so software running as the desktop user can neither forge nor erase them. The Trusted Detections page warns about allowlists in the signature directory that Lazaret didn't write.

## Background alerts and scheduled scans

```mermaid
flowchart LR
    session["graphical session"] --> service["lazaret.service: lazaret --background"]
    service --> follower["detection_journal_follower"]
    journal[("journal: clamd, clamonacc")] -->|wakeup| follower
    follower --> alert["desktop notification and Detections page"]
    timer["lazaret-scheduled-scan.timer"] --> scheduled["lazaret --scheduled-scan"]
    scheduled --> scanner["clamdscan or clamscan"]
    scheduled --> history[("activity history")]
```

`lazaret --background` runs without a window and follows the journal of the ClamAV services. A detection by clamd or clamonacc raises an alert, and the Detections page shows its timeline. Scheduled scans are a systemd user timer and service that Lazaret writes to `~/.config/systemd/user`. The service runs a headless scan with the same scanner code as the Scan page.

## Stored data

Lazaret keeps one SQLite database, `lazaret.db`, in its data directory: `$XDG_DATA_HOME/lazaret`, or `~/.local/share/lazaret` when that variable is unset, found with the `xdg` crate. Debug builds use `lazaret-devel` instead, and inside the Flatpak `XDG_DATA_HOME` points into the sandbox. Quarantined payloads sit in the `quarantine` directory next to the database. The tables are created by the numbered SQL files in `migrations/`, which are compiled into the binary. Each open reads `PRAGMA user_version` and applies the files it hasn't applied yet in order, each in its own transaction that also raises the version. A database with a higher version comes from a newer release and is refused without being changed. The screenshot fixtures and the tests create their databases through the same migrations.

Every store opens the file through `host_services::lazaret_database::locked_database_connection`, which holds `lazaret.lock` for as long as the connection lives, so only one connection in one process uses the file at a time; turso doesn't allow two processes to have it open together. Connections are short and a store never opens a second one while it holds the first. The window also holds `quarantine.lock` for as long as it runs, so only one process moves files into or out of quarantine; a scheduled scan that finds it taken leaves its detections in place. The quarantine lock is taken first and only ever around the database lock, so the two can't wait on each other.

The tables follow the shape of the Rust types: each state that carries its own data has its own detail table, keyed like its parent and deleted with it, so a column never holds a placeholder such as `0` or `''`. `CHECK` constraints list the valid values and combinations, and every connection turns on `PRAGMA foreign_keys`. Detail tables repeat the parent's status in their key, so a foreign key ties each detail row to the one status it belongs to.

### History tables

```mermaid
erDiagram
    activity_entries ||--o| scan_activities : "scan or skipped scan"
    scan_activities ||--o{ scan_activity_targets : "targets in order"
    scan_activities ||--o| scan_inspections : "scan that ran"
    scan_inspections ||--o| scan_threat_counts : "infected, counted"
    background_detections ||--o| detection_resolutions : "resolved"
    submissions ||--o| false_positive_signatures : "false positive"
    submissions ||--o| clamav_review_settlements : "settled by ClamAV"
    clamav_review_settlements ||--o| settled_database_versions : "version known"
    submissions ||--o| virustotal_analyses : "VirusTotal analysis"
    virustotal_analyses ||--o| virustotal_verdicts : "analysed"
    submissions ||--o| upload_refusals : "refused"
```

| Table | Key | References | Stores |
|---|---|---|---|
| `activity_entries` | `entry_id` | | One scan or signature update: start, status, duration and output. |
| `scan_activities` | `entry_id` | `activity_entries (entry_id, activity_status)` | The origin of a scan. A skipped scan is always scheduled. |
| `scan_activity_targets` | `entry_id, target_position` | `scan_activities` | One scanned path per row, in the order given. |
| `scan_inspections` | `entry_id` | `scan_activities (entry_id, activity_status)` | How many files a scan that ran inspected. Skipped scans have none. |
| `scan_threat_counts` | `entry_id` | `scan_inspections (entry_id, activity_status)` | The threat count of an infected scan. An infected scan without this row found threats it couldn't count. |
| `background_detections` | `file_path, signature_name`; `detection_id` is unique too | | One file that clamd or clamonacc reported for one signature: which scanners saw it, when, and how often. The journal follower matches new lines on the key. The pages and the incident view refer to a detection by `detection_id`. |
| `detection_resolutions` | `file_path, signature_name` | `background_detections` | How and when you resolved a detection. An open detection has no row, and a later sighting deletes it. |
| `detection_journal_position` | `position_row`, always 1 | | The journal cursor the follower continues from. |
| `submissions` | `content_sha256, submission_service, submission_kind` | | One file sent to ClamAV, MalwareBazaar or VirusTotal: its name, when, and its status. A `CHECK` lists the statuses each service and kind can have. |
| `false_positive_signatures` | as `submissions` | `submissions`, with its status | The signature reported as a false positive. |
| `clamav_review_settlements` | as `submissions` | `submissions`, with its status | A ClamAV report that a signature update settled. |
| `settled_database_versions` | as `submissions` | `clamav_review_settlements` | The daily database version that settled it. Without this row Lazaret couldn't read the version. |
| `virustotal_analyses` | as `submissions` | `submissions`, with its status | The VirusTotal analysis ID of an upload. |
| `virustotal_verdicts` | as `submissions` | `virustotal_analyses`, with its status | How many engines flagged the file, out of how many. |
| `upload_refusals` | as `submissions` | `submissions`, with its status | Why MalwareBazaar or VirusTotal refused an upload. |

### Quarantine tables

```mermaid
erDiagram
    file_contents ||--o{ quarantine : "content"
    quarantine ||--o| quarantine_signatures : "named threat"
    quarantine_pending ||--o| pending_payload_hashes : "hashed copy"
    quarantine_pending ||--o| pending_signatures : "named threat"
```

| Table | Key | References | Stores |
|---|---|---|---|
| `file_contents` | `content_sha256` | | The size of each quarantined content, by its lowercase SHA-256. Removed with the last entry that holds it. |
| `quarantine` | `entry_id`; `quarantine_path` is unique too | `file_contents` | One quarantined file: where it came from, where its payload is, when it was detected and its permission bits. |
| `quarantine_signatures` | `entry_id` | `quarantine` | The signature that detected the file. An entry without this row was blocked by on-access scanning before a signature was known. |
| `quarantine_pending` | `quarantine_path` | | A move that has started but not committed: source, planned size and permission bits. |
| `pending_payload_hashes` | `quarantine_path` | `quarantine_pending` | The hash of a copied payload. A blocked file renamed into quarantine has no hash until the next start computes it. |
| `pending_signatures` | `quarantine_path` | `quarantine_pending` | The signature of a pending move, with the same meaning as `quarantine_signatures`. |

A submission names its content by the same SHA-256 as `file_contents`, but has no foreign key to it: a submitted file may never have been quarantined, and `file_contents` loses its row when the last quarantined copy is restored or deleted, while the submission stays. A detection has no key to a quarantine entry for the same reason. Lazaret still treats an entry whose stored hash or detection date doesn't parse as unverified, so a database edited by hand can't make it restore unchecked content.

## Deployments

```mermaid
flowchart TB
    subgraph native["NixOS and Debian"]
        nativeApp["lazaret"] -->|spawns| nativeScanner["clamdscan on the host"]
        nativeApp -->|system bus| nativeHelper["lazaret-settings-helper"]
        nativeService["lazaret.service"]
    end
    subgraph flatpak["Flatpak"]
        sandboxApp["lazaret in the sandbox"] -->|flatpak-spawn --host| sandboxScanner["clamdscan on the host"]
        sandboxApp -->|Background portal| autostart["autostart with --background"]
        sandboxApp -.->|no helper| missing["live tuning unavailable"]
    end
```

The NixOS module and the Debian package install the helper, its polkit action, its D-Bus configuration and the user service. The Flatpak can't ship a privileged helper, so live tuning is not available there. Inside the sandbox, Lazaret runs the ClamAV programs on the host with `flatpak-spawn --host`. Paths under `/run/host` are translated back to host paths before they reach the scanner. The sandbox starts in the background through the Background portal instead of a systemd user service.
