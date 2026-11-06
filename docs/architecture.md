# Architecture

Lazaret is a desktop front-end for the ClamAV that is already installed on the host. It never bundles a scan engine and never runs as root. This page describes how the pieces fit together and which rules keep them safe. The rules for changing the code are in [development](development.md).

## Components

```mermaid
flowchart LR
    subgraph gui["lazaret (desktop user)"]
        scan["malware_scan"]
        quarantine["file_quarantine"]
        protection["protection_status"]
        detections["background_detections"]
        schedules["scheduled_scans"]
        lookups["threat_intel_lookup"]
        settings["application_settings"]
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
    protection -->|D-Bus| systemd
    protection -->|spawns| freshclam
    detections -->|reads| journal
    schedules -->|writes timer units, D-Bus| systemd
    quarantine --> database
    lookups -->|HTTPS| internet
    lookups --> keyring
    settings -->|system bus| helper
    helper -->|authorizes| polkit
    helper -->|restarts| systemd
```

The source is organised by feature: each directory under `src/` holds the logic of one feature next to its page. `settings_helper/` is the only code that runs with privileges, and `xtask/` holds the repository tasks: screenshots, packaging and releases.

Lazaret talks to the host in three ways, and never through shell commands like `systemctl` or `journalctl`:

- It spawns the ClamAV programs found on `PATH`: `clamdscan --fdpass`, `clamscan` and `freshclam`.
- It talks to systemd over D-Bus (`src/systemd_bus/`), for unit states, starting units and installing timers.
- It reads the journal through libsystemd (`src/systemd_journal/`).

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
