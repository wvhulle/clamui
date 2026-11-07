# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://codeberg.org/wvhulle/lazaret/compare/v0.1.0...v0.2.0) - 2026-11-07

### Added

- *(window)* derive a status per sidebar area from the protection evidence
- *(signatures)* add a Database updates page that owns the signature update
- *(scans)* add a Scan engine page for clamd, the scanners and their settings
- *(scans)* add an On-access scanning page for clamonacc and its settings
- *(scans)* add a Scheduled scans page and run the system scan from Manual scan
- *(scans)* show recent scans, exclusions and device auto-scan on Manual scan
- *(on-access)* follow the ClamAV docs on mounts, kernel support and watch setups
- *(settings)* one unlock per page, and open-settings scrolls to its group
- *(history)* record device scans with their own origin
- *(scans)* add the Removable drives page
- *(detections)* show how alerts reach you and the process-attach check
- *(analysis)* add the Analysis & False Positives page
- *(history)* store submissions to public databases in history.db
- *(submissions)* record ClamAV reports and settle them after updates
- *(submissions)* upload ClamAV-detected samples to MalwareBazaar
- *(submissions)* upload quarantined detections to VirusTotal
- *(submissions)* add the Submissions page with keys and entry points
- *(engine-settings)* show clamd settings with editors for their value type
- *(signatures)* turn the Signatures page into Signature Sources
- *(hardening)* drop the Hardening page
- *(logs)* drop the Logs page for per-area history and a menu
- *(protection)* drop the Protection page and start on what needs attention
- *(sidebar)* group the sidebar by data flow like bindrune
- *(navigation)* name pages after the sidebar and keep old names as aliases
- *(storage)* keep everything in one versioned lazaret.db in the xdg data folder
- *(live-tuning)* store typed runtime overrides that expire when they reduce protection
- *(service-log)* show journal entries as rows with time, level and sender

### Changed

- *(timeline)* make step actions generic per page and model running steps as their own phase
- *(settings)* type helper and systemd failures instead of passing text
- *(desktop)* type tray, vault, journal and probe failures
- *(threat-intel)* type lookup, report and quarantine failures
- *(window)* type startup page, settings choices and dialog answers
- *(history)* model activity records and threat findings as states
- *(signatures)* identify providers by enum and keep snippets in credentials
- *(scan,updates)* type page notices and lookup, systemd and audit failures
- *(layout)* group page modules by sidebar section
- *(protection)* let the window shell own the protection evidence stream
- *(layout)* share activity entry rows and evidence fixtures across pages
- *(settings)* embed the engine settings sections inline in their host pages
- *(pages)* move helpers shared between pages out of page directories
- *(scans)* extract the scan run machinery shared by scan pages
- *(settings)* drop settings deep links in favour of page navigation
- *(analysis)* split into Trusted Detections and Online Lookups
- *(config)* add a typed clamd configuration crate
- rename the settings helper to the ClamAV admin service
- *(sizes)* render and compute byte sizes with bytesize
- *(sharing)* organize lookups and submissions around user flows

### Documentation

- *(layout)* point architecture and translation template at the moved modules
- follow the grouped sidebar in recordings, usage and README
- describe the single lazaret.db and how to change its schema
- make screenshot generation faster

### Fixed

- *(detections)* never move or delete a blocked file owned by another user
- *(quarantine)* type the payload hash instead of an empty-string sentinel
- *(scan)* tell on-access blocks apart from real signature names
- *(scan)* tie scan messages to their run and keep one scan at a time
- *(detections)* make a resolved detection always carry its kind and time
- *(protection)* stop inventing results for unreadable systemd units
- *(scan)* classify scanner exits and unit results once into typed outcomes
- *(signatures)* classify signature update finishes once into typed outcomes
- *(protection)* model on-access, daemon, timer and override evidence as typed states
- *(settings-helper)* carry typed config values, reductions, audited actions and live tuning state
- *(trust-lists)* report unreadable allowlists and journal cursors instead of treating them as empty
- *(quarantine,logs)* model page listings, operations and notices as typed states
- *(detections)* model the open incident and its sub-state as one typed view
- *(scan-profiles)* select profiles by origin and keep the selection across reloads
- *(settings)* derive file manager, schedule and live-change states from typed models
- show unreadable host state as unknown instead of empty defaults
- *(trust)* keep pinned .ign2 entries instead of dropping them
- *(history)* store the scan origin in its own column
- *(settings)* scroll a revealed settings group to the top instead of relying on focus
- *(submissions)* refuse a second upload of the same file while one runs
- *(history)* store scan details in their own tables
- *(history)* key detections by file and signature, resolutions apart
- *(quarantine)* keep content facts and threat names in their own tables
- *(submissions)* tie submission details to their status
- *(settings)* stop pointing reduced-protection notices at the Protection page
- *(history)* hide a page's scan history until it has a run to show
- *(pages)* drop link groups that repeat sidebar entries
- *(scheduled-scans)* move the system scan and Run Now to Scheduled scans
- *(history)* show why scan history can't be read, with Retry
- *(storage)* keep data in the lazaret folder for every build
- *(devshell)* give the dev build gtk's schemas so the file chooser doesn't abort
- *(errors)* show load failures in their own row and log every storage failure to the journal
- *(engine-settings)* show read-only yes/no settings as switches
- remove overflowing nested pages

### Miscellaneous

- translations

### Testing

- *(vm)* click Run Now by its visible text instead of a fixed position
- *(vm)* find the live-tuning controls by their labels
