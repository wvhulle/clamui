# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://codeberg.org/wvhulle/lazaret/compare/v0.1.0...v0.2.0) - 2026-11-06

### Added

- *(protection)* say what a weakening setting change gives up and keep showing it
- *(trust)* report false positives to the ClamAV team with clamsubmit
- *(quarantine)* store quarantined files neutralized
- *(quarantine)* check quarantined files again before restoring and after updates
- *(scan)* show how many entries exclusions skipped
- *(protection)* warn about exclusions and schedule units that skip malware
- *(hardening)* check that other programs can't tamper with Lazaret or clamd
- *(engine)* choose what ClamAV detects from a Detection group
- *(lookups)* show system-provided API keys as read-only, reusing fangfrisch's abuse.ch key
- *(screenshots)* record an animated webp of every page

### Changed

- arrange source directories the way the window presents them
- add typed actions, a settings watcher and message-based file dialogs
- *(shell)* drive the window, navigation and settings subpages through messages
- *(pages)* keep scan, detections, schedule and preferences state in their models
- *(pages)* derive the remaining pages and rows from their models
- *(streams)* bridge blocking walks and the journal through one iterator stream
- *(pages)* run command streams through drop-to-cancel guards
- *(dialogs)* await file and alert dialogs instead of emitting from callbacks

### Documentation

- show recordings of every page instead of stills
- call the page captures recordings where they are recordings

### Fixed

- *(engine)* give the detection switches their own Detection page

### Testing

- *(lock)* wait for the released lock instead of racing forked children
