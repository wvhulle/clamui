# Usage

Lazaret works the same on every system. Where something depends on how you installed it, this page links to the [install guides](install/).

## Scan

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan.png" width="800" alt="The Scan page with a drop zone for files and folders above the scan options">

Drop files or folders on the Scan page, or add them with the buttons, and press **Start Scan**. You can also pass paths on the command line, `lazaret /path/to/folder`, or use the context-menu action of your file manager (Nautilus, Dolphin and Nemo, turned on under **Preferences**).

Lazaret scans through clamd when it answers, so the scan uses the signatures already loaded in memory. It passes file descriptors with `--fdpass`, so clamd can read files you can read. Without clamd it falls back to `clamscan`. The active backend is shown on the page, and you can force one in the scanner settings.

A profile picks targets and exclusions in one go. Manage them with **Manage Profiles**:

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/profile-manager.png" width="800" alt="The profile manager listing the built-in and custom scan profiles">

Exclusions skip folders and patterns in every scan. Home scans skip package and toolchain caches by default:

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-exclusions.png" width="800" alt="The exclusions settings with folders and patterns that scans skip">

## Results and quarantine

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-result.png" width="800" alt="Results of a finished scan with the files scanned, the duration and the threats found">

After a scan, the results appear on the Scan page: how many files were scanned out of how many were planned, how long it took, and every threat with its severity. Files the scanner never reported, for example after clamd lost the connection, are listed as a problem rather than silently counted as clean. From a threat you can copy its path, exclude it from future scans, or quarantine it.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/results-before-quarantine.png" width="800" alt="Scan results with two threats and a button to quarantine both">

**Quarantine** asks for confirmation, then moves each file into Lazaret's quarantine directory:

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/results-quarantine-confirmation.png" width="800" alt="The confirmation dialog before moving two files to quarantine">

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/results-quarantined.png" width="800" alt="Scan results after both threats were moved to quarantine">

A move copies the file, checks its hash and only then removes the original, so an interrupted move never loses the file. The Quarantine page lists every quarantined file. Expand an entry to check its reputation, restore it to where it came from, or delete it for good. **Clear Old Items** deletes files that have been in quarantine for more than 30 days.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/quarantine.png" width="800" alt="The Quarantine page listing quarantined files">

## False positives

When you are sure a detection is wrong, trust the file instead of excluding its path. Open the menu of a detected threat and choose **Trust This File…**, or press **Trust…** on a quarantined file. ClamAV then never reports a file with exactly that content again, in any scan on this computer, while a changed copy is checked as usual. **Ignore This Detection Everywhere…** silences a detection name for every file; prefer trusting by hash when only one file is affected.

Both need your administrator password, and the password prompt shows the exact hash or detection name. Remove entries under **Protection → Trusted Detections**, which also lists allowlist files in the signature folder that Lazaret didn't write. The **System Changes** tab on the Logs page shows every change, as recorded by the system journal. This needs the settings helper, so it isn't available in the Flatpak.

## Reputation lookups

On the Quarantine page you can look up a quarantined file by its SHA-256 hash, without uploading the file. CIRCL hashlookup tells whether the hash belongs to a known, harmless file. MalwareBazaar (abuse.ch) and VirusTotal tell whether it is a known malware sample. Both need a free API key. Paste the keys under **Preferences → Online Lookups**, where they are stored in your keyring. Or point Lazaret at key files, as each install guide explains.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/preferences-online-lookups.png" width="800" alt="The Online Lookups preferences with fields for the abuse.ch and VirusTotal keys">

## Protection

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/protection.png" width="800" alt="The Protection page summarizing signatures, the daemon, on-access blocking and scheduled scans">

The Protection page shows whether your system is actually protected: how old the signatures are, whether clamd answers, whether on-access scanning blocks files, and when the next scheduled scan runs. When something needs your attention, it says what to do, often with a command you can copy.

## Signatures

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/database.png" width="800" alt="The signature database page with the age of each signature file">

The signatures page lists the signature files and their age. **Update** starts the freshclam service of your system, or runs `freshclam` when there is no service.

## Detections and alerts

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/detections.png" width="800" alt="The Detections page listing files that the background services detected">

When clamd or on-access scanning detects a file in the background, Lazaret raises a desktop notification. For that it has to run in the background; the install guides explain how to start it with your session. The Detections page lists these detections, and each one opens a timeline of what happened to the file, from where you can quarantine it:

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/detection-incident.png" width="800" alt="The timeline of one detection, from blocking to quarantine">

## Scheduled scans

Under **Scheduled Scans**, choose how often to scan (hourly, daily, weekly or monthly), which targets, and whether to skip the scan on battery or quarantine detections automatically. Lazaret writes a systemd user timer, `lazaret-scheduled-scan.timer`, so scans run even when the window is closed, and runs missed after the computer was off.

## Logs

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/logs.png" width="800" alt="The Logs page listing past scans and updates">

The Logs page keeps a history of scans, updates and quarantine actions, and shows the clamd log. Export it as CSV or JSON.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/logs-entry-selected.png" width="800" alt="One log entry opened with its details">

## Preferences

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/preferences.png" width="800" alt="The general preferences with window behavior and file manager integration">

The general preferences cover window behavior, starting in the background, desktop notifications and file-manager actions. The clamd and freshclam settings live on their own settings pages. Where your install allows it, allowed clamd settings can be changed from there after an administrator password prompt; see live tuning in your install guide.
