# Usage

Lazaret works the same on every system. Where something depends on how you installed it, this page links to the [install guides](install/).

## The sidebar

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/start-page.webp" width="800" alt="Recording of the window opening on the first area that needs attention, with the status of every area in the sidebar">

The sidebar follows the way a detection travels, in four groups:

- **Signatures**, where detections come from: Signature Sources and Database Updates.
- **Scans**, how files get checked: Scan Files…, Scan Engine, On-Access Scanning, Scheduled Scans, Manual Scan and Removable Drives.
- **Findings**, what was found: Detections, Quarantine and Trusted Detections.
- **Sharing**, what leaves this computer: Online Lookups and Submissions.

Each entry shows its current state underneath, such as "Blocking ~/Downloads", "Next scan in 6 hours" or "2 need a decision". A warning icon means the area needs your review or its state is unknown, an error icon means it doesn't work, and a dimmed icon means it waits for another part, for example on-access scanning waiting for clamd. When you start Lazaret without choosing a page, it opens on the first entry that needs attention, or on Detections when everything is fine. It doesn't move once you have picked a page yourself.

<kbd>Ctrl</kbd>+<kbd>1</kbd> to <kbd>Ctrl</kbd>+<kbd>9</kbd> and <kbd>Ctrl</kbd>+<kbd>0</kbd> open the first ten entries in sidebar order, from Signature Sources to Trusted Detections. Online Lookups and Submissions have no shortcut. Start on a page with `lazaret --page=NAME`, for example `--page=manual-scan` or `--page=trusted-detections`.

The primary menu holds **Export History…**, which saves every recorded scan and signature update as CSV or JSON, and **Clear History…**, which deletes them after you confirm.

## Signature Sources

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/signature-sources.webp" width="800" alt="Recording of the Signature Sources page, expanding a signature source that shows how to add it">

Signature Sources lists where ClamAV's signatures come from and which other sources you could add, such as Sanesecurity or URLhaus, with the lines to add for each. It also shows whether the abuse.ch key is configured, missing or unreadable. That key unlocks URLhaus signatures through fangfrisch as well as MalwareBazaar lookups and uploads; it is edited on Submissions, and the row links there.

## Database Updates

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/database-updates.webp" width="800" alt="Recording of the Database Updates page, expanding the signatures step with its last updates and the Update Now button">

Database Updates shows how old the signatures are, when freshclam and fangfrisch last ran, and whether the freshclam that Lazaret runs can be trusted. To download new signatures right away, expand **Signatures current** and choose **Update Now**. The step shows the updater's output while it runs and the result when it is done. Below it, the update history lists every update started from Lazaret, newest first; select one to read its full transcript. The freshclam settings are on the same page.

## Scan Files…

The first row of the Scans group opens a file chooser and adds what you pick to a manual scan.

## Scan Engine

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-engine.webp" width="800" alt="Recording of the Scan Engine page with the clamd status and the detection options">

Every scan sends its files to clamd. Scan Engine shows whether clamd is running, which signature version it has loaded and which socket it listens on, and whether the scanner programs Lazaret runs can be trusted. Its detection options choose whether ClamAV reports potentially unwanted programs, heuristic findings, Office macros, encrypted archives and files too large to check, and whether it looks inside archives. Scans that run without clamd follow the same choices. Where your install allows it, you can change clamd settings here after entering your administrator password; see live tuning in your install guide. The page also lists the engine settings changed through Lazaret, as the system recorded them, and the clamd log.

## On-Access Scanning

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/on-access.webp" width="800" alt="Recording of the On-Access Scanning page with its watched folders and settings">

On-Access Scanning shows whether clamonacc runs, which folders and mounts it watches, and whether it blocks a detected file or only reports it. Blocking needs `OnAccessPrevention` and a kernel that supports permission events; mount watching never blocks. The page flags setups that clamonacc rejects or that can loop, such as a clamd user that isn't excluded, and lists the on-access settings changed through Lazaret and clamonacc's log lines.

## Scheduled Scans

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scheduled-scans.webp" width="800" alt="Recording of the Scheduled Scans page with the schedule and its next run">

When the system has a scan timer, Scheduled Scans shows it, its next run and how the last one ended, and **Run Now** starts its scan service on demand. Otherwise choose how often Lazaret scans (hourly, daily, weekly or monthly), which targets, and whether to skip the scan on battery or quarantine detections automatically. Scans run even when Lazaret is closed, and a scan missed while the computer was off runs once it is back on. Below, the history lists every scheduled run.

## Manual Scan

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/manual-scan.webp" width="800" alt="Recording of the Manual Scan page, then the profile manager opened with Manage Profiles">

Drop files or folders on Manual Scan, or add them with the buttons, and press **Start Scan**. You can also pass paths on the command line, `lazaret /path/to/folder`, or use the context-menu action of your file manager (Nautilus, Dolphin and Nemo, turned on under **Preferences**). Lazaret scans with clamd when it is running, which is faster because its signatures are already loaded, and uses the standalone scanner otherwise.

A profile picks targets and exclusions in one go. Manage them with **Manage Profiles**. Exclusions skip folders and patterns in every scan; home scans skip package and toolchain caches by default:

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-exclusions.webp" width="800" alt="Recording of opening the exclusions from the Manual Scan page, with folders and patterns that scans skip">

After a scan, the results show how many files were scanned out of how many were planned, how long it took, and every threat with its severity. Files the scanner never reported on are listed as a problem rather than silently counted as clean. From a threat you can copy its path, exclude it from future scans, trust it, report it, or quarantine it. **Quarantine** asks for confirmation, then moves each file into Lazaret's quarantine. Recent scans lists the manual scans, newest first, and stays hidden until there is one.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-results.webp" width="800" alt="Recording of a finished scan with two threats, the quarantine confirmation and the results after both files moved to quarantine">

## Removable Drives

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/removable-drives.webp" width="800" alt="Recording of the Removable Drives page with the auto-scan settings and the drives seen">

With **Device Auto-Scan** turned on, Lazaret scans a removable or external drive a few seconds after it is mounted. Set a size limit and choose whether to skip drives while the computer runs on battery. The page lists every drive connected since Lazaret started and why it was or wasn't scanned, shows a drive scan in progress and its results, and keeps the history of drive scans. Only one scan runs at a time: a drive connected during another scan is skipped.

## Detections

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/detections.webp" width="800" alt="Recording of the Detections page, opening one detection's timeline">

When ClamAV detects a file in the background, Lazaret raises a desktop notification. For that it has to run in the background; the install guides explain how to start it with your session. Detections lists these detections, and each one opens a timeline of what happened to the file, from where you quarantine it, delete it or keep it. **Keep** only stops Lazaret asking: ClamAV still reports the file at the next scan, so trust it from Quarantine or a scan result if it is a false positive. The page also shows whether alerts can reach you, and whether other programs can attach to Lazaret.

## Quarantine

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/quarantine.webp" width="800" alt="Recording of the Quarantine page with one entry expanded to show reputation lookups, false positive actions and its hash">

An interrupted move never loses the file. Quarantine lists every quarantined file. Expand an entry to check its reputation, restore it to where it came from, or delete it for good. **Clear Old Items** deletes files that have been in quarantine for more than 30 days. Before a file is restored, Lazaret checks it again with today's signatures and shows where it will go. After a signature update, and whenever you press **Check Again**, it checks every quarantined file and marks the ones that are no longer detected, so you can restore false positives once a signature update fixes them.

When you are sure a detection is wrong, trust the file instead of excluding its path: press **Trust…** on a quarantined file, or choose **Trust This File…** on a scan result. The file is then never reported again on this computer, but a changed copy of it is still checked. **Ignore This Detection Everywhere…** stops reporting a detection for every file, so prefer trusting the file when only one file is wrong. To get the detection fixed for everyone, press **Report…**, which sends the file, with your name and email address, to the ClamAV team. Trusting asks for your administrator password and is not available in the Flatpak.

## Trusted Detections

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/trusted-detections.webp" width="800" alt="Recording of the Trusted Detections page with the trusted files and ignored detections">

Trusted Detections lists what ClamAV is told to stay silent about: the files you trusted and the detections you ignored, each with who added it and when, and any allowlist in the signature folder that Lazaret didn't write. Malware with administrator rights could hide itself this way, so check that every entry was added on purpose. Remove an entry to have ClamAV report it again. The system changes below list every trust change made through Lazaret, as the system recorded them.

## Online Lookups

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/online-lookups.webp" width="800" alt="Recording of the Online Lookups page with what each service receives">

Online Lookups says what each service receives and whether it is ready. A lookup never uploads the file:

- **CIRCL hashlookup** gets the file's SHA-256 hash and tells whether it belongs to a known, harmless file. It needs no key.
- **MalwareBazaar** (abuse.ch) gets a detection's signature name or a file's hash and tells whether it is a known malware sample. It needs the abuse.ch key.
- **VirusTotal** gets a file's hash. It needs a VirusTotal key.

The keys are kept on Submissions, and each row links there. Lookups run where you start them: **Look Up** in an opened detection, and **Reputation** in an expanded quarantine entry.

## Submissions

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/submissions.webp" width="800" alt="Recording of the Submissions page with the submitted list and the keys">

Submissions lists everything Lazaret sent to a public database, and what became of it. Nothing leaves your computer until you confirm a dialog that names the file, the service and exactly what is sent. Start a submission from **Submit…** on a quarantined file, from **Submit…** in an opened detection whose file is in quarantine, from the Quarantined Files list on this page, or with **Report Missed Malware** for a file ClamAV doesn't detect. A file you already sent to the same service is not sent again; the earlier submission is shown instead.

Each service receives something different:

- **ClamAV** (Cisco Talos) gets the file through `clamsubmit`, with your name and email address, and for a false positive also the detection name. Talos processes samples by automation, only Talos can access them, and they are never made public or shared with other companies. A review takes at least 48 hours.
- **MalwareBazaar** (abuse.ch) gets a quarantined file that a ClamAV signature detected, named by its SHA-256 hash rather than its file name, with the signature as a tag. The sample becomes public: anyone can download it. Lazaret first looks the hash up and skips the upload when MalwareBazaar already lists it. Potentially unwanted programs are not sent.
- **VirusTotal** gets a quarantined file, also named by its hash, when a hash lookup finds no report and the file is at most 32 MB. VirusTotal shares uploaded files with its paying customers.

Only quarantined files can be uploaded to MalwareBazaar and VirusTotal, and only when their quarantine record has a usable hash: Lazaret reads them through the same integrity check as a restore, so it sends exactly the file it quarantined. Missed-malware reports read the file you pick without following symbolic links.

Statuses update without timers:

- A ClamAV report stays **awaiting review** until a signature update. After each update Lazaret checks the quarantined files again; a false positive that is no longer detected becomes **fixed in database version N**, and missed malware that is now detected becomes **detected since database version N**. Reports of files that are no longer kept in quarantine stay awaiting review.
- A MalwareBazaar upload is **uploaded** until a later lookup confirms it is **listed**.
- A VirusTotal upload is **queued** until it has a verdict, shown as how many engines flag it as malicious.

The refresh button asks MalwareBazaar and VirusTotal about uploads that are still waiting, only when you press it. A submission a service refused is marked for review, and you can try it again. Filter the list by service and status, and open a submission's public entry from its row.

**Services and Keys** holds the abuse.ch and VirusTotal keys, stored in your keyring, or point Lazaret at key files as each install guide explains. The abuse.ch key unlocks MalwareBazaar lookups and uploads, and also URLhaus signature downloads through fangfrisch.

## Preferences

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/preferences.webp" width="800" alt="Recording of the general preferences">

The preferences cover window behavior, starting in the background, desktop notifications and file-manager actions. ClamAV's own settings are on the pages of the area they belong to.
