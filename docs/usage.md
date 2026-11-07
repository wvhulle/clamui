# Usage

Lazaret works the same on every system. Where something depends on how you installed it, this page links to the [install guides](install/).

## Scan

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan.webp" width="800" alt="Recording of the Scan page, then the profile manager opened with Manage Profiles">

Drop files or folders on the Scan page, or add them with the buttons, and press **Start Scan**. You can also pass paths on the command line, `lazaret /path/to/folder`, or use the context-menu action of your file manager (Nautilus, Dolphin and Nemo, turned on under **Preferences**).

Lazaret scans with the ClamAV daemon when it is running, which is faster because its signatures are already loaded, and uses the standalone scanner otherwise. The page shows which one is in use, and you can choose one in the scanner settings.

A profile picks targets and exclusions in one go. Manage them with **Manage Profiles**:


Exclusions skip folders and patterns in every scan. Home scans skip package and toolchain caches by default:

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-settings.webp" width="800" alt="Recording of opening the exclusions from the Scan page, with folders and patterns that scans skip">

## Results and quarantine

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/scan-results.webp" width="800" alt="Recording of a finished scan with two threats, the quarantine confirmation and the results after both files moved to quarantine">

After a scan, the results appear on the Scan page: how many files were scanned out of how many were planned, how long it took, and every threat with its severity. Files the scanner never reported on are listed as a problem rather than silently counted as clean. From a threat you can copy its path, exclude it from future scans, or quarantine it.


**Quarantine** asks for confirmation, then moves each file into Lazaret's quarantine directory.



An interrupted move never loses the file. The Quarantine page lists every quarantined file. Expand an entry to check its reputation, restore it to where it came from, or delete it for good. **Clear Old Items** deletes files that have been in quarantine for more than 30 days. Before a file is restored, Lazaret checks it again with today's signatures and shows where it will go. After a signature update, and whenever you press **Check Again**, it checks every quarantined file and marks the ones that are no longer detected, so you can restore false positives once a signature update fixes them.

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/quarantine.webp" width="800" alt="Recording of the Quarantine page with one entry expanded to show reputation lookups, false positive actions and its hash">

## False positives

When you are sure a detection is wrong, trust the file instead of excluding its path. Open the menu of a detected threat and choose **Trust This File…**, or press **Trust…** on a quarantined file. The file is then never reported again on this computer, but a changed copy of it is still checked. **Ignore This Detection Everywhere…** stops reporting a detection for every file, so prefer trusting the file when only one file is wrong.

To get the detection fixed for everyone, choose **Report False Positive…** or press **Report…** on a quarantined file. This uploads the file, with your name and email address, to the ClamAV team, and the **Submissions** page tracks the report.

Both ask for your administrator password. Review and remove trusted files on the **Analysis & False Positives** page, and see who changed what on the **System Changes** tab of the Logs page. Trusting files is not available in the Flatpak.

## Reputation lookups

On the Quarantine page you can look up a quarantined file without uploading it; only a fingerprint of the file is sent. CIRCL hashlookup tells whether the hash belongs to a known, harmless file. MalwareBazaar (abuse.ch) and VirusTotal tell whether it is a known malware sample. Both need a free API key. Paste the keys under **Submissions → Services & Keys**, where they are stored in your keyring. Or point Lazaret at key files, as each install guide explains.

## Submissions

The Submissions page lists everything Lazaret sent to a public database, and what became of it. Nothing leaves your computer until you confirm a dialog that names the file, the service and exactly what is sent. Start a submission from **Submit…** on a quarantined file, from **Submit…** in an opened detection whose file is in quarantine, from the Quarantined Files list on this page, or with **Report Missed Malware** for a file ClamAV doesn't detect. A file you already sent to the same service is not sent again; the earlier submission is shown instead.

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

**Services & Keys** holds the abuse.ch and VirusTotal keys. The abuse.ch key unlocks MalwareBazaar lookups and uploads, and also URLhaus signature downloads through fangfrisch.


## Protection

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/protection.webp" width="800" alt="Recording of the Protection page, expanding the daemon step and following Review to the detections">

The Protection page shows whether your system is actually protected: how old the signatures are, whether the ClamAV daemon is running, whether on-access scanning blocks files, and when the next scheduled scan runs. When something needs your attention, it says what to do, often with a command you can copy.

## Signatures

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/signatures.webp" width="800" alt="Recording of the Signatures page, expanding a signature source that shows how to add it">

The Signatures page lists where ClamAV's signatures come from and which other sources you could add, with the lines to add for each.

## Database updates

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/signature-update.webp" width="800" alt="Recording of the Database Updates page, expanding the signatures step with its last updates and the Update Now button">

The Database Updates page shows how old the signatures are, when freshclam and fangfrisch last ran, and whether the freshclam that Lazaret runs can be trusted. To download new signatures right away, expand **Signatures current** and choose **Update Now**. The step shows the updater's output while it runs and the result when it is done. Below it, the update history lists every update started from Lazaret, newest first; select one to read its full transcript. The **Settings** tab holds the freshclam settings. The Protection page links here from its signatures step.

## Hardening

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/hardening.webp" width="800" alt="Recording of the Hardening page with firewall, access control and intrusion detection checks">

The Hardening page lists protections outside ClamAV that make exploits harder: a firewall, AppArmor or SELinux, whether other programs can tamper with Lazaret or pose as ClamAV, intrusion prevention and rootkit checks. They don't change the Protection summary. Where something is missing, it suggests how to set it up.

## Detections and alerts

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/detections.webp" width="800" alt="Recording of the Detections page, opening one detection's timeline">

When ClamAV detects a file in the background, Lazaret raises a desktop notification. For that it has to run in the background; the install guides explain how to start it with your session. The Detections page lists these detections, and each one opens a timeline of what happened to the file, from where you can quarantine it.


## Scheduled scans

Under **Scheduled Scans**, choose how often to scan (hourly, daily, weekly or monthly), which targets, and whether to skip the scan on battery or quarantine detections automatically. Scans run even when Lazaret is closed, and a scan missed while the computer was off runs once it is back on.

## Removable drives

With **Device Auto-Scan** turned on, Lazaret scans a removable or external drive a few seconds after it is mounted. Set a size limit and choose whether to skip drives while the computer runs on battery. The Removable Drives page lists every drive connected since Lazaret started and why it was or wasn't scanned, shows a drive scan in progress and its results, and keeps the history of drive scans. Only one scan runs at a time: a drive connected during another scan is skipped.

## Logs

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/logs.webp" width="800" alt="Recording of the Logs page, opening one scan's details and then the System Changes tab">

The Logs page keeps a history of scans, updates and quarantine actions, and shows the log of the ClamAV daemon. Export it as CSV or JSON.


## Preferences

<img src="https://codeberg.org/wvhulle/lazaret/raw/branch/screenshots/preferences.webp" width="800" alt="Recording of the general preferences">

The **Detection** settings, next to Scanner Engine, choose whether ClamAV reports potentially unwanted programs, heuristic findings, Office macros, encrypted archives and files too large to check, and whether it looks inside archives. Scans that run without the ClamAV daemon follow the same choices.

The general preferences cover window behavior, starting in the background, desktop notifications and file-manager actions. ClamAV's own settings live on their own settings pages. Where your install allows it, you can change some of them there after entering your administrator password; see live tuning in your install guide.
