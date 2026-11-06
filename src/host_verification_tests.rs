use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use futures::{StreamExt, future::ready, stream};

use crate::{
    detections_page::{
        background_detections_page::{BackgroundDetectionsPageCommand, load_displayed_detections},
        detected_file_state::{DetectedFileState, inspect_detected_file},
        detections_view_state::file_states_to_keep,
        incident_timeline_presentation::{
            DeletionPrompt, DisplayedDetection, SignatureLookupState, incident_timeline,
        },
    },
    host_services::{
        activity_history::activity_history_database::ActivityHistory,
        clamav_programs::distribution_install_guides::DistributionFamily,
        clamav_scanner::{
            scan_exclusion_rules::ScanExclusions,
            scan_progress_events::{CompletedScanOutcome, ScanRequest, scan_progress_events},
            scanner_command_builder::{
                ScannerBackend, ScannerProgramPaths, probe_clamd_availability,
            },
        },
        detection_journal::{
            detection_history_store::DetectionResolution,
            detection_journal_follower::{
                DetectionJournalEvent, JournalStartPosition, detection_journal_events,
            },
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
    },
    scan_page::eicar_test_file::eicar_test_bytes,
};

fn host_scan_request(
    scan_targets: Vec<PathBuf>,
    scanner_backend: ScannerBackend,
    file_list_directory: &Path,
) -> ScanRequest {
    ScanRequest {
        scan_targets,
        scanner_backend,
        scanner_programs: ScannerProgramPaths::locate_trusted_programs(),
        file_list_directory: file_list_directory.to_path_buf(),
        scan_exclusions: ScanExclusions::default(),
        detection_arguments: Vec::new(),
    }
}

async fn complete_scan(scan_request: ScanRequest) -> CompletedScanOutcome {
    scan_progress_events(scan_request)
        .fold(
            CompletedScanOutcome::default(),
            |mut scan_outcome, progress_event| {
                scan_outcome.absorb_progress_event(progress_event);
                ready(scan_outcome)
            },
        )
        .await
}

async fn open_host_vault(vault_root: &Path) -> QuarantineVault {
    QuarantineVault::open_vault(
        vault_root.join("quarantine.db"),
        vault_root.join("quarantine"),
    )
    .await
    .expect("opened vault")
}

fn clamav_temporary_entries() -> Vec<String> {
    fs::read_dir(std::env::temp_dir())
        .map(|temporary_entries| {
            temporary_entries
                .filter_map(Result::ok)
                .map(|temporary_entry| temporary_entry.file_name().to_string_lossy().into_owned())
                .filter(|entry_name| entry_name.starts_with("clamav-"))
                .collect()
        })
        .unwrap_or_default()
}

async fn verify_detection_quarantine_and_restore(scanner_backend: ScannerBackend) {
    let verification_root = tempfile::tempdir().expect("verification root");
    let scan_directory = verification_root.path().join("scan");
    fs::create_dir_all(&scan_directory).expect("scan directory");
    let eicar_path = scan_directory.join("eicar-test.txt");
    let non_utf8_path = scan_directory.join(OsString::from_vec(b"bad-\xff-name.txt".to_vec()));
    fs::write(&eicar_path, eicar_test_bytes()).expect("eicar file");
    fs::write(&non_utf8_path, eicar_test_bytes()).expect("non-utf8 eicar file");

    let scan_outcome = complete_scan(host_scan_request(
        vec![scan_directory],
        scanner_backend,
        verification_root.path(),
    ))
    .await;
    println!("{scanner_backend:?}: {scan_outcome:#?}");
    assert_eq!(
        scan_outcome.detected_threats.len(),
        2,
        "both files detected"
    );
    assert!(
        scan_outcome
            .detected_threats
            .iter()
            .any(|detected_threat| detected_threat.file_path == non_utf8_path),
        "non-UTF-8 path preserved"
    );

    let quarantine_vault = open_host_vault(&verification_root.path().join("vault")).await;
    let moved_record = quarantine_vault
        .move_file_into_quarantine(
            &non_utf8_path,
            &scan_outcome.detected_threats[0].threat_name,
        )
        .await
        .expect("quarantined");
    assert!(!non_utf8_path.exists());
    quarantine_vault
        .restore_quarantined_file(moved_record.entry_id)
        .await
        .expect("restored");
    assert_eq!(
        fs::read(&non_utf8_path).expect("restored"),
        eicar_test_bytes()
    );
}

#[tokio::test]
#[ignore = "needs a real ClamAV host"]
async fn host_clamd_detects_quarantines_and_restores_outside_on_access_paths() {
    assert_eq!(
        probe_clamd_availability(&ScannerProgramPaths::locate_trusted_programs()).await,
        ScannerBackend::ClamdDaemon
    );
    verify_detection_quarantine_and_restore(ScannerBackend::ClamdDaemon).await;
}

#[tokio::test]
#[ignore = "needs a real ClamAV host"]
async fn host_clamscan_detects_quarantines_and_restores_outside_on_access_paths() {
    verify_detection_quarantine_and_restore(ScannerBackend::StandaloneClamscan).await;
}

async fn verify_blocked_file_flow(scanner_backend: ScannerBackend, quarantine_directory: &Path) {
    let downloads_directory =
        PathBuf::from(std::env::var_os("HOME").expect("home directory")).join("Downloads");
    let eicar_path = downloads_directory.join(format!(
        "lazaret-eicar-{}-{scanner_backend:?}.txt",
        std::process::id()
    ));
    fs::write(&eicar_path, eicar_test_bytes()).expect("write into Downloads");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let read_outcome = fs::read(&eicar_path);
    println!(
        "{scanner_backend:?} read as user: {:?}",
        read_outcome.as_ref().map(Vec::len)
    );
    assert_eq!(
        read_outcome
            .err()
            .and_then(|read_failure| read_failure.raw_os_error()),
        Some(rustix::io::Errno::PERM.raw_os_error()),
        "on-access prevention must be blocking this file"
    );

    let verification_root = tempfile::tempdir_in(quarantine_directory).expect("verification root");
    let scan_outcome = complete_scan(host_scan_request(
        vec![eicar_path.clone()],
        scanner_backend,
        verification_root.path(),
    ))
    .await;
    println!("{scanner_backend:?} scan: {scan_outcome:#?}");
    assert!(scan_outcome.threats_were_found(), "blocked file reported");
    assert_eq!(scan_outcome.detected_threats[0].file_path, eicar_path);

    let quarantine_vault = open_host_vault(&verification_root.path().join("vault")).await;
    let moved_record = quarantine_vault
        .move_file_into_quarantine(&eicar_path, &scan_outcome.detected_threats[0].threat_name)
        .await
        .expect("blocked file quarantined");
    println!("{scanner_backend:?} quarantined: {moved_record:#?}");
    assert!(!eicar_path.exists(), "source moved out of Downloads");
    assert_eq!(
        fs::read(&moved_record.quarantine_path).expect("payload readable"),
        eicar_test_bytes()
    );

    quarantine_vault
        .restore_quarantined_file(moved_record.entry_id)
        .await
        .expect("restored");
    assert!(eicar_path.exists(), "restored to Downloads");
    println!("{scanner_backend:?} restored; removing test file");
    fs::remove_file(&eicar_path).expect("remove test file");
}

#[tokio::test]
#[ignore = "needs a real ClamAV host with OnAccessPrevention on ~/Downloads"]
async fn host_blocked_file_is_detected_quarantined_and_restored() {
    let vault_parent =
        PathBuf::from(std::env::var_os("HOME").expect("home directory")).join(".local/share");
    verify_blocked_file_flow(ScannerBackend::ClamdDaemon, &vault_parent).await;
    verify_blocked_file_flow(ScannerBackend::StandaloneClamscan, &vault_parent).await;
}

async fn verify_cancel_stops_scanner(scanner_backend: ScannerBackend, scan_target: PathBuf) {
    let temporary_entries_before = clamav_temporary_entries();
    let verification_root = tempfile::tempdir().expect("verification root");
    let (abortable_events, scan_abort_handle) = stream::abortable(scan_progress_events(
        host_scan_request(vec![scan_target], scanner_backend, verification_root.path()),
    ));
    let scan_task = tokio::spawn(abortable_events.count());
    tokio::time::sleep(Duration::from_secs(8)).await;
    let scanner_program = match scanner_backend {
        ScannerBackend::ClamdDaemon => "clamdscan",
        ScannerBackend::StandaloneClamscan => "clamscan",
    };
    let running_before = scanner_process_ids(scanner_program);
    println!("{scanner_backend:?} running before cancel: {running_before:?}");
    let cancelled_at = Instant::now();
    scan_abort_handle.abort();
    let event_count = scan_task.await.expect("scan task");
    println!("{scanner_backend:?} events before cancel: {event_count}");
    let stop_deadline = Duration::from_secs(10);
    while !scanner_process_ids(scanner_program).is_empty() && cancelled_at.elapsed() < stop_deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!(
        "{scanner_backend:?} stopped after {:?}; remaining {:?}",
        cancelled_at.elapsed(),
        scanner_process_ids(scanner_program)
    );
    assert!(
        scanner_process_ids(scanner_program).is_empty(),
        "scanner exited"
    );
    assert_eq!(
        probe_clamd_availability(&ScannerProgramPaths::locate_trusted_programs()).await,
        ScannerBackend::ClamdDaemon,
        "clamd stays healthy"
    );
    let leftover_entries = clamav_temporary_entries()
        .into_iter()
        .filter(|entry_name| !temporary_entries_before.contains(entry_name))
        .collect::<Vec<_>>();
    println!("{scanner_backend:?} new clamav temp entries: {leftover_entries:?}");
    assert!(leftover_entries.is_empty(), "no temp directories left");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fs::read_dir(verification_root.path())
            .expect("private directory")
            .count(),
        0,
        "private scanner files removed"
    );
}

fn scanner_process_ids(scanner_program: &str) -> Vec<String> {
    std::process::Command::new("pgrep")
        .args(["-x", scanner_program])
        .output()
        .map(|pgrep_output| {
            String::from_utf8_lossy(&pgrep_output.stdout)
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "needs a real ClamAV host and a large directory in HOST_LARGE_SCAN_TARGET"]
async fn host_cancel_stops_clamd_scan() {
    let scan_target = PathBuf::from(std::env::var_os("HOST_LARGE_SCAN_TARGET").expect("target"));
    verify_cancel_stops_scanner(ScannerBackend::ClamdDaemon, scan_target).await;
}

#[tokio::test]
#[ignore = "needs a real ClamAV host and a large directory in HOST_LARGE_SCAN_TARGET"]
async fn host_cancel_stops_clamscan_scan() {
    let scan_target = PathBuf::from(std::env::var_os("HOST_LARGE_SCAN_TARGET").expect("target"));
    verify_cancel_stops_scanner(ScannerBackend::StandaloneClamscan, scan_target).await;
}

#[tokio::test]
#[ignore = "needs a real ClamAV host"]
async fn host_status_probes_read_the_real_system() {
    let service_state =
        crate::host_services::clamav_programs::database_directory_status::detect_freshclam_service(
        )
        .await;
    println!("freshclam service: {service_state:?}");
    let database_directory =
        crate::host_services::clamav_programs::database_directory_status::configured_database_directory();
    let directory_status =
        crate::host_services::clamav_programs::database_directory_status::inspect_database_directory(
            &database_directory,
            std::time::SystemTime::now(),
        );
    println!("database directory: {directory_status:#?}");
    println!(
        "update plan: {:?}",
        crate::signatures_page::signature_update_dialog::database_update_events::plan_database_update(service_state)
    );
    println!(
        "distribution: {:?}",
        crate::host_services::clamav_programs::distribution_install_guides::detect_distribution_family()
    );
}

#[tokio::test]
#[ignore = "needs a real ClamAV host with OnAccessPrevention on ~/Downloads"]
async fn host_background_detection_flows_from_journal_to_quarantine() {
    let home_directory = PathBuf::from(std::env::var_os("HOME").expect("home directory"));
    let eicar_path = home_directory
        .join("Downloads")
        .join(format!("lazaret-detection-{}.txt", std::process::id()));
    let verification_root =
        tempfile::tempdir_in(&home_directory).expect("verification root on the same filesystem");
    let activity_history =
        ActivityHistory::at_database_path(verification_root.path().join("history.db"));

    let mut journal_events = Box::pin(detection_journal_events(
        JournalStartPosition::FromOldestEntry,
    ));
    while tokio::time::timeout(Duration::from_secs(3), journal_events.next())
        .await
        .is_ok()
    {}

    fs::write(&eicar_path, eicar_test_bytes()).expect("write into Downloads");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let _refused_read = fs::read(&eicar_path);
    assert_eq!(
        inspect_detected_file(&eicar_path),
        DetectedFileState::BlockedInPlace,
        "on-access prevention must be blocking this file"
    );

    let mut matching_records = Vec::new();
    let mut last_cursor = String::new();
    while let Ok(Some(journal_event)) =
        tokio::time::timeout(Duration::from_secs(5), journal_events.next()).await
    {
        if let DetectionJournalEvent::DetectionObserved {
            detection_record,
            journal_cursor,
        } = journal_event
            && detection_record.file_path == eicar_path
        {
            matching_records.push(detection_record);
            last_cursor = journal_cursor;
        }
    }
    println!(
        "live journal lines for the file: {}",
        matching_records.len()
    );
    assert!(
        !matching_records.is_empty(),
        "the follower must wake up on a new journal entry"
    );

    let newly_opened = activity_history
        .record_detection_batch(&matching_records, &last_cursor)
        .await
        .expect("recorded");
    assert_eq!(newly_opened.len(), 1, "one notification for the file");
    let stored_detections = activity_history.list_detections().await.expect("listed");
    assert_eq!(stored_detections.len(), 1, "one row for the file");
    let stored_detection = stored_detections[0].clone();
    assert_eq!(stored_detection.signature_name, "Eicar-Test-Signature");
    assert!(stored_detection.found_on_access);
    assert_eq!(
        stored_detection.sighting_count,
        i64::try_from(matching_records.len()).expect("line count")
    );

    let incident_steps = incident_timeline(
        &DisplayedDetection {
            stored_detection: stored_detection.clone(),
            file_state: inspect_detected_file(&eicar_path),
        },
        DeletionPrompt::NotAsked,
        &SignatureLookupState::NotLookedUp,
        DistributionFamily::NixosFamily,
    );
    incident_steps.iter().for_each(|incident_step| {
        println!(
            "{:?} | {} | {}",
            incident_step.node_state, incident_step.step_title, incident_step.status_text
        );
    });

    let quarantine_vault = open_host_vault(&verification_root.path().join("vault")).await;
    let moved_record = quarantine_vault
        .move_file_into_quarantine(&eicar_path, &stored_detection.signature_name)
        .await
        .expect("blocked file quarantined");
    assert_eq!(moved_record.threat_name, "Eicar-Test-Signature");
    assert_eq!(
        inspect_detected_file(&eicar_path),
        DetectedFileState::NoLongerThere
    );
    activity_history
        .resolve_detection(
            stored_detection.detection_id,
            DetectionResolution::MovedToQuarantine,
            stored_detection.last_seen_unix + 1,
        )
        .await
        .expect("resolved");
    assert_eq!(
        activity_history.list_detections().await.expect("listed")[0].resolution,
        DetectionResolution::MovedToQuarantine
    );
}

#[tokio::test]
#[ignore = "needs a real ClamAV host with OnAccessPrevention on ~/Downloads"]
async fn host_refreshing_after_sightings_does_not_feed_back_into_the_journal() {
    let home_directory = PathBuf::from(std::env::var_os("HOME").expect("home directory"));
    let eicar_path = home_directory
        .join("Downloads")
        .join(format!("lazaret-feedback-{}.txt", std::process::id()));
    let verification_root =
        tempfile::tempdir_in(&home_directory).expect("verification root on the same filesystem");
    let activity_history =
        ActivityHistory::at_database_path(verification_root.path().join("history.db"));
    let mut journal_events = Box::pin(detection_journal_events(
        JournalStartPosition::FromOldestEntry,
    ));
    while tokio::time::timeout(Duration::from_secs(3), journal_events.next())
        .await
        .is_ok()
    {}

    fs::write(&eicar_path, eicar_test_bytes()).expect("write into Downloads");
    let started_watching = Instant::now();
    let mut displayed_detections = Vec::new();
    let mut settled_line_count = 0_u32;
    let mut late_line_count = 0_u32;
    while started_watching.elapsed() < Duration::from_secs(25) {
        let Ok(Some(journal_event)) =
            tokio::time::timeout(Duration::from_secs(1), journal_events.next()).await
        else {
            continue;
        };
        let DetectionJournalEvent::DetectionObserved {
            detection_record,
            journal_cursor,
        } = journal_event
        else {
            continue;
        };
        if detection_record.file_path != eicar_path {
            continue;
        }
        if started_watching.elapsed() < Duration::from_secs(10) {
            settled_line_count += 1;
        } else {
            late_line_count += 1;
        }
        let newly_opened = activity_history
            .record_detection_batch(std::slice::from_ref(&detection_record), &journal_cursor)
            .await
            .expect("recorded");
        let known_file_states = file_states_to_keep(&displayed_detections, &newly_opened);
        if let BackgroundDetectionsPageCommand::DetectionsLoaded(loaded_detections) =
            load_displayed_detections(activity_history.clone(), known_file_states).await
        {
            displayed_detections = loaded_detections;
        }
    }
    println!("lines in the first 10s: {settled_line_count}, in the next 15s: {late_line_count}");
    let _removal_outcome = fs::remove_file(&eicar_path);
    assert!(settled_line_count > 0, "the detection must be seen");
    assert_eq!(
        late_line_count, 0,
        "refreshing must not cause new sightings"
    );
}
