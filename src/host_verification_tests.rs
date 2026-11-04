use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use futures::{StreamExt, future::ready, stream};

use crate::{
    file_quarantine::quarantine_entry_database::QuarantineVault,
    malware_scan::{
        scan_progress_events::{CompletedScanOutcome, ScanRequest, scan_progress_events},
        scanner_command_builder::{ScannerBackend, ScannerProgramPaths, probe_clamd_availability},
    },
};

fn eicar_test_bytes() -> Vec<u8> {
    [
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-",
        "TEST-FILE!$H+H*",
    ]
    .concat()
    .into_bytes()
}

fn host_scan_request(
    scan_targets: Vec<PathBuf>,
    scanner_backend: ScannerBackend,
    file_list_directory: &Path,
) -> ScanRequest {
    ScanRequest {
        scan_targets,
        scanner_backend,
        scanner_programs: ScannerProgramPaths::from_search_path(),
        file_list_directory: file_list_directory.to_path_buf(),
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
        probe_clamd_availability(&ScannerProgramPaths::from_search_path()).await,
        ScannerBackend::ClamdDaemon
    );
    verify_detection_quarantine_and_restore(ScannerBackend::ClamdDaemon).await;
}

#[tokio::test]
#[ignore = "needs a real ClamAV host"]
async fn host_clamscan_detects_quarantines_and_restores_outside_on_access_paths() {
    verify_detection_quarantine_and_restore(ScannerBackend::StandaloneClamscan).await;
}

#[tokio::test]
#[ignore = "needs a real ClamAV host with OnAccessPrevention; records behaviour without asserting \
            it"]
async fn host_records_behaviour_inside_on_access_prevention_path() {
    let downloads_directory =
        PathBuf::from(std::env::var_os("HOME").expect("home directory")).join("Downloads");
    let eicar_path = downloads_directory.join(format!("clamui-eicar-{}.txt", std::process::id()));
    let write_outcome = fs::write(&eicar_path, eicar_test_bytes());
    println!("write into Downloads: {write_outcome:?}");
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!(
        "read as user: {:?}",
        fs::read(&eicar_path).map(|file_bytes| file_bytes.len())
    );

    let verification_root = tempfile::tempdir().expect("verification root");
    let clamd_outcome = complete_scan(host_scan_request(
        vec![eicar_path.clone()],
        ScannerBackend::ClamdDaemon,
        verification_root.path(),
    ))
    .await;
    println!("clamd scan: {clamd_outcome:#?}");
    let clamscan_outcome = complete_scan(host_scan_request(
        vec![eicar_path.clone()],
        ScannerBackend::StandaloneClamscan,
        verification_root.path(),
    ))
    .await;
    println!("clamscan scan: {clamscan_outcome:#?}");

    let quarantine_vault = open_host_vault(&verification_root.path().join("vault")).await;
    let move_outcome = quarantine_vault
        .move_file_into_quarantine(&eicar_path, "Eicar-Test-Signature")
        .await;
    println!("quarantine move: {move_outcome:#?}");
    println!(
        "listed entries: {:#?}",
        quarantine_vault.list_quarantine_entries().await
    );
    println!("file still present: {}", eicar_path.exists());
    println!("remove leftover: {:?}", fs::remove_file(&eicar_path));
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
        probe_clamd_availability(&ScannerProgramPaths::from_search_path()).await,
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
    let component_availabilities = futures::future::join_all(
        crate::clamav_components::component_availability::ALL_CLAMAV_COMPONENTS
            .map(crate::clamav_components::component_availability::probe_component_availability),
    )
    .await;
    println!("components: {component_availabilities:#?}");
    let service_state =
        crate::virus_database::database_directory_status::detect_freshclam_service().await;
    println!("freshclam service: {service_state:?}");
    let database_directory =
        crate::virus_database::database_directory_status::configured_database_directory();
    let directory_status =
        crate::virus_database::database_directory_status::inspect_database_directory(
            &database_directory,
            std::time::SystemTime::now(),
        );
    println!("database directory: {directory_status:#?}");
    println!(
        "update plan: {:?}",
        crate::virus_database::database_update_events::plan_database_update(service_state)
    );
    println!(
        "distribution: {:?}",
        crate::clamav_components::distribution_install_guides::detect_distribution_family()
    );
}
