use std::{collections::BTreeMap, num::NonZeroU64, path::PathBuf, time::Duration};

use jiff::Timestamp;
use tokio::task::spawn_blocking;
use turso::{Builder, Connection, Row, transaction::TransactionBehavior};

use crate::host_services::{
    clamav_scanner::{
        scan_progress_events::ThreatFindings, scanner_output_parser::sanitize_scanner_line,
    },
    desktop::file_process_lock::{ProcessFileLock, wait_for_file_lock},
    quarantine_vault::quarantine_file_moves::{
        QuarantineMoveFailure, pin_database_file, secure_database_files,
    },
};

const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_RETAINED_ENTRIES: i64 = 10_000;
const ENTRIES_KEEPING_OUTPUT: i64 = 200;
const HISTORY_SCHEMA: &str = include_str!("../../../data/database-schemas/history.sql");
const HISTORY_CONNECTION_PRAGMAS: &str = "PRAGMA foreign_keys=ON;";
const ENTRY_QUERY: &str = "
    SELECT activity_entries.entry_id, activity_entries.started_at_unix,
        activity_entries.activity_status, activity_entries.duration_millis,
        activity_entries.activity_output, scan_activities.scan_origin,
        scan_inspections.inspected_file_count, scan_threat_counts.threat_count
    FROM activity_entries
    LEFT JOIN scan_activities ON scan_activities.entry_id = activity_entries.entry_id
    LEFT JOIN scan_inspections ON scan_inspections.entry_id = activity_entries.entry_id
    LEFT JOIN scan_threat_counts ON scan_threat_counts.entry_id = activity_entries.entry_id
    ORDER BY activity_entries.started_at_unix DESC, activity_entries.entry_id DESC";
const TARGET_QUERY: &str =
    "SELECT entry_id, target_path FROM scan_activity_targets ORDER BY entry_id, target_position";

#[derive(Debug, thiserror::Error)]
pub enum ActivityHistoryFailure {
    #[error("the history database failed: {0}")]
    DatabaseFailed(#[from] turso::Error),
    #[error("the history file is unavailable: {0}")]
    HistoryFileUnavailable(#[from] QuarantineMoveFailure),
    #[error("the history file check stopped unexpectedly: {0}")]
    HistoryFileCheckInterrupted(#[from] tokio::task::JoinError),
    #[error("checking the detected files stopped unexpectedly: {0}")]
    DetectedFileCheckInterrupted(tokio::task::JoinError),
    #[error("the history database path is not valid UTF-8")]
    DatabasePathNotUtf8,
    #[error("a stored history entry has an unknown status")]
    StoredStatusUnknown,
    #[error("a stored history entry has an unknown scan origin")]
    StoredOriginUnknown,
    #[error("a stored scan entry lacks its scan details, or an update entry has them")]
    StoredScanDetailsInconsistent,
    #[error("a stored submission has an unknown service, kind or status")]
    StoredSubmissionUnreadable,
    #[error("a stored history entry has an impossible time: {0}")]
    StoredTimeInvalid(#[from] jiff::Error),
    #[error("the history lock is unavailable: {0}")]
    HistoryLockUnavailable(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FoundThreatCount {
    CountedThreats { threat_count: NonZeroU64 },
    UncountedThreats,
}

impl FoundThreatCount {
    pub fn from_findings(threat_findings: &ThreatFindings) -> Option<Self> {
        match threat_findings {
            ThreatFindings::NoThreatsFound => None,
            ThreatFindings::AttributedThreats(attributed_threats) => Some(Self::CountedThreats {
                threat_count: attributed_threats.threat_count(),
            }),
            ThreatFindings::UnattributedThreatsOnly => Some(Self::UncountedThreats),
        }
    }

    const fn exported_count(self) -> u64 {
        match self {
            Self::CountedThreats { threat_count } => threat_count.get(),
            Self::UncountedThreats => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanActivityStatus {
    ScanClean,
    ScanInfected { found_threats: FoundThreatCount },
    ScanFailed,
    ScanCancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanOrigin {
    ManualScan,
    ScheduledScan,
    DeviceScan,
}

const ALL_SCAN_ORIGINS: [ScanOrigin; 3] = [
    ScanOrigin::ManualScan,
    ScanOrigin::ScheduledScan,
    ScanOrigin::DeviceScan,
];

impl ScanOrigin {
    pub const fn stored_origin_text(self) -> &'static str {
        match self {
            Self::ManualScan => "manual_scan",
            Self::ScheduledScan => "scheduled_scan",
            Self::DeviceScan => "device_scan",
        }
    }

    pub fn from_stored_origin_text(stored_text: &str) -> Result<Self, ActivityHistoryFailure> {
        ALL_SCAN_ORIGINS
            .into_iter()
            .find(|scan_origin| scan_origin.stored_origin_text() == stored_text)
            .ok_or(ActivityHistoryFailure::StoredOriginUnknown)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateActivityStatus {
    UpdateApplied,
    UpdateAlreadyCurrent,
    UpdateRequested,
    UpdateResultUnknown,
    UpdateFailed,
    UpdateCancelled,
}

const ALL_UPDATE_STATUSES: [UpdateActivityStatus; 6] = [
    UpdateActivityStatus::UpdateApplied,
    UpdateActivityStatus::UpdateAlreadyCurrent,
    UpdateActivityStatus::UpdateRequested,
    UpdateActivityStatus::UpdateResultUnknown,
    UpdateActivityStatus::UpdateFailed,
    UpdateActivityStatus::UpdateCancelled,
];

impl UpdateActivityStatus {
    const fn stored_status_text(self) -> &'static str {
        match self {
            Self::UpdateApplied => "update_applied",
            Self::UpdateAlreadyCurrent => "update_already_current",
            Self::UpdateRequested => "update_requested",
            Self::UpdateResultUnknown => "update_result_unknown",
            Self::UpdateFailed => "update_failed",
            Self::UpdateCancelled => "update_cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityRecord {
    ScanActivity {
        scan_targets: Vec<PathBuf>,
        inspected_file_count: u64,
        scan_status: ScanActivityStatus,
        scan_origin: ScanOrigin,
    },
    SkippedScan {
        scan_targets: Vec<PathBuf>,
    },
    UpdateActivity {
        update_status: UpdateActivityStatus,
    },
}

const SCAN_TARGET_SEPARATOR: char = '\n';

fn exported_scan_targets(scan_targets: &[PathBuf]) -> String {
    scan_targets
        .iter()
        .map(|scan_target| sanitize_scanner_line(&scan_target.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(&SCAN_TARGET_SEPARATOR.to_string())
}

fn stored_target_paths(scan_targets: &[PathBuf]) -> Vec<String> {
    scan_targets
        .iter()
        .map(|scan_target| sanitize_scanner_line(&scan_target.to_string_lossy()))
        .filter(|target_text| !target_text.is_empty())
        .collect()
}

pub struct ExportedActivityColumns {
    pub activity_status: &'static str,
    pub activity_targets: String,
    pub inspected_file_count: u64,
    pub threat_count: u64,
}

struct StoredScanDetails {
    scan_status_text: &'static str,
    scan_origin: ScanOrigin,
    target_paths: Vec<String>,
    scan_inspection: ScanInspection,
}

enum ScanInspection {
    InspectionNotRun,
    InspectedFiles {
        inspected_file_count: u64,
        stored_threat_count: StoredThreatCount,
    },
}

enum StoredThreatCount {
    NoThreatCountRow,
    ThreatCountRow { threat_count: NonZeroU64 },
}

enum StoredActivityDetails {
    UpdateWithoutDetails,
    ScanWithDetails(StoredScanDetails),
}

impl ActivityRecord {
    pub const fn stored_status_text(&self) -> &'static str {
        match self {
            Self::ScanActivity { scan_status, .. } => match scan_status {
                ScanActivityStatus::ScanClean => "scan_clean",
                ScanActivityStatus::ScanInfected { .. } => "scan_infected",
                ScanActivityStatus::ScanFailed => "scan_failed",
                ScanActivityStatus::ScanCancelled => "scan_cancelled",
            },
            Self::SkippedScan { .. } => "scan_skipped",
            Self::UpdateActivity { update_status } => update_status.stored_status_text(),
        }
    }

    pub fn scan_targets(&self) -> &[PathBuf] {
        match self {
            Self::ScanActivity { scan_targets, .. } | Self::SkippedScan { scan_targets } => {
                scan_targets
            }
            Self::UpdateActivity { .. } => &[],
        }
    }

    const fn exported_inspected_file_count(&self) -> u64 {
        match self {
            Self::ScanActivity {
                inspected_file_count,
                ..
            } => *inspected_file_count,
            Self::SkippedScan { .. } | Self::UpdateActivity { .. } => 0,
        }
    }

    const fn exported_threat_count(&self) -> u64 {
        match self {
            Self::ScanActivity {
                scan_status: ScanActivityStatus::ScanInfected { found_threats },
                ..
            } => found_threats.exported_count(),
            Self::ScanActivity { .. } | Self::SkippedScan { .. } | Self::UpdateActivity { .. } => 0,
        }
    }

    pub fn exported_columns(&self) -> ExportedActivityColumns {
        ExportedActivityColumns {
            activity_status: self.stored_status_text(),
            activity_targets: exported_scan_targets(self.scan_targets()),
            inspected_file_count: self.exported_inspected_file_count(),
            threat_count: self.exported_threat_count(),
        }
    }

    fn stored_details(&self) -> StoredActivityDetails {
        match self {
            Self::ScanActivity {
                scan_targets,
                inspected_file_count,
                scan_status,
                scan_origin,
            } => StoredActivityDetails::ScanWithDetails(StoredScanDetails {
                scan_status_text: self.stored_status_text(),
                scan_origin: *scan_origin,
                target_paths: stored_target_paths(scan_targets),
                scan_inspection: ScanInspection::InspectedFiles {
                    inspected_file_count: *inspected_file_count,
                    stored_threat_count: match scan_status {
                        ScanActivityStatus::ScanInfected {
                            found_threats: FoundThreatCount::CountedThreats { threat_count },
                        } => StoredThreatCount::ThreatCountRow {
                            threat_count: *threat_count,
                        },
                        ScanActivityStatus::ScanInfected {
                            found_threats: FoundThreatCount::UncountedThreats,
                        }
                        | ScanActivityStatus::ScanClean
                        | ScanActivityStatus::ScanFailed
                        | ScanActivityStatus::ScanCancelled => StoredThreatCount::NoThreatCountRow,
                    },
                },
            }),
            Self::SkippedScan { scan_targets } => {
                StoredActivityDetails::ScanWithDetails(StoredScanDetails {
                    scan_status_text: self.stored_status_text(),
                    scan_origin: ScanOrigin::ScheduledScan,
                    target_paths: stored_target_paths(scan_targets),
                    scan_inspection: ScanInspection::InspectionNotRun,
                })
            }
            Self::UpdateActivity { .. } => StoredActivityDetails::UpdateWithoutDetails,
        }
    }
}

fn activity_record_from_row(
    entry_row: &Row,
    scan_targets: Vec<PathBuf>,
) -> Result<ActivityRecord, ActivityHistoryFailure> {
    let stored_status: String = entry_row.get(2)?;
    let scan_origin_text: Option<String> = entry_row.get(5)?;
    let inspected_file_count: Option<u64> = entry_row.get(6)?;
    let threat_count: Option<u64> = entry_row.get(7)?;
    if let Some(update_status) = ALL_UPDATE_STATUSES
        .into_iter()
        .find(|update_status| update_status.stored_status_text() == stored_status)
    {
        return match scan_origin_text {
            None => Ok(ActivityRecord::UpdateActivity { update_status }),
            Some(_) => Err(ActivityHistoryFailure::StoredScanDetailsInconsistent),
        };
    }
    let scan_origin = match scan_origin_text {
        Some(origin_text) => ScanOrigin::from_stored_origin_text(&origin_text)?,
        None => return Err(ActivityHistoryFailure::StoredScanDetailsInconsistent),
    };
    let ran_scan = |inspected_file_count, scan_status| ActivityRecord::ScanActivity {
        scan_targets: scan_targets.clone(),
        inspected_file_count,
        scan_status,
        scan_origin,
    };
    match (stored_status.as_str(), inspected_file_count, threat_count) {
        ("scan_skipped", None, None) => Ok(ActivityRecord::SkippedScan {
            scan_targets: scan_targets.clone(),
        }),
        ("scan_clean", Some(inspected_file_count), None) => Ok(ran_scan(
            inspected_file_count,
            ScanActivityStatus::ScanClean,
        )),
        ("scan_failed", Some(inspected_file_count), None) => Ok(ran_scan(
            inspected_file_count,
            ScanActivityStatus::ScanFailed,
        )),
        ("scan_cancelled", Some(inspected_file_count), None) => Ok(ran_scan(
            inspected_file_count,
            ScanActivityStatus::ScanCancelled,
        )),
        ("scan_infected", Some(inspected_file_count), None) => Ok(ran_scan(
            inspected_file_count,
            ScanActivityStatus::ScanInfected {
                found_threats: FoundThreatCount::UncountedThreats,
            },
        )),
        ("scan_infected", Some(inspected_file_count), Some(stored_count)) => {
            NonZeroU64::new(stored_count)
                .map(|threat_count| {
                    ran_scan(
                        inspected_file_count,
                        ScanActivityStatus::ScanInfected {
                            found_threats: FoundThreatCount::CountedThreats { threat_count },
                        },
                    )
                })
                .ok_or(ActivityHistoryFailure::StoredScanDetailsInconsistent)
        }
        (
            "scan_skipped" | "scan_clean" | "scan_failed" | "scan_cancelled" | "scan_infected",
            _stored_inspection,
            _stored_threats,
        ) => Err(ActivityHistoryFailure::StoredScanDetailsInconsistent),
        (_unknown_status, _stored_inspection, _stored_threats) => {
            Err(ActivityHistoryFailure::StoredStatusUnknown)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewActivityEntry {
    pub started_at: Timestamp,
    pub activity_record: ActivityRecord,
    pub duration_millis: u64,
    pub activity_output: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEntryRecord {
    pub entry_id: i64,
    pub started_at: Timestamp,
    pub activity_record: ActivityRecord,
    pub duration_millis: u64,
    pub activity_output: String,
}

fn activity_entry_from_row(
    entry_row: &Row,
    targets_by_entry: &mut BTreeMap<i64, Vec<PathBuf>>,
) -> Result<ActivityEntryRecord, ActivityHistoryFailure> {
    let entry_id: i64 = entry_row.get(0)?;
    Ok(ActivityEntryRecord {
        entry_id,
        started_at: Timestamp::from_second(entry_row.get(1)?)?,
        activity_record: activity_record_from_row(
            entry_row,
            targets_by_entry.remove(&entry_id).unwrap_or_default(),
        )?,
        duration_millis: entry_row.get(3)?,
        activity_output: entry_row.get(4)?,
    })
}

async fn stored_targets_by_entry(
    database_connection: &Connection,
) -> Result<BTreeMap<i64, Vec<PathBuf>>, ActivityHistoryFailure> {
    let mut target_rows = database_connection.query(TARGET_QUERY, ()).await?;
    let mut targets_by_entry = BTreeMap::<i64, Vec<PathBuf>>::new();
    while let Some(target_row) = target_rows.next().await? {
        targets_by_entry
            .entry(target_row.get(0)?)
            .or_default()
            .push(PathBuf::from(target_row.get::<String>(1)?));
    }
    Ok(targets_by_entry)
}

async fn write_activity_details(
    database_connection: &Connection,
    entry_id: i64,
    activity_record: &ActivityRecord,
) -> Result<(), ActivityHistoryFailure> {
    let StoredActivityDetails::ScanWithDetails(scan_details) = activity_record.stored_details()
    else {
        return Ok(());
    };
    database_connection
        .execute(
            "INSERT INTO scan_activities (entry_id, activity_status, scan_origin) VALUES (?1, ?2, \
             ?3)",
            (
                entry_id,
                scan_details.scan_status_text,
                scan_details.scan_origin.stored_origin_text(),
            ),
        )
        .await?;
    for (target_position, target_path) in scan_details.target_paths.into_iter().enumerate() {
        database_connection
            .execute(
                "INSERT INTO scan_activity_targets (entry_id, target_position, target_path) \
                 VALUES (?1, ?2, ?3)",
                (entry_id, target_position as u64, target_path),
            )
            .await?;
    }
    let ScanInspection::InspectedFiles {
        inspected_file_count,
        stored_threat_count,
    } = scan_details.scan_inspection
    else {
        return Ok(());
    };
    database_connection
        .execute(
            "INSERT INTO scan_inspections (entry_id, activity_status, inspected_file_count) \
             VALUES (?1, ?2, ?3)",
            (
                entry_id,
                scan_details.scan_status_text,
                inspected_file_count,
            ),
        )
        .await?;
    if let StoredThreatCount::ThreatCountRow { threat_count } = stored_threat_count {
        database_connection
            .execute(
                "INSERT INTO scan_threat_counts (entry_id, activity_status, threat_count) VALUES \
                 (?1, ?2, ?3)",
                (entry_id, scan_details.scan_status_text, threat_count.get()),
            )
            .await?;
    }
    Ok(())
}

async fn insert_activity_entry(
    database_connection: &Connection,
    activity_entry: &ActivityEntryRecord,
) -> Result<(), ActivityHistoryFailure> {
    database_connection
        .execute(
            "INSERT INTO activity_entries (entry_id, started_at_unix, activity_status, \
             duration_millis, activity_output) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                activity_entry.entry_id,
                activity_entry.started_at.as_second(),
                activity_entry.activity_record.stored_status_text(),
                activity_entry.duration_millis,
                activity_entry.activity_output.as_str(),
            ),
        )
        .await?;
    write_activity_details(
        database_connection,
        activity_entry.entry_id,
        &activity_entry.activity_record,
    )
    .await
}

async fn next_entry_id(database_connection: &Connection) -> Result<i64, ActivityHistoryFailure> {
    Ok(database_connection
        .prepare("SELECT COALESCE(MAX(entry_id), 0) + 1 FROM activity_entries")
        .await?
        .query_row(())
        .await?
        .get(0)?)
}

async fn list_activity_entries(
    database_connection: &Connection,
) -> Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure> {
    let mut targets_by_entry = stored_targets_by_entry(database_connection).await?;
    let mut entry_rows = database_connection.query(ENTRY_QUERY, ()).await?;
    let mut recent_entries = Vec::new();
    while let Some(entry_row) = entry_rows.next().await? {
        recent_entries.push(activity_entry_from_row(&entry_row, &mut targets_by_entry)?);
    }
    Ok(recent_entries)
}

#[derive(Clone, Debug)]
pub struct ActivityHistory {
    database_path: PathBuf,
}

impl ActivityHistory {
    pub fn at_database_path(database_path: PathBuf) -> Self {
        Self { database_path }
    }

    pub(crate) async fn lock_history(&self) -> Result<ProcessFileLock, ActivityHistoryFailure> {
        let lock_path = self.database_path.with_extension("lock");
        Ok(spawn_blocking(move || wait_for_file_lock(&lock_path)).await??)
    }

    pub(crate) async fn open_connection(&self) -> Result<Connection, ActivityHistoryFailure> {
        let pinned_path = self.database_path.clone();
        spawn_blocking(move || pin_database_file(&pinned_path)).await??;
        let database_text_path = self
            .database_path
            .to_str()
            .ok_or(ActivityHistoryFailure::DatabasePathNotUtf8)?;
        let history_database = Builder::new_local(database_text_path).build().await?;
        let database_connection = history_database.connect()?;
        database_connection.busy_timeout(DATABASE_BUSY_TIMEOUT)?;
        database_connection
            .execute_batch(HISTORY_CONNECTION_PRAGMAS)
            .await?;
        database_connection.execute_batch(HISTORY_SCHEMA).await?;
        secure_database_files(&self.database_path);
        Ok(database_connection)
    }

    pub async fn record_activity(
        &self,
        new_entry: NewActivityEntry,
    ) -> Result<(), ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let mut database_connection = self.open_connection().await?;
        let entry_transaction = database_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let entry_id = next_entry_id(&entry_transaction).await?;
        insert_activity_entry(
            &entry_transaction,
            &ActivityEntryRecord {
                entry_id,
                started_at: new_entry.started_at,
                activity_record: new_entry.activity_record,
                duration_millis: new_entry.duration_millis,
                activity_output: new_entry.activity_output,
            },
        )
        .await?;
        entry_transaction
            .execute(
                "UPDATE activity_entries SET activity_output = '' WHERE entry_id <= ?1 - ?2",
                (entry_id, ENTRIES_KEEPING_OUTPUT),
            )
            .await?;
        entry_transaction
            .execute(
                "DELETE FROM activity_entries WHERE entry_id <= ?1 - ?2",
                (entry_id, MAXIMUM_RETAINED_ENTRIES),
            )
            .await?;
        entry_transaction.commit().await?;
        Ok(())
    }

    pub async fn list_recent_entries(
        &self,
    ) -> Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        list_activity_entries(&database_connection).await
    }

    pub async fn clear_all_entries(&self) -> Result<(), ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        self.open_connection()
            .await?
            .execute("DELETE FROM activity_entries", ())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod activity_history_database_tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scan_entry(started_at: Timestamp, activity_output: &str) -> NewActivityEntry {
        NewActivityEntry {
            started_at,
            activity_record: ActivityRecord::ScanActivity {
                scan_targets: vec![PathBuf::from("/scan/target"), PathBuf::from("/scan/other")],
                inspected_file_count: 12,
                scan_status: ScanActivityStatus::ScanInfected {
                    found_threats: FoundThreatCount::CountedThreats {
                        threat_count: NonZeroU64::new(2).expect("two threats"),
                    },
                },
                scan_origin: ScanOrigin::ManualScan,
            },
            duration_millis: 1500,
            activity_output: activity_output.to_owned(),
        }
    }

    #[tokio::test]
    async fn entries_survive_reopening_and_list_newest_first() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("history.db");
        let writing_history = ActivityHistory::at_database_path(database_path.clone());
        writing_history
            .record_activity(scan_entry(Timestamp::constant(100, 0), "older"))
            .await
            .expect("older entry");
        writing_history
            .record_activity(scan_entry(Timestamp::constant(200, 0), "newer"))
            .await
            .expect("newer entry");
        drop(writing_history);
        let listed_entries = ActivityHistory::at_database_path(database_path.clone())
            .list_recent_entries()
            .await
            .expect("listed entries");
        assert_eq!(listed_entries.len(), 2);
        assert_eq!(listed_entries[0].activity_output, "newer");
        assert_eq!(
            listed_entries[0].activity_record,
            scan_entry(Timestamp::constant(200, 0), "newer").activity_record
        );
        assert_eq!(listed_entries[1].started_at, Timestamp::constant(100, 0));
        assert_eq!(
            std::fs::metadata(&database_path)
                .expect("database metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn a_second_handle_sees_entries_written_by_the_first() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("history.db");
        let viewing_history = ActivityHistory::at_database_path(database_path.clone());
        assert!(
            viewing_history
                .list_recent_entries()
                .await
                .expect("empty")
                .is_empty()
        );
        ActivityHistory::at_database_path(database_path)
            .record_activity(scan_entry(Timestamp::constant(100, 0), "written elsewhere"))
            .await
            .expect("written entry");
        assert_eq!(
            viewing_history
                .list_recent_entries()
                .await
                .expect("listed")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn clearing_removes_every_entry() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = ActivityHistory::at_database_path(temporary_root.path().join("history.db"));
        history
            .record_activity(scan_entry(Timestamp::constant(100, 0), "entry"))
            .await
            .expect("entry");
        history.clear_all_entries().await.expect("cleared");
        assert!(
            history
                .list_recent_entries()
                .await
                .expect("listed")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn only_recent_entries_keep_their_output() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = ActivityHistory::at_database_path(temporary_root.path().join("history.db"));
        let connection = history.open_connection().await.expect("connection");
        connection
            .execute(
                "INSERT INTO activity_entries (entry_id, started_at_unix, activity_status, \
                 duration_millis, activity_output) VALUES (1, 1, 'update_applied', 0, 'stale \
                 output')",
                (),
            )
            .await
            .expect("old entry");
        connection
            .execute(
                "INSERT INTO activity_entries (entry_id, started_at_unix, activity_status, \
                 duration_millis, activity_output) VALUES (500, 2, 'update_applied', 0, 'fresh')",
                (),
            )
            .await
            .expect("recent entry");
        drop(connection);
        history
            .record_activity(scan_entry(Timestamp::constant(3, 0), "newest"))
            .await
            .expect("newest");
        let listed_entries = history.list_recent_entries().await.expect("listed");
        assert_eq!(listed_entries[2].activity_output, "");
        assert_eq!(listed_entries[1].activity_output, "fresh");
    }

    async fn recorded_and_listed(activity_record: ActivityRecord) -> ActivityRecord {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = ActivityHistory::at_database_path(temporary_root.path().join("history.db"));
        history
            .record_activity(NewActivityEntry {
                started_at: Timestamp::constant(100, 0),
                activity_record,
                duration_millis: 0,
                activity_output: String::new(),
            })
            .await
            .expect("recorded");
        history
            .list_recent_entries()
            .await
            .expect("listed")
            .remove(0)
            .activity_record
    }

    #[tokio::test]
    async fn a_comma_in_a_target_path_round_trips() {
        let scanned_record = ActivityRecord::ScanActivity {
            scan_targets: vec![
                PathBuf::from("/home/user/report, final.pdf"),
                PathBuf::from("/scan/other"),
            ],
            inspected_file_count: 2,
            scan_status: ScanActivityStatus::ScanClean,
            scan_origin: ScanOrigin::ManualScan,
        };
        assert_eq!(
            recorded_and_listed(scanned_record.clone()).await,
            scanned_record
        );
    }

    #[tokio::test]
    async fn a_scheduled_scan_keeps_its_origin() {
        let scheduled_record = ActivityRecord::ScanActivity {
            scan_targets: vec![PathBuf::from("/home/user")],
            inspected_file_count: 7,
            scan_status: ScanActivityStatus::ScanInfected {
                found_threats: FoundThreatCount::UncountedThreats,
            },
            scan_origin: ScanOrigin::ScheduledScan,
        };
        assert_eq!(
            recorded_and_listed(scheduled_record.clone()).await,
            scheduled_record
        );
    }

    #[tokio::test]
    async fn updates_and_skipped_scans_read_back_without_scan_counts() {
        let update_record = ActivityRecord::UpdateActivity {
            update_status: UpdateActivityStatus::UpdateAlreadyCurrent,
        };
        assert_eq!(
            recorded_and_listed(update_record.clone()).await,
            update_record
        );
        let skipped_record = ActivityRecord::SkippedScan {
            scan_targets: vec![PathBuf::from("/scan/target")],
        };
        assert_eq!(
            recorded_and_listed(skipped_record.clone()).await,
            skipped_record
        );
    }

    #[tokio::test]
    async fn infected_scans_without_named_threats_read_back_as_uncounted() {
        let uncounted_record = ActivityRecord::ScanActivity {
            scan_targets: vec![PathBuf::from("/scan/target")],
            inspected_file_count: 1,
            scan_status: ScanActivityStatus::ScanInfected {
                found_threats: FoundThreatCount::UncountedThreats,
            },
            scan_origin: ScanOrigin::ManualScan,
        };
        assert_eq!(
            recorded_and_listed(uncounted_record.clone()).await,
            uncounted_record
        );
    }

    #[test]
    fn clean_findings_cannot_make_an_infected_scan() {
        assert_eq!(
            FoundThreatCount::from_findings(&ThreatFindings::NoThreatsFound),
            None
        );
        assert_eq!(
            FoundThreatCount::from_findings(&ThreatFindings::UnattributedThreatsOnly),
            Some(FoundThreatCount::UncountedThreats)
        );
    }

    #[tokio::test]
    async fn line_breaks_inside_a_target_cannot_split_it() {
        let scanned_record = ActivityRecord::ScanActivity {
            scan_targets: vec![PathBuf::from("/scan/odd\nname"), PathBuf::new()],
            inspected_file_count: 1,
            scan_status: ScanActivityStatus::ScanClean,
            scan_origin: ScanOrigin::ManualScan,
        };
        assert_eq!(
            recorded_and_listed(scanned_record).await.scan_targets(),
            [PathBuf::from("/scan/odd name")]
        );
    }

    fn every_activity_record() -> Vec<ActivityRecord> {
        let scan_targets = vec![PathBuf::from("/home/user"), PathBuf::from("/srv/share")];
        let ran_statuses = [
            ScanActivityStatus::ScanClean,
            ScanActivityStatus::ScanInfected {
                found_threats: FoundThreatCount::CountedThreats {
                    threat_count: NonZeroU64::new(3).expect("three threats"),
                },
            },
            ScanActivityStatus::ScanInfected {
                found_threats: FoundThreatCount::UncountedThreats,
            },
            ScanActivityStatus::ScanFailed,
            ScanActivityStatus::ScanCancelled,
        ];
        ran_statuses
            .into_iter()
            .flat_map(|scan_status| {
                ALL_SCAN_ORIGINS
                    .into_iter()
                    .map(move |scan_origin| (scan_status, scan_origin))
            })
            .map(|(scan_status, scan_origin)| ActivityRecord::ScanActivity {
                scan_targets: scan_targets.clone(),
                inspected_file_count: 12,
                scan_status,
                scan_origin,
            })
            .chain([ActivityRecord::SkippedScan {
                scan_targets: scan_targets.clone(),
            }])
            .chain(
                ALL_UPDATE_STATUSES
                    .into_iter()
                    .map(|update_status| ActivityRecord::UpdateActivity { update_status }),
            )
            .collect()
    }

    #[tokio::test]
    async fn every_activity_variant_round_trips_through_the_tables() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = ActivityHistory::at_database_path(temporary_root.path().join("history.db"));
        let recorded_records = every_activity_record();
        for (entry_position, activity_record) in recorded_records.iter().enumerate() {
            history
                .record_activity(NewActivityEntry {
                    started_at: Timestamp::constant(100 + entry_position as i64, 0),
                    activity_record: activity_record.clone(),
                    duration_millis: 7,
                    activity_output: format!("output {entry_position}"),
                })
                .await
                .expect("recorded");
        }
        let listed_records = history
            .list_recent_entries()
            .await
            .expect("listed")
            .into_iter()
            .rev()
            .map(|listed_entry| listed_entry.activity_record)
            .collect::<Vec<_>>();
        assert_eq!(listed_records, recorded_records);
    }

    fn raw_count(database_path: &std::path::Path, count_query: &str) -> i64 {
        rusqlite::Connection::open(database_path)
            .expect("database")
            .query_row(count_query, [], |count_row| count_row.get(0))
            .expect("count")
    }

    #[tokio::test]
    async fn updates_store_no_scan_rows_and_targets_are_ordered_rows() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("history.db");
        let history = ActivityHistory::at_database_path(database_path.clone());
        for activity_record in every_activity_record() {
            history
                .record_activity(NewActivityEntry {
                    started_at: Timestamp::constant(100, 0),
                    activity_record,
                    duration_millis: 0,
                    activity_output: String::new(),
                })
                .await
                .expect("recorded");
        }
        assert_eq!(
            raw_count(
                &database_path,
                "SELECT COUNT(*) FROM scan_activities JOIN activity_entries USING (entry_id) \
                 WHERE activity_entries.activity_status LIKE 'update_%'"
            ),
            0
        );
        assert_eq!(
            raw_count(&database_path, "SELECT COUNT(*) FROM scan_activities"),
            16
        );
        assert_eq!(
            raw_count(&database_path, "SELECT COUNT(*) FROM scan_inspections"),
            15
        );
        assert_eq!(
            raw_count(&database_path, "SELECT COUNT(*) FROM scan_threat_counts"),
            3
        );
        assert_eq!(
            raw_count(&database_path, "SELECT COUNT(*) FROM scan_activity_targets"),
            32
        );
        assert_eq!(
            raw_count(
                &database_path,
                "SELECT COUNT(*) FROM scan_activity_targets WHERE target_position = 1 AND \
                 target_path = '/srv/share'"
            ),
            16
        );
        history.clear_all_entries().await.expect("cleared");
        assert_eq!(
            raw_count(
                &database_path,
                "SELECT (SELECT COUNT(*) FROM scan_activities) + (SELECT COUNT(*) FROM \
                 scan_activity_targets) + (SELECT COUNT(*) FROM scan_inspections) + (SELECT \
                 COUNT(*) FROM scan_threat_counts)"
            ),
            0
        );
    }

    #[tokio::test]
    async fn the_activity_schema_refuses_rows_that_cannot_exist() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("history.db");
        ActivityHistory::at_database_path(database_path.clone())
            .list_recent_entries()
            .await
            .expect("created");
        let checked_connection = rusqlite::Connection::open(&database_path).expect("database");
        checked_connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 INSERT INTO activity_entries VALUES (1, 1, 'scan_infected', 0, '');
                 INSERT INTO scan_activities VALUES (1, 'scan_infected', 'manual_scan');
                 INSERT INTO scan_inspections VALUES (1, 'scan_infected', 3);
                 INSERT INTO activity_entries VALUES (2, 1, 'scan_clean', 0, '');
                 INSERT INTO scan_activities VALUES (2, 'scan_clean', 'manual_scan');
                 INSERT INTO scan_inspections VALUES (2, 'scan_clean', 3);
                 INSERT INTO activity_entries VALUES (3, 1, 'update_applied', 0, '');
                 INSERT INTO activity_entries VALUES (4, 1, 'scan_skipped', 0, '');",
            )
            .expect("valid rows");
        [
            "INSERT INTO activity_entries VALUES (9, 1, 'scheduled_scan_clean', 0, '')",
            "INSERT INTO activity_entries VALUES (9, 1, 'scan_clean', -1, '')",
            "INSERT INTO scan_activities VALUES (3, 'update_applied', 'manual_scan')",
            "INSERT INTO scan_activities VALUES (3, 'scan_clean', 'manual_scan')",
            "INSERT INTO scan_activities VALUES (4, 'scan_skipped', 'manual_scan')",
            "INSERT INTO scan_activities VALUES (4, 'scan_skipped', 'usb_scan')",
            "INSERT INTO scan_threat_counts VALUES (1, 'scan_infected', 0)",
            "INSERT INTO scan_threat_counts VALUES (2, 'scan_clean', 4)",
            "INSERT INTO scan_threat_counts VALUES (2, 'scan_infected', 4)",
            "INSERT INTO scan_inspections VALUES (4, 'scan_skipped', 0)",
            "INSERT INTO scan_inspections VALUES (1, 'scan_infected', -1)",
            "INSERT INTO scan_activity_targets VALUES (3, 0, '/home')",
            "INSERT INTO scan_activity_targets VALUES (1, -1, '/home')",
            "INSERT INTO scan_activity_targets VALUES (1, 0, '')",
        ]
        .into_iter()
        .for_each(|invalid_insert| {
            assert!(
                checked_connection.execute(invalid_insert, []).is_err(),
                "accepted: {invalid_insert}"
            );
        });
    }

    #[tokio::test]
    async fn an_infected_scan_without_its_inspection_row_is_unreadable() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("history.db");
        let history = ActivityHistory::at_database_path(database_path.clone());
        history.list_recent_entries().await.expect("created");
        rusqlite::Connection::open(&database_path)
            .expect("database")
            .execute_batch(
                "INSERT INTO activity_entries VALUES (1, 1, 'scan_infected', 0, '');
                 INSERT INTO scan_activities VALUES (1, 'scan_infected', 'manual_scan');",
            )
            .expect("partial rows");
        assert!(matches!(
            history.list_recent_entries().await,
            Err(ActivityHistoryFailure::StoredScanDetailsInconsistent)
        ));
    }
}
