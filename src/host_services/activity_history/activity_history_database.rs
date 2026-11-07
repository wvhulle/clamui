use std::{num::NonZeroU64, path::PathBuf, time::Duration};

use jiff::Timestamp;
use tokio::task::spawn_blocking;
use turso::{Builder, Connection, Row, Value};

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
const HISTORY_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS activity_entries (
        entry_id INTEGER PRIMARY KEY,
        started_at_unix INTEGER NOT NULL,
        activity_status TEXT NOT NULL,
        activity_targets TEXT NOT NULL,
        inspected_file_count INTEGER NOT NULL,
        threat_count INTEGER NOT NULL,
        duration_millis INTEGER NOT NULL,
        activity_output TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS background_detections (
        detection_id INTEGER PRIMARY KEY,
        file_path BLOB NOT NULL,
        signature_name TEXT NOT NULL,
        found_on_access INTEGER NOT NULL,
        found_by_schedule INTEGER NOT NULL,
        first_seen_unix INTEGER NOT NULL,
        last_seen_unix INTEGER NOT NULL,
        sighting_count INTEGER NOT NULL,
        resolution TEXT NOT NULL,
        resolved_at_unix INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS detection_journal_position (
        position_row INTEGER PRIMARY KEY,
        journal_cursor TEXT NOT NULL
    );
";
const ENTRY_COLUMNS: &str = "entry_id, started_at_unix, activity_status, activity_targets, \
                             inspected_file_count, threat_count, duration_millis, activity_output";

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

    const fn stored_count(self) -> u64 {
        match self {
            Self::CountedThreats { threat_count } => threat_count.get(),
            Self::UncountedThreats => 0,
        }
    }

    fn from_stored_count(stored_count: u64) -> Self {
        NonZeroU64::new(stored_count).map_or(Self::UncountedThreats, |threat_count| {
            Self::CountedThreats { threat_count }
        })
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

fn stored_scan_targets(scan_targets: &[PathBuf]) -> String {
    scan_targets
        .iter()
        .map(|scan_target| sanitize_scanner_line(&scan_target.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(&SCAN_TARGET_SEPARATOR.to_string())
}

fn scan_targets_from_stored_text(stored_targets: &str) -> Vec<PathBuf> {
    stored_targets
        .split(SCAN_TARGET_SEPARATOR)
        .filter(|stored_target| !stored_target.is_empty())
        .map(PathBuf::from)
        .collect()
}

pub struct StoredActivityColumns {
    pub activity_status: &'static str,
    pub activity_targets: String,
    pub inspected_file_count: u64,
    pub threat_count: u64,
}

impl ActivityRecord {
    pub const fn stored_status_text(&self) -> &'static str {
        match self {
            Self::ScanActivity {
                scan_status,
                scan_origin: ScanOrigin::ManualScan,
                ..
            } => match scan_status {
                ScanActivityStatus::ScanClean => "scan_clean",
                ScanActivityStatus::ScanInfected { .. } => "scan_infected",
                ScanActivityStatus::ScanFailed => "scan_failed",
                ScanActivityStatus::ScanCancelled => "scan_cancelled",
            },
            Self::ScanActivity {
                scan_status,
                scan_origin: ScanOrigin::ScheduledScan,
                ..
            } => match scan_status {
                ScanActivityStatus::ScanClean => "scheduled_scan_clean",
                ScanActivityStatus::ScanInfected { .. } => "scheduled_scan_infected",
                ScanActivityStatus::ScanFailed => "scheduled_scan_failed",
                ScanActivityStatus::ScanCancelled => "scheduled_scan_cancelled",
            },
            Self::SkippedScan { .. } => "scan_skipped",
            Self::UpdateActivity { update_status } => match update_status {
                UpdateActivityStatus::UpdateApplied => "update_applied",
                UpdateActivityStatus::UpdateAlreadyCurrent => "update_already_current",
                UpdateActivityStatus::UpdateRequested => "update_requested",
                UpdateActivityStatus::UpdateResultUnknown => "update_result_unknown",
                UpdateActivityStatus::UpdateFailed => "update_failed",
                UpdateActivityStatus::UpdateCancelled => "update_cancelled",
            },
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

    const fn stored_inspected_file_count(&self) -> u64 {
        match self {
            Self::ScanActivity {
                inspected_file_count,
                ..
            } => *inspected_file_count,
            Self::SkippedScan { .. } | Self::UpdateActivity { .. } => 0,
        }
    }

    const fn stored_threat_count(&self) -> u64 {
        match self {
            Self::ScanActivity {
                scan_status: ScanActivityStatus::ScanInfected { found_threats },
                ..
            } => found_threats.stored_count(),
            Self::ScanActivity { .. } | Self::SkippedScan { .. } | Self::UpdateActivity { .. } => 0,
        }
    }

    pub fn stored_columns(&self) -> StoredActivityColumns {
        StoredActivityColumns {
            activity_status: self.stored_status_text(),
            activity_targets: stored_scan_targets(self.scan_targets()),
            inspected_file_count: self.stored_inspected_file_count(),
            threat_count: self.stored_threat_count(),
        }
    }

    fn from_stored_columns(
        stored_status: &str,
        stored_targets: &str,
        inspected_file_count: u64,
        threat_count: u64,
    ) -> Result<Self, ActivityHistoryFailure> {
        let scan_activity = |scan_status, scan_origin| Self::ScanActivity {
            scan_targets: scan_targets_from_stored_text(stored_targets),
            inspected_file_count,
            scan_status,
            scan_origin,
        };
        let infected_status = ScanActivityStatus::ScanInfected {
            found_threats: FoundThreatCount::from_stored_count(threat_count),
        };
        let update_activity = |update_status| Self::UpdateActivity { update_status };
        Ok(match stored_status {
            "scan_clean" => scan_activity(ScanActivityStatus::ScanClean, ScanOrigin::ManualScan),
            "scan_infected" => scan_activity(infected_status, ScanOrigin::ManualScan),
            "scan_failed" => scan_activity(ScanActivityStatus::ScanFailed, ScanOrigin::ManualScan),
            "scan_cancelled" => {
                scan_activity(ScanActivityStatus::ScanCancelled, ScanOrigin::ManualScan)
            }
            "scheduled_scan_clean" => {
                scan_activity(ScanActivityStatus::ScanClean, ScanOrigin::ScheduledScan)
            }
            "scheduled_scan_infected" => scan_activity(infected_status, ScanOrigin::ScheduledScan),
            "scheduled_scan_failed" => {
                scan_activity(ScanActivityStatus::ScanFailed, ScanOrigin::ScheduledScan)
            }
            "scheduled_scan_cancelled" => {
                scan_activity(ScanActivityStatus::ScanCancelled, ScanOrigin::ScheduledScan)
            }
            "scan_skipped" => Self::SkippedScan {
                scan_targets: scan_targets_from_stored_text(stored_targets),
            },
            "update_applied" => update_activity(UpdateActivityStatus::UpdateApplied),
            "update_already_current" => update_activity(UpdateActivityStatus::UpdateAlreadyCurrent),
            "update_requested" => update_activity(UpdateActivityStatus::UpdateRequested),
            "update_result_unknown" => update_activity(UpdateActivityStatus::UpdateResultUnknown),
            "update_failed" => update_activity(UpdateActivityStatus::UpdateFailed),
            "update_cancelled" => update_activity(UpdateActivityStatus::UpdateCancelled),
            _unknown_status => return Err(ActivityHistoryFailure::StoredStatusUnknown),
        })
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

fn stored_count(stored_value: i64) -> u64 {
    u64::try_from(stored_value).unwrap_or(0)
}

fn activity_entry_from_row(entry_row: &Row) -> Result<ActivityEntryRecord, ActivityHistoryFailure> {
    let stored_status: String = entry_row.get(2)?;
    let stored_targets: String = entry_row.get(3)?;
    let inspected_file_count: i64 = entry_row.get(4)?;
    let threat_count: i64 = entry_row.get(5)?;
    let duration_millis: i64 = entry_row.get(6)?;
    Ok(ActivityEntryRecord {
        entry_id: entry_row.get(0)?,
        started_at: Timestamp::from_second(entry_row.get(1)?)?,
        activity_record: ActivityRecord::from_stored_columns(
            &stored_status,
            &stored_targets,
            stored_count(inspected_file_count),
            stored_count(threat_count),
        )?,
        duration_millis: stored_count(duration_millis),
        activity_output: entry_row.get(7)?,
    })
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
        database_connection.execute_batch(HISTORY_SCHEMA).await?;
        secure_database_files(&self.database_path);
        Ok(database_connection)
    }

    pub async fn record_activity(
        &self,
        new_entry: NewActivityEntry,
    ) -> Result<(), ActivityHistoryFailure> {
        let StoredActivityColumns {
            activity_status,
            activity_targets,
            inspected_file_count,
            threat_count,
        } = new_entry.activity_record.stored_columns();
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        database_connection
            .execute(
                "INSERT INTO activity_entries (started_at_unix, activity_status, \
                 activity_targets, inspected_file_count, threat_count, duration_millis, \
                 activity_output) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vec![
                    Value::Integer(new_entry.started_at.as_second()),
                    Value::Text(activity_status.to_owned()),
                    Value::Text(activity_targets),
                    Value::Integer(inspected_file_count as i64),
                    Value::Integer(threat_count as i64),
                    Value::Integer(new_entry.duration_millis as i64),
                    Value::Text(new_entry.activity_output),
                ],
            )
            .await?;
        database_connection
            .execute(
                "UPDATE activity_entries SET activity_output = '' WHERE entry_id <= (SELECT \
                 MAX(entry_id) FROM activity_entries) - ?1",
                [ENTRIES_KEEPING_OUTPUT],
            )
            .await?;
        database_connection
            .execute(
                "DELETE FROM activity_entries WHERE entry_id <= (SELECT MAX(entry_id) FROM \
                 activity_entries) - ?1",
                [MAXIMUM_RETAINED_ENTRIES],
            )
            .await?;
        Ok(())
    }

    pub async fn list_recent_entries(
        &self,
    ) -> Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        let mut entry_rows = database_connection
            .query(
                &format!(
                    "SELECT {ENTRY_COLUMNS} FROM activity_entries ORDER BY started_at_unix DESC, \
                     entry_id DESC"
                ),
                (),
            )
            .await?;
        let mut recent_entries = Vec::new();
        while let Some(entry_row) = entry_rows.next().await? {
            recent_entries.push(activity_entry_from_row(&entry_row)?);
        }
        Ok(recent_entries)
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
                 activity_targets, inspected_file_count, threat_count, duration_millis, \
                 activity_output) VALUES (1, 1, 'scan_clean', '', 0, 0, 0, 'stale output')",
                (),
            )
            .await
            .expect("old entry");
        connection
            .execute(
                "INSERT INTO activity_entries (entry_id, started_at_unix, activity_status, \
                 activity_targets, inspected_file_count, threat_count, duration_millis, \
                 activity_output) VALUES (500, 2, 'scan_clean', '', 0, 0, 0, 'fresh')",
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

    #[test]
    fn rows_stored_before_origins_were_recorded_read_as_manual_scans() {
        [
            "scan_clean",
            "scan_infected",
            "scan_failed",
            "scan_cancelled",
        ]
        .into_iter()
        .for_each(|stored_status| {
            assert!(matches!(
                ActivityRecord::from_stored_columns(stored_status, "/tmp", 1, 0),
                Ok(ActivityRecord::ScanActivity {
                    scan_origin: ScanOrigin::ManualScan,
                    ..
                })
            ));
        });
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

    #[test]
    fn old_comma_joined_targets_read_as_one_target() {
        assert_eq!(
            scan_targets_from_stored_text("/scan/one, /scan/two"),
            vec![PathBuf::from("/scan/one, /scan/two")]
        );
        assert_eq!(scan_targets_from_stored_text(""), Vec::<PathBuf>::new());
    }

    #[test]
    fn line_breaks_inside_a_target_cannot_split_it() {
        assert_eq!(
            scan_targets_from_stored_text(&stored_scan_targets(&[PathBuf::from(
                "/scan/odd\nname"
            )])),
            vec![PathBuf::from("/scan/odd name")]
        );
    }
}
