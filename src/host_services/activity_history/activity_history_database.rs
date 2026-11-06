use std::{path::PathBuf, time::Duration};

use jiff::Timestamp;
use tokio::task::spawn_blocking;
use turso::{Builder, Connection, Row, Value};

use crate::host_services::{
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
    #[error("the history database path is not valid UTF-8")]
    DatabasePathNotUtf8,
    #[error("a stored history entry has an unknown status")]
    StoredStatusUnknown,
    #[error("a stored history entry has an impossible time: {0}")]
    StoredTimeInvalid(#[from] jiff::Error),
    #[error("the history lock is unavailable: {0}")]
    HistoryLockUnavailable(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStatus {
    ScanClean,
    ScanInfected,
    ScanFailed,
    ScanCancelled,
    ScanSkipped,
    UpdateApplied,
    UpdateAlreadyCurrent,
    UpdateRequested,
    UpdateResultUnknown,
    UpdateFailed,
    UpdateCancelled,
}

impl ActivityStatus {
    const fn stored_text(self) -> &'static str {
        match self {
            Self::ScanClean => "scan_clean",
            Self::ScanInfected => "scan_infected",
            Self::ScanFailed => "scan_failed",
            Self::ScanCancelled => "scan_cancelled",
            Self::ScanSkipped => "scan_skipped",
            Self::UpdateApplied => "update_applied",
            Self::UpdateAlreadyCurrent => "update_already_current",
            Self::UpdateRequested => "update_requested",
            Self::UpdateResultUnknown => "update_result_unknown",
            Self::UpdateFailed => "update_failed",
            Self::UpdateCancelled => "update_cancelled",
        }
    }

    fn from_stored_text(stored_text: &str) -> Result<Self, ActivityHistoryFailure> {
        match stored_text {
            "scan_clean" => Ok(Self::ScanClean),
            "scan_infected" => Ok(Self::ScanInfected),
            "scan_failed" => Ok(Self::ScanFailed),
            "scan_cancelled" => Ok(Self::ScanCancelled),
            "scan_skipped" => Ok(Self::ScanSkipped),
            "update_applied" => Ok(Self::UpdateApplied),
            "update_already_current" => Ok(Self::UpdateAlreadyCurrent),
            "update_requested" => Ok(Self::UpdateRequested),
            "update_result_unknown" => Ok(Self::UpdateResultUnknown),
            "update_failed" => Ok(Self::UpdateFailed),
            "update_cancelled" => Ok(Self::UpdateCancelled),
            _unknown_status => Err(ActivityHistoryFailure::StoredStatusUnknown),
        }
    }

    pub const fn is_virus_scan(self) -> bool {
        matches!(
            self,
            Self::ScanClean | Self::ScanInfected | Self::ScanFailed | Self::ScanCancelled
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewActivityEntry {
    pub started_at: Timestamp,
    pub activity_status: ActivityStatus,
    pub activity_targets: String,
    pub inspected_file_count: u64,
    pub threat_count: u64,
    pub duration_millis: u64,
    pub activity_output: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ActivityEntryRecord {
    pub entry_id: i64,
    pub started_at: Timestamp,
    pub activity_status: ActivityStatus,
    pub activity_targets: String,
    pub inspected_file_count: u64,
    pub threat_count: u64,
    pub duration_millis: u64,
    pub activity_output: String,
}

fn activity_entry_from_row(entry_row: &Row) -> Result<ActivityEntryRecord, ActivityHistoryFailure> {
    let stored_status: String = entry_row.get(2)?;
    let inspected_file_count: i64 = entry_row.get(4)?;
    let threat_count: i64 = entry_row.get(5)?;
    let duration_millis: i64 = entry_row.get(6)?;
    Ok(ActivityEntryRecord {
        entry_id: entry_row.get(0)?,
        started_at: Timestamp::from_second(entry_row.get(1)?)?,
        activity_status: ActivityStatus::from_stored_text(&stored_status)?,
        activity_targets: entry_row.get(3)?,
        inspected_file_count: inspected_file_count.max(0) as u64,
        threat_count: threat_count.max(0) as u64,
        duration_millis: duration_millis.max(0) as u64,
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
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        database_connection
            .execute(
                "INSERT INTO activity_entries (started_at_unix, activity_status, \
                 activity_targets, inspected_file_count, threat_count, duration_millis, \
                 activity_output) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vec![
                    Value::Integer(new_entry.started_at.as_second()),
                    Value::Text(new_entry.activity_status.stored_text().to_owned()),
                    Value::Text(new_entry.activity_targets),
                    Value::Integer(new_entry.inspected_file_count as i64),
                    Value::Integer(new_entry.threat_count as i64),
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
            activity_status: ActivityStatus::ScanInfected,
            activity_targets: "/scan/target\n/scan/other".to_owned(),
            inspected_file_count: 12,
            threat_count: 2,
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
            listed_entries[0].activity_status,
            ActivityStatus::ScanInfected
        );
        assert_eq!(listed_entries[0].inspected_file_count, 12);
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
}
