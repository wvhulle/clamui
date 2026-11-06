use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf};

use turso::{Connection, Row, Value};

use crate::host_services::{
    activity_history::activity_history_database::{ActivityHistory, ActivityHistoryFailure},
    detection_journal::detection_journal_records::{DetectionSource, JournalDetectionRecord},
};

const REOPEN_GRACE_SECONDS: i64 = 10;
const DETECTION_COLUMNS: &str = "detection_id, file_path, signature_name, found_on_access,
                                 found_by_schedule, first_seen_unix, last_seen_unix,
                                 sighting_count, resolution, resolved_at_unix";
const JOURNAL_POSITION_ROW: i64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionResolution {
    Unresolved,
    MovedToQuarantine,
    DeletedByUser,
    DismissedByUser,
}

impl DetectionResolution {
    const fn stored_text(self) -> &'static str {
        match self {
            Self::Unresolved => "",
            Self::MovedToQuarantine => "quarantined",
            Self::DeletedByUser => "deleted",
            Self::DismissedByUser => "dismissed",
        }
    }

    fn from_stored_text(stored_text: &str) -> Self {
        match stored_text {
            "quarantined" => Self::MovedToQuarantine,
            "deleted" => Self::DeletedByUser,
            "dismissed" => Self::DismissedByUser,
            _unresolved => Self::Unresolved,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDetection {
    pub detection_id: i64,
    pub file_path: PathBuf,
    pub signature_name: String,
    pub found_on_access: bool,
    pub found_by_schedule: bool,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    pub sighting_count: i64,
    pub resolution: DetectionResolution,
    pub resolved_at_unix: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionSighting {
    NewlyOpened,
    RepeatOfOpen,
}

pub fn sighting_reopens_detection(
    resolution: DetectionResolution,
    resolved_at_unix: i64,
    observed_at_unix: i64,
) -> bool {
    resolution != DetectionResolution::Unresolved
        && observed_at_unix > resolved_at_unix + REOPEN_GRACE_SECONDS
}

fn stored_detection_from_row(
    detection_row: &Row,
) -> Result<StoredDetection, ActivityHistoryFailure> {
    let path_bytes: Vec<u8> = detection_row.get(1)?;
    let found_on_access: i64 = detection_row.get(3)?;
    let found_by_schedule: i64 = detection_row.get(4)?;
    let stored_resolution: String = detection_row.get(8)?;
    Ok(StoredDetection {
        detection_id: detection_row.get(0)?,
        file_path: PathBuf::from(OsStr::from_bytes(&path_bytes)),
        signature_name: detection_row.get(2)?,
        found_on_access: found_on_access != 0,
        found_by_schedule: found_by_schedule != 0,
        first_seen_unix: detection_row.get(5)?,
        last_seen_unix: detection_row.get(6)?,
        sighting_count: detection_row.get(7)?,
        resolution: DetectionResolution::from_stored_text(&stored_resolution),
        resolved_at_unix: detection_row.get(9)?,
    })
}

async fn find_matching_detection(
    database_connection: &Connection,
    detection_record: &JournalDetectionRecord,
) -> Result<Option<StoredDetection>, ActivityHistoryFailure> {
    let mut matching_rows = database_connection
        .query(
            &format!(
                "SELECT {DETECTION_COLUMNS} FROM background_detections WHERE file_path = ?1 AND \
                 signature_name = ?2"
            ),
            vec![
                Value::Blob(detection_record.file_path.as_os_str().as_bytes().to_vec()),
                Value::Text(detection_record.signature_name.clone()),
            ],
        )
        .await?;
    match matching_rows.next().await? {
        Some(matching_row) => Ok(Some(stored_detection_from_row(&matching_row)?)),
        None => Ok(None),
    }
}

async fn apply_detection_record(
    database_connection: &Connection,
    detection_record: &JournalDetectionRecord,
) -> Result<DetectionSighting, ActivityHistoryFailure> {
    let seen_on_access =
        i64::from(detection_record.detection_source == DetectionSource::OnAccessScanner);
    let seen_by_schedule =
        i64::from(detection_record.detection_source == DetectionSource::ScheduledScan);
    let Some(existing_detection) =
        find_matching_detection(database_connection, detection_record).await?
    else {
        database_connection
            .execute(
                "INSERT INTO background_detections (file_path, signature_name, found_on_access, \
                 found_by_schedule, first_seen_unix, last_seen_unix, sighting_count, resolution, \
                 resolved_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', 0)",
                vec![
                    Value::Blob(detection_record.file_path.as_os_str().as_bytes().to_vec()),
                    Value::Text(detection_record.signature_name.clone()),
                    Value::Integer(seen_on_access),
                    Value::Integer(seen_by_schedule),
                    Value::Integer(detection_record.observed_at_unix),
                ],
            )
            .await?;
        return Ok(DetectionSighting::NewlyOpened);
    };
    let reopened = sighting_reopens_detection(
        existing_detection.resolution,
        existing_detection.resolved_at_unix,
        detection_record.observed_at_unix,
    );
    let (kept_resolution, kept_resolved_at) = if reopened {
        (DetectionResolution::Unresolved, 0)
    } else {
        (
            existing_detection.resolution,
            existing_detection.resolved_at_unix,
        )
    };
    database_connection
        .execute(
            "UPDATE background_detections SET found_on_access = MAX(found_on_access, ?1), \
             found_by_schedule = MAX(found_by_schedule, ?2), last_seen_unix = MAX(last_seen_unix, \
             ?3), sighting_count = sighting_count + 1, resolution = ?4, resolved_at_unix = ?5 \
             WHERE detection_id = ?6",
            vec![
                Value::Integer(seen_on_access),
                Value::Integer(seen_by_schedule),
                Value::Integer(detection_record.observed_at_unix),
                Value::Text(kept_resolution.stored_text().to_owned()),
                Value::Integer(kept_resolved_at),
                Value::Integer(existing_detection.detection_id),
            ],
        )
        .await?;
    Ok(if reopened {
        DetectionSighting::NewlyOpened
    } else {
        DetectionSighting::RepeatOfOpen
    })
}

impl ActivityHistory {
    pub async fn record_detection_batch(
        &self,
        detection_records: &[JournalDetectionRecord],
        journal_cursor: &str,
    ) -> Result<Vec<JournalDetectionRecord>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        database_connection.execute("BEGIN IMMEDIATE", ()).await?;
        let mut newly_opened = Vec::new();
        for detection_record in detection_records {
            if apply_detection_record(&database_connection, detection_record).await?
                == DetectionSighting::NewlyOpened
            {
                newly_opened.push(detection_record.clone());
            }
        }
        database_connection
            .execute(
                "INSERT OR REPLACE INTO detection_journal_position (position_row, journal_cursor) \
                 VALUES (?1, ?2)",
                vec![
                    Value::Integer(JOURNAL_POSITION_ROW),
                    Value::Text(journal_cursor.to_owned()),
                ],
            )
            .await?;
        database_connection.execute("COMMIT", ()).await?;
        Ok(newly_opened)
    }

    pub async fn saved_journal_cursor(&self) -> Result<Option<String>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        let mut cursor_rows = database_connection
            .query("SELECT journal_cursor FROM detection_journal_position", ())
            .await?;
        match cursor_rows.next().await? {
            Some(cursor_row) => Ok(Some(cursor_row.get(0)?)),
            None => Ok(None),
        }
    }

    pub async fn list_detections(&self) -> Result<Vec<StoredDetection>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        let mut detection_rows = database_connection
            .query(
                &format!(
                    "SELECT {DETECTION_COLUMNS} FROM background_detections ORDER BY \
                     last_seen_unix DESC, detection_id DESC"
                ),
                (),
            )
            .await?;
        let mut stored_detections = Vec::new();
        while let Some(detection_row) = detection_rows.next().await? {
            stored_detections.push(stored_detection_from_row(&detection_row)?);
        }
        Ok(stored_detections)
    }

    pub async fn resolve_detection(
        &self,
        detection_id: i64,
        resolution: DetectionResolution,
        resolved_at_unix: i64,
    ) -> Result<(), ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        self.open_connection()
            .await?
            .execute(
                "UPDATE background_detections SET resolution = ?1, resolved_at_unix = ?2 WHERE \
                 detection_id = ?3",
                vec![
                    Value::Text(resolution.stored_text().to_owned()),
                    Value::Integer(resolved_at_unix),
                    Value::Integer(detection_id),
                ],
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod detection_history_store_tests {
    use super::*;

    const FIRST_SEEN_UNIX: i64 = 1_793_869_222;

    fn detection_record(observed_at_unix: i64) -> JournalDetectionRecord {
        JournalDetectionRecord {
            observed_at_unix,
            detection_source: DetectionSource::OnAccessScanner,
            file_path: PathBuf::from(OsStr::from_bytes(b"/home/user/Downloads/a\xff.exe")),
            signature_name: "Win.Test-1".to_owned(),
        }
    }

    fn temporary_history() -> (tempfile::TempDir, ActivityHistory) {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let activity_history =
            ActivityHistory::at_database_path(temporary_root.path().join("history.db"));
        (temporary_root, activity_history)
    }

    #[tokio::test]
    async fn repeated_lines_for_one_file_become_one_counted_detection() {
        let (_temporary_root, activity_history) = temporary_history();
        let repeated_records = [
            detection_record(FIRST_SEEN_UNIX),
            detection_record(FIRST_SEEN_UNIX + 1),
            detection_record(FIRST_SEEN_UNIX + 3),
        ];
        let newly_opened = activity_history
            .record_detection_batch(&repeated_records, "cursor-a")
            .await
            .expect("recorded");
        assert_eq!(newly_opened.len(), 1);
        let stored_detections = activity_history.list_detections().await.expect("listed");
        assert_eq!(stored_detections.len(), 1);
        assert_eq!(stored_detections[0].sighting_count, 3);
        assert_eq!(stored_detections[0].first_seen_unix, FIRST_SEEN_UNIX);
        assert_eq!(stored_detections[0].last_seen_unix, FIRST_SEEN_UNIX + 3);
        assert_eq!(
            stored_detections[0].file_path,
            repeated_records[0].file_path
        );
    }

    #[tokio::test]
    async fn the_journal_cursor_is_saved_with_the_batch() {
        let (_temporary_root, activity_history) = temporary_history();
        assert_eq!(
            activity_history.saved_journal_cursor().await.expect("read"),
            None
        );
        activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN_UNIX)], "cursor-a")
            .await
            .expect("recorded");
        activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN_UNIX + 1)], "cursor-b")
            .await
            .expect("recorded");
        assert_eq!(
            activity_history.saved_journal_cursor().await.expect("read"),
            Some("cursor-b".to_owned())
        );
    }

    #[tokio::test]
    async fn only_a_later_sighting_reopens_a_resolved_detection() {
        let (_temporary_root, activity_history) = temporary_history();
        activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN_UNIX)], "cursor-a")
            .await
            .expect("recorded");
        let detection_id =
            activity_history.list_detections().await.expect("listed")[0].detection_id;
        activity_history
            .resolve_detection(
                detection_id,
                DetectionResolution::MovedToQuarantine,
                FIRST_SEEN_UNIX + 5,
            )
            .await
            .expect("resolved");
        let trailing_sighting = activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN_UNIX + 6)], "cursor-b")
            .await
            .expect("recorded");
        assert!(trailing_sighting.is_empty());
        assert_eq!(
            activity_history.list_detections().await.expect("listed")[0].resolution,
            DetectionResolution::MovedToQuarantine
        );
        let later_download = activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN_UNIX + 600)], "cursor-c")
            .await
            .expect("recorded");
        assert_eq!(later_download.len(), 1);
        assert_eq!(
            activity_history.list_detections().await.expect("listed")[0].resolution,
            DetectionResolution::Unresolved
        );
    }
}
