use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf};

use jiff::{SignedDuration, Timestamp};
use turso::{Connection, Row, transaction::TransactionBehavior};

use crate::host_services::{
    activity_history::activity_history_database::{ActivityHistory, ActivityHistoryFailure},
    detection_journal::detection_journal_records::{DetectionSource, JournalDetectionRecord},
};

const REOPEN_GRACE: SignedDuration = SignedDuration::from_secs(10);
const DETECTION_QUERY: &str = "
    SELECT background_detections.detection_id, background_detections.file_path,
        background_detections.signature_name, background_detections.detection_sources,
        background_detections.first_seen_unix, background_detections.last_seen_unix,
        background_detections.sighting_count, detection_resolutions.resolution_kind,
        detection_resolutions.resolved_at_unix
    FROM background_detections
    LEFT JOIN detection_resolutions
        ON detection_resolutions.file_path = background_detections.file_path
        AND detection_resolutions.signature_name = background_detections.signature_name";
const DETECTION_KEY_FILTER: &str = "file_path = ?1 AND signature_name = ?2";
const JOURNAL_POSITION_ROW: i64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionKind {
    MovedToQuarantine,
    DeletedByUser,
    DismissedByUser,
}

const ALL_RESOLUTION_KINDS: [ResolutionKind; 3] = [
    ResolutionKind::MovedToQuarantine,
    ResolutionKind::DeletedByUser,
    ResolutionKind::DismissedByUser,
];

impl ResolutionKind {
    const fn stored_text(self) -> &'static str {
        match self {
            Self::MovedToQuarantine => "quarantined",
            Self::DeletedByUser => "deleted",
            Self::DismissedByUser => "dismissed",
        }
    }

    fn from_stored_text(stored_text: &str) -> Result<Self, ActivityHistoryFailure> {
        ALL_RESOLUTION_KINDS
            .into_iter()
            .find(|resolution_kind| resolution_kind.stored_text() == stored_text)
            .ok_or(ActivityHistoryFailure::StoredDetectionUnreadable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectionState {
    Open,
    Resolved {
        resolution_kind: ResolutionKind,
        resolved_at: Timestamp,
    },
}

impl DetectionState {
    fn from_resolution_row(detection_row: &Row) -> Result<Self, ActivityHistoryFailure> {
        let resolution_kind: Option<String> = detection_row.get(7)?;
        let resolved_at_unix: Option<i64> = detection_row.get(8)?;
        match (resolution_kind, resolved_at_unix) {
            (None, None) => Ok(Self::Open),
            (Some(kind_text), Some(resolved_at_unix)) => Ok(Self::Resolved {
                resolution_kind: ResolutionKind::from_stored_text(&kind_text)?,
                resolved_at: Timestamp::from_second(resolved_at_unix)?,
            }),
            (Some(_), None) | (None, Some(_)) => {
                Err(ActivityHistoryFailure::StoredDetectionUnreadable)
            }
        }
    }

    pub const fn awaits_user_decision(&self) -> bool {
        match self {
            Self::Open => true,
            Self::Resolved { .. } => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionSources {
    OnAccessOnly,
    ScheduleOnly,
    OnAccessAndSchedule,
}

const ALL_DETECTION_SOURCES: [DetectionSources; 3] = [
    DetectionSources::OnAccessOnly,
    DetectionSources::ScheduleOnly,
    DetectionSources::OnAccessAndSchedule,
];

impl DetectionSources {
    const fn stored_text(self) -> &'static str {
        match self {
            Self::OnAccessOnly => "on_access",
            Self::ScheduleOnly => "scheduled_scan",
            Self::OnAccessAndSchedule => "on_access_and_scheduled_scan",
        }
    }

    fn from_stored_text(stored_text: &str) -> Result<Self, ActivityHistoryFailure> {
        ALL_DETECTION_SOURCES
            .into_iter()
            .find(|detection_sources| detection_sources.stored_text() == stored_text)
            .ok_or(ActivityHistoryFailure::StoredDetectionUnreadable)
    }

    pub const fn from_single_source(detection_source: DetectionSource) -> Self {
        match detection_source {
            DetectionSource::OnAccessScanner => Self::OnAccessOnly,
            DetectionSource::ScheduledScan => Self::ScheduleOnly,
        }
    }

    pub const fn including_source(self, detection_source: DetectionSource) -> Self {
        match (self, detection_source) {
            (
                Self::OnAccessAndSchedule,
                DetectionSource::OnAccessScanner | DetectionSource::ScheduledScan,
            )
            | (Self::OnAccessOnly, DetectionSource::ScheduledScan)
            | (Self::ScheduleOnly, DetectionSource::OnAccessScanner) => Self::OnAccessAndSchedule,
            (Self::OnAccessOnly, DetectionSource::OnAccessScanner) => Self::OnAccessOnly,
            (Self::ScheduleOnly, DetectionSource::ScheduledScan) => Self::ScheduleOnly,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDetection {
    pub detection_id: i64,
    pub file_path: PathBuf,
    pub signature_name: String,
    pub detection_sources: DetectionSources,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub sighting_count: i64,
    pub detection_state: DetectionState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionSighting {
    NewlyOpened,
    RepeatOfOpen,
}

pub fn sighting_reopens_detection(
    detection_state: &DetectionState,
    observed_at: Timestamp,
) -> bool {
    match detection_state {
        DetectionState::Open => false,
        DetectionState::Resolved { resolved_at, .. } => observed_at > *resolved_at + REOPEN_GRACE,
    }
}

fn stored_detection_from_row(
    detection_row: &Row,
) -> Result<StoredDetection, ActivityHistoryFailure> {
    let path_bytes: Vec<u8> = detection_row.get(1)?;
    Ok(StoredDetection {
        detection_id: detection_row.get(0)?,
        file_path: PathBuf::from(OsStr::from_bytes(&path_bytes)),
        signature_name: detection_row.get(2)?,
        detection_sources: DetectionSources::from_stored_text(&detection_row.get::<String>(3)?)?,
        first_seen: Timestamp::from_second(detection_row.get(4)?)?,
        last_seen: Timestamp::from_second(detection_row.get(5)?)?,
        sighting_count: detection_row.get(6)?,
        detection_state: DetectionState::from_resolution_row(detection_row)?,
    })
}

fn detection_key(detection_record: &JournalDetectionRecord) -> (Vec<u8>, String) {
    (
        detection_record.file_path.as_os_str().as_bytes().to_vec(),
        detection_record.signature_name.clone(),
    )
}

async fn find_matching_detection(
    database_connection: &Connection,
    detection_record: &JournalDetectionRecord,
) -> Result<Option<StoredDetection>, ActivityHistoryFailure> {
    let mut matching_rows = database_connection
        .query(
            format!(
                "{DETECTION_QUERY} WHERE background_detections.file_path = ?1 AND \
                 background_detections.signature_name = ?2"
            ),
            detection_key(detection_record),
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
    let (file_path, signature_name) = detection_key(detection_record);
    let observed_at_unix = detection_record.observed_at.as_second();
    let Some(existing_detection) =
        find_matching_detection(database_connection, detection_record).await?
    else {
        database_connection
            .execute(
                "INSERT INTO background_detections (file_path, signature_name, detection_id, \
                 detection_sources, first_seen_unix, last_seen_unix, sighting_count) SELECT ?1, \
                 ?2, COALESCE(MAX(detection_id), 0) + 1, ?3, ?4, ?4, 1 FROM background_detections",
                (
                    file_path,
                    signature_name,
                    DetectionSources::from_single_source(detection_record.detection_source)
                        .stored_text(),
                    observed_at_unix,
                ),
            )
            .await?;
        return Ok(DetectionSighting::NewlyOpened);
    };
    database_connection
        .execute(
            format!(
                "UPDATE background_detections SET detection_sources = ?3, last_seen_unix = \
                 MAX(last_seen_unix, ?4), sighting_count = sighting_count + 1 WHERE \
                 {DETECTION_KEY_FILTER}"
            ),
            (
                file_path.clone(),
                signature_name.clone(),
                existing_detection
                    .detection_sources
                    .including_source(detection_record.detection_source)
                    .stored_text(),
                observed_at_unix,
            ),
        )
        .await?;
    if !sighting_reopens_detection(
        &existing_detection.detection_state,
        detection_record.observed_at,
    ) {
        return Ok(DetectionSighting::RepeatOfOpen);
    }
    database_connection
        .execute(
            format!("DELETE FROM detection_resolutions WHERE {DETECTION_KEY_FILTER}"),
            (file_path, signature_name),
        )
        .await?;
    Ok(DetectionSighting::NewlyOpened)
}

impl ActivityHistory {
    pub async fn record_detection_batch(
        &self,
        detection_records: &[JournalDetectionRecord],
        journal_cursor: &str,
    ) -> Result<Vec<JournalDetectionRecord>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let mut database_connection = self.open_connection().await?;
        let batch_transaction = database_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let mut newly_opened = Vec::new();
        for detection_record in detection_records {
            if apply_detection_record(&batch_transaction, detection_record).await?
                == DetectionSighting::NewlyOpened
            {
                newly_opened.push(detection_record.clone());
            }
        }
        batch_transaction
            .execute(
                "INSERT OR REPLACE INTO detection_journal_position (position_row, journal_cursor) \
                 VALUES (?1, ?2)",
                (JOURNAL_POSITION_ROW, journal_cursor),
            )
            .await?;
        batch_transaction.commit().await?;
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
                format!(
                    "{DETECTION_QUERY} ORDER BY background_detections.last_seen_unix DESC, \
                     background_detections.detection_id DESC"
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
        resolution_kind: ResolutionKind,
        resolved_at: Timestamp,
    ) -> Result<(), ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        self.open_connection()
            .await?
            .execute(
                "INSERT OR REPLACE INTO detection_resolutions (file_path, signature_name, \
                 resolution_kind, resolved_at_unix) SELECT file_path, signature_name, ?2, ?3 FROM \
                 background_detections WHERE detection_id = ?1",
                (
                    detection_id,
                    resolution_kind.stored_text(),
                    resolved_at.as_second(),
                ),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod detection_history_store_tests {
    use super::*;

    const FIRST_SEEN: Timestamp = Timestamp::constant(1_793_869_222, 0);

    fn detection_record(observed_at: Timestamp) -> JournalDetectionRecord {
        JournalDetectionRecord {
            observed_at,
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
            detection_record(FIRST_SEEN),
            detection_record(FIRST_SEEN + SignedDuration::from_secs(1)),
            detection_record(FIRST_SEEN + SignedDuration::from_secs(3)),
        ];
        let newly_opened = activity_history
            .record_detection_batch(&repeated_records, "cursor-a")
            .await
            .expect("recorded");
        assert_eq!(newly_opened.len(), 1);
        let stored_detections = activity_history.list_detections().await.expect("listed");
        assert_eq!(stored_detections.len(), 1);
        assert_eq!(stored_detections[0].sighting_count, 3);
        assert_eq!(stored_detections[0].first_seen, FIRST_SEEN);
        assert_eq!(
            stored_detections[0].last_seen,
            FIRST_SEEN + SignedDuration::from_secs(3)
        );
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
            .record_detection_batch(&[detection_record(FIRST_SEEN)], "cursor-a")
            .await
            .expect("recorded");
        activity_history
            .record_detection_batch(
                &[detection_record(FIRST_SEEN + SignedDuration::from_secs(1))],
                "cursor-b",
            )
            .await
            .expect("recorded");
        assert_eq!(
            activity_history.saved_journal_cursor().await.expect("read"),
            Some("cursor-b".to_owned())
        );
    }

    async fn only_detection_state(activity_history: &ActivityHistory) -> DetectionState {
        activity_history.list_detections().await.expect("listed")[0]
            .detection_state
            .clone()
    }

    #[tokio::test]
    async fn every_resolution_kind_is_stored_with_its_resolution_time() {
        for resolution_kind in [
            ResolutionKind::MovedToQuarantine,
            ResolutionKind::DeletedByUser,
            ResolutionKind::DismissedByUser,
        ] {
            let (_temporary_root, activity_history) = temporary_history();
            activity_history
                .record_detection_batch(&[detection_record(FIRST_SEEN)], "cursor-a")
                .await
                .expect("recorded");
            assert_eq!(
                only_detection_state(&activity_history).await,
                DetectionState::Open
            );
            let detection_id =
                activity_history.list_detections().await.expect("listed")[0].detection_id;
            let resolved_at = FIRST_SEEN + SignedDuration::from_secs(5);
            activity_history
                .resolve_detection(detection_id, resolution_kind, resolved_at)
                .await
                .expect("resolved");
            assert_eq!(
                only_detection_state(&activity_history).await,
                DetectionState::Resolved {
                    resolution_kind,
                    resolved_at,
                }
            );
        }
    }

    #[tokio::test]
    async fn only_a_later_sighting_reopens_a_resolved_detection() {
        let (_temporary_root, activity_history) = temporary_history();
        activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN)], "cursor-a")
            .await
            .expect("recorded");
        let detection_id =
            activity_history.list_detections().await.expect("listed")[0].detection_id;
        let resolved_at = FIRST_SEEN + SignedDuration::from_secs(5);
        activity_history
            .resolve_detection(detection_id, ResolutionKind::MovedToQuarantine, resolved_at)
            .await
            .expect("resolved");
        let trailing_sighting = activity_history
            .record_detection_batch(
                &[detection_record(FIRST_SEEN + SignedDuration::from_secs(6))],
                "cursor-b",
            )
            .await
            .expect("recorded");
        assert!(trailing_sighting.is_empty());
        assert_eq!(
            only_detection_state(&activity_history).await,
            DetectionState::Resolved {
                resolution_kind: ResolutionKind::MovedToQuarantine,
                resolved_at,
            }
        );
        let later_download = activity_history
            .record_detection_batch(
                &[detection_record(
                    FIRST_SEEN + SignedDuration::from_secs(600),
                )],
                "cursor-c",
            )
            .await
            .expect("recorded");
        assert_eq!(later_download.len(), 1);
        assert_eq!(
            only_detection_state(&activity_history).await,
            DetectionState::Open
        );
    }

    #[test]
    fn the_grace_period_decides_whether_a_sighting_reopens() {
        let resolved_state = DetectionState::Resolved {
            resolution_kind: ResolutionKind::DismissedByUser,
            resolved_at: FIRST_SEEN,
        };
        assert!(!sighting_reopens_detection(
            &resolved_state,
            FIRST_SEEN + REOPEN_GRACE
        ));
        assert!(sighting_reopens_detection(
            &resolved_state,
            FIRST_SEEN + REOPEN_GRACE + SignedDuration::from_secs(1)
        ));
        assert!(!sighting_reopens_detection(
            &DetectionState::Open,
            FIRST_SEEN + SignedDuration::from_secs(600)
        ));
    }

    struct SourceMergeCase {
        existing_sources: DetectionSources,
        new_source: DetectionSource,
        merged_sources: DetectionSources,
    }

    #[test]
    fn merging_sources_keeps_every_scanner_that_saw_the_file() {
        let merge_cases = [
            SourceMergeCase {
                existing_sources: DetectionSources::OnAccessOnly,
                new_source: DetectionSource::OnAccessScanner,
                merged_sources: DetectionSources::OnAccessOnly,
            },
            SourceMergeCase {
                existing_sources: DetectionSources::OnAccessOnly,
                new_source: DetectionSource::ScheduledScan,
                merged_sources: DetectionSources::OnAccessAndSchedule,
            },
            SourceMergeCase {
                existing_sources: DetectionSources::ScheduleOnly,
                new_source: DetectionSource::ScheduledScan,
                merged_sources: DetectionSources::ScheduleOnly,
            },
            SourceMergeCase {
                existing_sources: DetectionSources::ScheduleOnly,
                new_source: DetectionSource::OnAccessScanner,
                merged_sources: DetectionSources::OnAccessAndSchedule,
            },
            SourceMergeCase {
                existing_sources: DetectionSources::OnAccessAndSchedule,
                new_source: DetectionSource::ScheduledScan,
                merged_sources: DetectionSources::OnAccessAndSchedule,
            },
        ];
        merge_cases.into_iter().for_each(|merge_case| {
            assert_eq!(
                merge_case
                    .existing_sources
                    .including_source(merge_case.new_source),
                merge_case.merged_sources
            );
        });
    }

    #[tokio::test]
    async fn sightings_from_both_scanners_are_merged_in_storage() {
        let (_temporary_root, activity_history) = temporary_history();
        let scheduled_record = JournalDetectionRecord {
            detection_source: DetectionSource::ScheduledScan,
            ..detection_record(FIRST_SEEN + SignedDuration::from_secs(1))
        };
        activity_history
            .record_detection_batch(
                &[detection_record(FIRST_SEEN), scheduled_record],
                "cursor-a",
            )
            .await
            .expect("recorded");
        assert_eq!(
            activity_history.list_detections().await.expect("listed")[0].detection_sources,
            DetectionSources::OnAccessAndSchedule
        );
    }

    fn raw_count(activity_history_root: &tempfile::TempDir, count_query: &str) -> i64 {
        rusqlite::Connection::open(activity_history_root.path().join("history.db"))
            .expect("database")
            .query_row(count_query, [], |count_row| count_row.get(0))
            .expect("count")
    }

    #[tokio::test]
    async fn an_open_detection_has_no_resolution_row_and_reopening_removes_it() {
        let (temporary_root, activity_history) = temporary_history();
        activity_history
            .record_detection_batch(&[detection_record(FIRST_SEEN)], "cursor-a")
            .await
            .expect("recorded");
        assert_eq!(
            raw_count(
                &temporary_root,
                "SELECT COUNT(*) FROM detection_resolutions"
            ),
            0
        );
        let detection_id =
            activity_history.list_detections().await.expect("listed")[0].detection_id;
        activity_history
            .resolve_detection(detection_id, ResolutionKind::DeletedByUser, FIRST_SEEN)
            .await
            .expect("resolved");
        assert_eq!(
            raw_count(
                &temporary_root,
                "SELECT COUNT(*) FROM detection_resolutions"
            ),
            1
        );
        activity_history
            .record_detection_batch(
                &[detection_record(FIRST_SEEN + SignedDuration::from_secs(60))],
                "cursor-b",
            )
            .await
            .expect("recorded");
        assert_eq!(
            raw_count(
                &temporary_root,
                "SELECT COUNT(*) FROM detection_resolutions"
            ),
            0
        );
    }

    #[tokio::test]
    async fn another_file_or_signature_is_another_detection_with_its_own_id() {
        let (_temporary_root, activity_history) = temporary_history();
        let other_signature = JournalDetectionRecord {
            signature_name: "Win.Test-2".to_owned(),
            ..detection_record(FIRST_SEEN)
        };
        let other_file = JournalDetectionRecord {
            file_path: PathBuf::from("/home/user/Downloads/b.exe"),
            ..detection_record(FIRST_SEEN)
        };
        activity_history
            .record_detection_batch(
                &[
                    detection_record(FIRST_SEEN),
                    other_signature,
                    other_file,
                    detection_record(FIRST_SEEN + SignedDuration::from_secs(1)),
                ],
                "cursor-a",
            )
            .await
            .expect("recorded");
        let mut detection_ids = activity_history
            .list_detections()
            .await
            .expect("listed")
            .into_iter()
            .map(|stored_detection| stored_detection.detection_id)
            .collect::<Vec<_>>();
        detection_ids.sort_unstable();
        assert_eq!(detection_ids, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn the_screenshot_fixture_loads_as_typed_detections() {
        let (temporary_root, activity_history) = temporary_history();
        let fixture_connection =
            rusqlite::Connection::open(temporary_root.path().join("history.db")).expect("database");
        fixture_connection
            .execute_batch(include_str!("../../../data/database-schemas/history.sql"))
            .expect("schema");
        fixture_connection
            .execute_batch(
                &include_str!("../../../xtask/assets/detections-seed.sql")
                    .replace(
                        "@UNRESOLVED_PATH@",
                        "'/home/alex/Downloads/invoice.pdf.exe'",
                    )
                    .replace(
                        "@SCHEDULED_PATH@",
                        "'/home/alex/Downloads/setup-helper.bin'",
                    ),
            )
            .expect("fixture rows");
        drop(fixture_connection);
        let fixture_detections = activity_history.list_detections().await.expect("listed");
        assert_eq!(
            fixture_detections
                .iter()
                .map(|stored_detection| (
                    stored_detection.detection_sources,
                    stored_detection.detection_state.awaits_user_decision()
                ))
                .collect::<Vec<_>>(),
            vec![
                (DetectionSources::OnAccessOnly, true),
                (DetectionSources::ScheduleOnly, true),
                (DetectionSources::OnAccessOnly, false),
            ]
        );
    }

    #[tokio::test]
    async fn the_detection_schema_refuses_rows_that_cannot_exist() {
        let (temporary_root, activity_history) = temporary_history();
        activity_history.list_detections().await.expect("created");
        let checked_connection =
            rusqlite::Connection::open(temporary_root.path().join("history.db")).expect("database");
        checked_connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 INSERT INTO background_detections VALUES (CAST('/a' AS BLOB), 'Sig-1', 1, \
                 'on_access', 10, 20, 2);",
            )
            .expect("valid row");
        [
            "INSERT INTO background_detections VALUES (CAST('/a' AS BLOB), 'Sig-1', 2, \
             'on_access', 10, 20, 2)",
            "INSERT INTO background_detections VALUES (CAST('/b' AS BLOB), 'Sig-1', 1, \
             'on_access', 10, 20, 2)",
            "INSERT INTO background_detections VALUES (CAST('/b' AS BLOB), 'Sig-1', 2, 'none', \
             10, 20, 2)",
            "INSERT INTO background_detections VALUES (CAST('/b' AS BLOB), 'Sig-1', 2, \
             'on_access', 10, 20, 0)",
            "INSERT INTO background_detections VALUES (CAST('/b' AS BLOB), 'Sig-1', 2, \
             'on_access', 30, 20, 1)",
            "INSERT INTO detection_resolutions VALUES (CAST('/a' AS BLOB), 'Sig-1', 'archived', \
             30)",
            "INSERT INTO detection_resolutions VALUES (CAST('/a' AS BLOB), 'Sig-1', \
             'quarantined', NULL)",
            "INSERT INTO detection_resolutions VALUES (CAST('/c' AS BLOB), 'Sig-1', 'deleted', 30)",
            "INSERT INTO detection_journal_position VALUES (2, 'cursor')",
        ]
        .into_iter()
        .for_each(|invalid_insert| {
            assert!(
                checked_connection.execute(invalid_insert, []).is_err(),
                "accepted: {invalid_insert}"
            );
        });
    }
}
