use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf};

use jiff::{SignedDuration, Timestamp};
use turso::{Connection, Row, Value};

use crate::host_services::{
    activity_history::activity_history_database::{ActivityHistory, ActivityHistoryFailure},
    detection_journal::detection_journal_records::{DetectionSource, JournalDetectionRecord},
};

const REOPEN_GRACE: SignedDuration = SignedDuration::from_secs(10);
const DETECTION_COLUMNS: &str = "detection_id, file_path, signature_name, found_on_access,
                                 found_by_schedule, first_seen_unix, last_seen_unix,
                                 sighting_count, resolution, resolved_at_unix";
const JOURNAL_POSITION_ROW: i64 = 1;
const UNRESOLVED_STORED_TEXT: &str = "";
const UNRESOLVED_STORED_TIME: i64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionKind {
    MovedToQuarantine,
    DeletedByUser,
    DismissedByUser,
}

impl ResolutionKind {
    const fn stored_text(self) -> &'static str {
        match self {
            Self::MovedToQuarantine => "quarantined",
            Self::DeletedByUser => "deleted",
            Self::DismissedByUser => "dismissed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredStateInconsistency {
    ResolutionTextUnknown { stored_resolution_text: String },
    ResolvedWithoutTime { resolution_kind: ResolutionKind },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectionState {
    Open,
    Resolved {
        resolution_kind: ResolutionKind,
        resolved_at: Timestamp,
    },
    StoredStateUnreadable {
        stored_inconsistency: StoredStateInconsistency,
    },
}

impl DetectionState {
    fn from_stored_columns(
        stored_resolution_text: String,
        resolved_at_unix: i64,
    ) -> Result<Self, jiff::Error> {
        let resolution_kind = match stored_resolution_text.as_str() {
            UNRESOLVED_STORED_TEXT => return Ok(Self::Open),
            "quarantined" => ResolutionKind::MovedToQuarantine,
            "deleted" => ResolutionKind::DeletedByUser,
            "dismissed" => ResolutionKind::DismissedByUser,
            _unknown_text => {
                return Ok(Self::StoredStateUnreadable {
                    stored_inconsistency: StoredStateInconsistency::ResolutionTextUnknown {
                        stored_resolution_text,
                    },
                });
            }
        };
        if resolved_at_unix == UNRESOLVED_STORED_TIME {
            return Ok(Self::StoredStateUnreadable {
                stored_inconsistency: StoredStateInconsistency::ResolvedWithoutTime {
                    resolution_kind,
                },
            });
        }
        Ok(Self::Resolved {
            resolution_kind,
            resolved_at: Timestamp::from_second(resolved_at_unix)?,
        })
    }

    pub const fn awaits_user_decision(&self) -> bool {
        match self {
            Self::Open | Self::StoredStateUnreadable { .. } => true,
            Self::Resolved { .. } => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionSources {
    OnAccessOnly,
    ScheduleOnly,
    OnAccessAndSchedule,
    NoSourceRecorded,
}

impl DetectionSources {
    const fn from_stored_flags(found_on_access: bool, found_by_schedule: bool) -> Self {
        match (found_on_access, found_by_schedule) {
            (true, true) => Self::OnAccessAndSchedule,
            (true, false) => Self::OnAccessOnly,
            (false, true) => Self::ScheduleOnly,
            (false, false) => Self::NoSourceRecorded,
        }
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
            (Self::NoSourceRecorded, new_source) => Self::from_single_source(new_source),
        }
    }

    pub const fn includes_on_access(self) -> bool {
        match self {
            Self::OnAccessOnly | Self::OnAccessAndSchedule => true,
            Self::ScheduleOnly | Self::NoSourceRecorded => false,
        }
    }

    const fn includes_schedule(self) -> bool {
        match self {
            Self::ScheduleOnly | Self::OnAccessAndSchedule => true,
            Self::OnAccessOnly | Self::NoSourceRecorded => false,
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
        DetectionState::StoredStateUnreadable { .. } => true,
    }
}

fn stored_detection_from_row(
    detection_row: &Row,
) -> Result<StoredDetection, ActivityHistoryFailure> {
    let path_bytes: Vec<u8> = detection_row.get(1)?;
    let found_on_access: i64 = detection_row.get(3)?;
    let found_by_schedule: i64 = detection_row.get(4)?;
    Ok(StoredDetection {
        detection_id: detection_row.get(0)?,
        file_path: PathBuf::from(OsStr::from_bytes(&path_bytes)),
        signature_name: detection_row.get(2)?,
        detection_sources: DetectionSources::from_stored_flags(
            found_on_access != 0,
            found_by_schedule != 0,
        ),
        first_seen: Timestamp::from_second(detection_row.get(5)?)?,
        last_seen: Timestamp::from_second(detection_row.get(6)?)?,
        sighting_count: detection_row.get(7)?,
        detection_state: DetectionState::from_stored_columns(
            detection_row.get(8)?,
            detection_row.get(9)?,
        )?,
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
    let Some(existing_detection) =
        find_matching_detection(database_connection, detection_record).await?
    else {
        let new_sources = DetectionSources::from_single_source(detection_record.detection_source);
        database_connection
            .execute(
                "INSERT INTO background_detections (file_path, signature_name, found_on_access, \
                 found_by_schedule, first_seen_unix, last_seen_unix, sighting_count, resolution, \
                 resolved_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, ?6, ?7)",
                vec![
                    Value::Blob(detection_record.file_path.as_os_str().as_bytes().to_vec()),
                    Value::Text(detection_record.signature_name.clone()),
                    Value::Integer(i64::from(new_sources.includes_on_access())),
                    Value::Integer(i64::from(new_sources.includes_schedule())),
                    Value::Integer(detection_record.observed_at.as_second()),
                    Value::Text(UNRESOLVED_STORED_TEXT.to_owned()),
                    Value::Integer(UNRESOLVED_STORED_TIME),
                ],
            )
            .await?;
        return Ok(DetectionSighting::NewlyOpened);
    };
    let merged_sources = existing_detection
        .detection_sources
        .including_source(detection_record.detection_source);
    database_connection
        .execute(
            "UPDATE background_detections SET found_on_access = ?1, found_by_schedule = ?2, \
             last_seen_unix = MAX(last_seen_unix, ?3), sighting_count = sighting_count + 1 WHERE \
             detection_id = ?4",
            vec![
                Value::Integer(i64::from(merged_sources.includes_on_access())),
                Value::Integer(i64::from(merged_sources.includes_schedule())),
                Value::Integer(detection_record.observed_at.as_second()),
                Value::Integer(existing_detection.detection_id),
            ],
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
            "UPDATE background_detections SET resolution = ?1, resolved_at_unix = ?2 WHERE \
             detection_id = ?3",
            vec![
                Value::Text(UNRESOLVED_STORED_TEXT.to_owned()),
                Value::Integer(UNRESOLVED_STORED_TIME),
                Value::Integer(existing_detection.detection_id),
            ],
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
        resolution_kind: ResolutionKind,
        resolved_at: Timestamp,
    ) -> Result<(), ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        self.open_connection()
            .await?
            .execute(
                "UPDATE background_detections SET resolution = ?1, resolved_at_unix = ?2 WHERE \
                 detection_id = ?3",
                vec![
                    Value::Text(resolution_kind.stored_text().to_owned()),
                    Value::Integer(resolved_at.as_second()),
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

    async fn insert_raw_detection_row(
        activity_history: &ActivityHistory,
        found_on_access_flag: i64,
        found_by_schedule_flag: i64,
        stored_resolution_text: &str,
        resolved_at_unix: i64,
    ) {
        activity_history
            .open_connection()
            .await
            .expect("opened")
            .execute(
                "INSERT INTO background_detections (file_path, signature_name, found_on_access, \
                 found_by_schedule, first_seen_unix, last_seen_unix, sighting_count, resolution, \
                 resolved_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, ?6, ?7)",
                vec![
                    Value::Blob(
                        detection_record(FIRST_SEEN)
                            .file_path
                            .as_os_str()
                            .as_bytes()
                            .to_vec(),
                    ),
                    Value::Text(detection_record(FIRST_SEEN).signature_name),
                    Value::Integer(found_on_access_flag),
                    Value::Integer(found_by_schedule_flag),
                    Value::Integer(FIRST_SEEN.as_second()),
                    Value::Text(stored_resolution_text.to_owned()),
                    Value::Integer(resolved_at_unix),
                ],
            )
            .await
            .expect("inserted");
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
            SourceMergeCase {
                existing_sources: DetectionSources::NoSourceRecorded,
                new_source: DetectionSource::ScheduledScan,
                merged_sources: DetectionSources::ScheduleOnly,
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

    #[tokio::test]
    async fn an_unrecognised_stored_resolution_stays_visible_as_needing_a_decision() {
        let (_temporary_root, activity_history) = temporary_history();
        insert_raw_detection_row(&activity_history, 1, 0, "archived", 1_793_869_300).await;
        let unreadable_state = only_detection_state(&activity_history).await;
        assert_eq!(
            unreadable_state,
            DetectionState::StoredStateUnreadable {
                stored_inconsistency: StoredStateInconsistency::ResolutionTextUnknown {
                    stored_resolution_text: "archived".to_owned(),
                },
            }
        );
        assert!(unreadable_state.awaits_user_decision());
        let next_sighting = activity_history
            .record_detection_batch(
                &[detection_record(FIRST_SEEN + SignedDuration::from_secs(1))],
                "cursor-a",
            )
            .await
            .expect("recorded");
        assert_eq!(next_sighting.len(), 1);
        assert_eq!(
            only_detection_state(&activity_history).await,
            DetectionState::Open
        );
    }

    #[tokio::test]
    async fn a_resolution_stored_without_a_time_is_not_treated_as_resolved() {
        let (_temporary_root, activity_history) = temporary_history();
        insert_raw_detection_row(&activity_history, 1, 0, "quarantined", 0).await;
        let unreadable_state = only_detection_state(&activity_history).await;
        assert_eq!(
            unreadable_state,
            DetectionState::StoredStateUnreadable {
                stored_inconsistency: StoredStateInconsistency::ResolvedWithoutTime {
                    resolution_kind: ResolutionKind::MovedToQuarantine,
                },
            }
        );
        assert!(unreadable_state.awaits_user_decision());
    }

    #[tokio::test]
    async fn a_row_without_any_found_flag_reads_as_no_source_recorded() {
        let (_temporary_root, activity_history) = temporary_history();
        insert_raw_detection_row(&activity_history, 0, 0, "", 0).await;
        assert_eq!(
            activity_history.list_detections().await.expect("listed")[0].detection_sources,
            DetectionSources::NoSourceRecorded
        );
    }
}
