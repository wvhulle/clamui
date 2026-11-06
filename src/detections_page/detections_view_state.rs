use std::{collections::HashMap, path::Path};

use crate::{
    detections_page::{
        detected_file_state::{DetectedFileState, OpeningCheck},
        incident_timeline_presentation::{DisplayedDetection, detection_needs_attention},
    },
    host_services::detection_journal::{
        detection_history_store::StoredDetection,
        detection_journal_follower::{DetectionJournalEvent, JournalAccess},
        detection_journal_records::JournalDetectionRecord,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenedIncident {
    NoIncidentOpen,
    IncidentOpen { detection_id: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwaitedIncident {
    NothingAwaited,
    FileAwaited { file_path: std::path::PathBuf },
}

pub struct JournalBatch {
    pub detection_records: Vec<JournalDetectionRecord>,
    pub last_cursor: String,
    pub access_changes: Vec<JournalAccess>,
}

pub fn split_journal_batch(journal_events: Vec<DetectionJournalEvent>) -> JournalBatch {
    journal_events.into_iter().fold(
        JournalBatch {
            detection_records: Vec::new(),
            last_cursor: String::new(),
            access_changes: Vec::new(),
        },
        |mut journal_batch, journal_event| {
            match journal_event {
                DetectionJournalEvent::DetectionObserved {
                    detection_record,
                    journal_cursor,
                } => {
                    journal_batch.detection_records.push(detection_record);
                    journal_batch.last_cursor = journal_cursor;
                }
                DetectionJournalEvent::JournalUnreadable => {
                    journal_batch
                        .access_changes
                        .push(JournalAccess::JournalUnreadable);
                }
                DetectionJournalEvent::FollowingStopped { failure_text } => {
                    journal_batch
                        .access_changes
                        .push(JournalAccess::FollowingFailed { failure_text });
                }
            }
            journal_batch
        },
    )
}

pub fn file_state_for_detection(
    stored_detection: &StoredDetection,
    known_file_states: &HashMap<i64, DetectedFileState>,
    inspect_file: impl Fn(&Path, OpeningCheck) -> DetectedFileState,
) -> DetectedFileState {
    if let Some(known_state) = known_file_states.get(&stored_detection.detection_id) {
        return *known_state;
    }
    inspect_file(
        &stored_detection.file_path,
        if stored_detection.detection_state.awaits_user_decision() {
            OpeningCheck::OpenToCheckBlocking
        } else {
            OpeningCheck::InspectWithoutOpening
        },
    )
}

pub fn file_states_to_keep(
    displayed_detections: &[DisplayedDetection],
    newly_opened: &[JournalDetectionRecord],
) -> HashMap<i64, DetectedFileState> {
    displayed_detections
        .iter()
        .filter(|displayed_detection| {
            !newly_opened.iter().any(|detection_record| {
                detection_record.file_path == displayed_detection.stored_detection.file_path
            })
        })
        .map(|displayed_detection| {
            (
                displayed_detection.stored_detection.detection_id,
                displayed_detection.file_state,
            )
        })
        .collect()
}

pub fn detections_needing_attention_first(
    displayed_detections: &[DisplayedDetection],
) -> Vec<DisplayedDetection> {
    let mut sorted_detections = displayed_detections.to_vec();
    sorted_detections
        .sort_by_key(|displayed_detection| !detection_needs_attention(displayed_detection));
    sorted_detections
}

pub fn unresolved_detection_count(displayed_detections: &[DisplayedDetection]) -> usize {
    displayed_detections
        .iter()
        .filter(|displayed_detection| detection_needs_attention(displayed_detection))
        .count()
}

pub fn detection_for_file<'detections>(
    displayed_detections: &'detections [DisplayedDetection],
    file_path: &Path,
) -> Option<&'detections DisplayedDetection> {
    displayed_detections
        .iter()
        .find(|displayed_detection| displayed_detection.stored_detection.file_path == file_path)
}

#[cfg(test)]
mod detections_view_state_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        detections_page::detected_file_state::{FileAccess, FileOwner},
        host_services::detection_journal::{
            detection_history_store::{DetectionSources, DetectionState, ResolutionKind},
            detection_journal_records::DetectionSource,
        },
    };

    fn stored_detection(detection_id: i64, detection_state: DetectionState) -> StoredDetection {
        StoredDetection {
            detection_id,
            file_path: PathBuf::from("/home/user/Downloads/blocked.exe"),
            signature_name: "Win.Test-1".to_owned(),
            detection_sources: DetectionSources::OnAccessOnly,
            first_seen: jiff::Timestamp::constant(1, 0),
            last_seen: jiff::Timestamp::constant(2, 0),
            sighting_count: 1,
            detection_state,
        }
    }

    fn opens_needed_for(
        detection: &StoredDetection,
        known_file_states: &HashMap<i64, DetectedFileState>,
    ) -> u32 {
        let found_state =
            file_state_for_detection(detection, known_file_states, |_file_path, opening_check| {
                match opening_check {
                    OpeningCheck::OpenToCheckBlocking => DetectedFileState::StateUnknown,
                    OpeningCheck::InspectWithoutOpening => DetectedFileState::NoLongerThere,
                }
            });
        u32::from(found_state == DetectedFileState::StateUnknown)
    }

    #[test]
    fn a_repeat_sighting_never_reopens_the_file_because_that_would_cause_another_sighting() {
        let detection = stored_detection(7, DetectionState::Open);
        let displayed_detections = [DisplayedDetection {
            stored_detection: detection.clone(),
            file_state: DetectedFileState::Present {
                access: FileAccess::BlockedOnAccess,
                owner: FileOwner::CurrentUser,
            },
        }];
        assert_eq!(
            opens_needed_for(&detection, &file_states_to_keep(&displayed_detections, &[])),
            0
        );
    }

    #[test]
    fn a_new_or_reopened_detection_is_checked_once() {
        let detection = stored_detection(7, DetectionState::Open);
        assert_eq!(opens_needed_for(&detection, &HashMap::new()), 1);
        let displayed_detections = [DisplayedDetection {
            stored_detection: detection.clone(),
            file_state: DetectedFileState::NoLongerThere,
        }];
        let reopened_record = JournalDetectionRecord {
            observed_at: jiff::Timestamp::constant(3, 0),
            detection_source: DetectionSource::OnAccessScanner,
            file_path: detection.file_path.clone(),
            signature_name: detection.signature_name.clone(),
        };
        assert_eq!(
            opens_needed_for(
                &detection,
                &file_states_to_keep(&displayed_detections, &[reopened_record])
            ),
            1
        );
    }

    #[test]
    fn resolved_detections_are_never_opened() {
        assert_eq!(
            opens_needed_for(
                &stored_detection(
                    7,
                    DetectionState::Resolved {
                        resolution_kind: ResolutionKind::DismissedByUser,
                        resolved_at: jiff::Timestamp::constant(3, 0),
                    }
                ),
                &HashMap::new()
            ),
            0
        );
    }

    #[test]
    fn a_journal_batch_keeps_the_last_cursor_and_reports_access_problems() {
        let detection_record = JournalDetectionRecord {
            observed_at: jiff::Timestamp::constant(1, 0),
            detection_source: DetectionSource::OnAccessScanner,
            file_path: PathBuf::from("/tmp/file"),
            signature_name: "Win.Test-1".to_owned(),
        };
        let journal_batch = split_journal_batch(vec![
            DetectionJournalEvent::DetectionObserved {
                detection_record: detection_record.clone(),
                journal_cursor: "cursor-a".to_owned(),
            },
            DetectionJournalEvent::DetectionObserved {
                detection_record,
                journal_cursor: "cursor-b".to_owned(),
            },
            DetectionJournalEvent::JournalUnreadable,
        ]);
        assert_eq!(journal_batch.detection_records.len(), 2);
        assert_eq!(journal_batch.last_cursor, "cursor-b");
        assert_eq!(
            journal_batch.access_changes,
            vec![JournalAccess::JournalUnreadable]
        );
    }
}
