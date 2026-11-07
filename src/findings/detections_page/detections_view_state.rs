use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{
    findings::detections_page::{
        detected_file_state::{DetectedFileState, OpeningCheck},
        incident_timeline_presentation::{
            DeletionPrompt, DisplayedDetection, SignatureLookupState, detection_needs_attention,
        },
    },
    host_services::detection_journal::{
        detection_history_store::StoredDetection,
        detection_journal_follower::{DetectionJournalEvent, JournalAccess},
        detection_journal_records::JournalDetectionRecord,
    },
};

#[derive(Debug, Default)]
pub enum IncidentView {
    #[default]
    DetectionList,
    IncidentOpen {
        detection_id: i64,
        deletion_prompt: DeletionPrompt,
        signature_lookup: SignatureLookupState,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IncidentRequest {
    KeepShownIncident,
    OpenIncidentForFile { file_path: PathBuf },
}

impl IncidentView {
    pub const fn freshly_opened(detection_id: i64) -> Self {
        Self::IncidentOpen {
            detection_id,
            deletion_prompt: DeletionPrompt::NotAsked,
            signature_lookup: SignatureLookupState::NotLookedUp,
        }
    }

    pub const fn opened_detection_id(&self) -> Option<i64> {
        match self {
            Self::DetectionList => None,
            Self::IncidentOpen { detection_id, .. } => Some(*detection_id),
        }
    }

    pub fn with_deletion_prompt(self, chosen_prompt: DeletionPrompt) -> Self {
        match self {
            Self::DetectionList => Self::DetectionList,
            Self::IncidentOpen {
                detection_id,
                signature_lookup,
                ..
            } => Self::IncidentOpen {
                detection_id,
                deletion_prompt: chosen_prompt,
                signature_lookup,
            },
        }
    }

    pub fn with_signature_lookup(
        self,
        lookup_detection_id: i64,
        lookup_state: SignatureLookupState,
    ) -> Self {
        match self {
            Self::IncidentOpen {
                detection_id,
                deletion_prompt,
                ..
            } if detection_id == lookup_detection_id => Self::IncidentOpen {
                detection_id,
                deletion_prompt,
                signature_lookup: lookup_state,
            },
            Self::DetectionList | Self::IncidentOpen { .. } => self,
        }
    }

    pub fn with_requested_incident(
        self,
        displayed_detections: &[DisplayedDetection],
        incident_request: &IncidentRequest,
    ) -> Self {
        match incident_request {
            IncidentRequest::KeepShownIncident => self,
            IncidentRequest::OpenIncidentForFile { file_path } => detection_for_file(
                displayed_detections,
                file_path,
            )
            .map_or(self, |displayed_detection| {
                Self::freshly_opened(displayed_detection.stored_detection.detection_id)
            }),
        }
    }

    pub fn still_listed_in(self, displayed_detections: &[DisplayedDetection]) -> Self {
        let opened_detection_listed = self.opened_detection_id().is_some_and(|detection_id| {
            displayed_detections.iter().any(|displayed_detection| {
                displayed_detection.stored_detection.detection_id == detection_id
            })
        });
        if opened_detection_listed {
            self
        } else {
            Self::DetectionList
        }
    }
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
                DetectionJournalEvent::FollowingStopped(follow_failure) => {
                    journal_batch
                        .access_changes
                        .push(JournalAccess::FollowingFailed(follow_failure));
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
    use super::*;
    use crate::{
        findings::detections_page::detected_file_state::{FileAccess, FileOwner},
        host_services::{
            detection_journal::{
                detection_history_store::{DetectionSources, DetectionState, ResolutionKind},
                detection_journal_records::DetectionSource,
            },
            threat_intel::malware_bazaar_client::KnownSampleLookup,
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

    fn listed_detection(detection_id: i64, file_name: &str) -> DisplayedDetection {
        DisplayedDetection {
            stored_detection: StoredDetection {
                file_path: PathBuf::from("/home/user/Downloads").join(file_name),
                ..stored_detection(detection_id, DetectionState::Open)
            },
            file_state: DetectedFileState::NoLongerThere,
        }
    }

    fn incident_with_prompt_and_lookup(detection_id: i64) -> IncidentView {
        IncidentView::freshly_opened(detection_id)
            .with_deletion_prompt(DeletionPrompt::AwaitingAnswer)
            .with_signature_lookup(
                detection_id,
                SignatureLookupState::LookupFinished(KnownSampleLookup::NoKnownSamples),
            )
    }

    fn is_fresh_incident(incident_view: &IncidentView, expected_detection_id: i64) -> bool {
        matches!(
            incident_view,
            IncidentView::IncidentOpen {
                detection_id,
                deletion_prompt: DeletionPrompt::NotAsked,
                signature_lookup: SignatureLookupState::NotLookedUp,
            } if *detection_id == expected_detection_id
        )
    }

    #[test]
    fn a_lookup_result_for_another_incident_is_ignored() {
        let incident_view = IncidentView::freshly_opened(2).with_signature_lookup(
            1,
            SignatureLookupState::LookupFinished(KnownSampleLookup::NoKnownSamples),
        );
        assert!(is_fresh_incident(&incident_view, 2));
    }

    #[test]
    fn a_lookup_result_for_the_open_incident_is_shown() {
        let incident_view = IncidentView::freshly_opened(1)
            .with_signature_lookup(1, SignatureLookupState::LookingUp);
        assert!(matches!(
            incident_view,
            IncidentView::IncidentOpen {
                signature_lookup: SignatureLookupState::LookingUp,
                ..
            }
        ));
    }

    #[test]
    fn a_lookup_result_after_going_back_is_ignored() {
        let incident_view = IncidentView::DetectionList
            .with_signature_lookup(1, SignatureLookupState::LookingUp)
            .with_deletion_prompt(DeletionPrompt::AwaitingAnswer);
        assert!(matches!(incident_view, IncidentView::DetectionList));
    }

    #[test]
    fn reopening_an_incident_resets_the_deletion_prompt_and_the_lookup() {
        assert!(matches!(
            incident_with_prompt_and_lookup(1),
            IncidentView::IncidentOpen {
                deletion_prompt: DeletionPrompt::AwaitingAnswer,
                signature_lookup: SignatureLookupState::LookupFinished(_),
                ..
            }
        ));
        assert!(is_fresh_incident(&IncidentView::freshly_opened(1), 1));
    }

    #[test]
    fn opening_from_a_notification_resets_the_deletion_prompt_and_the_lookup() {
        let displayed_detections = [
            listed_detection(1, "invoice.pdf.exe"),
            listed_detection(2, "setup.exe"),
        ];
        let incident_request = IncidentRequest::OpenIncidentForFile {
            file_path: PathBuf::from("/home/user/Downloads/invoice.pdf.exe"),
        };
        [1, 2].into_iter().for_each(|previously_open_id| {
            let incident_view = incident_with_prompt_and_lookup(previously_open_id)
                .with_requested_incident(&displayed_detections, &incident_request);
            assert!(is_fresh_incident(&incident_view, 1));
        });
    }

    #[test]
    fn a_notification_for_an_unlisted_file_keeps_the_shown_view() {
        let displayed_detections = [listed_detection(2, "setup.exe")];
        let incident_view = incident_with_prompt_and_lookup(2).with_requested_incident(
            &displayed_detections,
            &IncidentRequest::OpenIncidentForFile {
                file_path: PathBuf::from("/home/user/Downloads/invoice.pdf.exe"),
            },
        );
        assert!(matches!(
            incident_view,
            IncidentView::IncidentOpen {
                detection_id: 2,
                deletion_prompt: DeletionPrompt::AwaitingAnswer,
                ..
            }
        ));
    }

    #[test]
    fn an_incident_no_longer_found_falls_back_to_the_list() {
        let displayed_detections = [listed_detection(2, "setup.exe")];
        assert!(matches!(
            incident_with_prompt_and_lookup(1).still_listed_in(&displayed_detections),
            IncidentView::DetectionList
        ));
        assert!(matches!(
            incident_with_prompt_and_lookup(2).still_listed_in(&displayed_detections),
            IncidentView::IncidentOpen {
                deletion_prompt: DeletionPrompt::AwaitingAnswer,
                ..
            }
        ));
    }
}
