use std::path::Path;

use crate::{
    host_services::{
        activity_history::{
            activity_history_database::ActivityHistoryFailure,
            submission_history_store::{
                SubmissionProgress, SubmissionRecord, SubmissionService, SubmissionTarget,
            },
        },
        quarantine_vault::{
            quarantine_entry_database::{QuarantineEntryRecord, StoredDetectionDate},
            quarantine_file_moves::{QuarantineMoveFailure, RecordedPayloadHash},
        },
        sample_submissions::bazaar_sample_upload::{BazaarEligibility, bazaar_eligibility},
    },
    sharing::submissions_page::uploads_in_flight::{UploadActivity, UploadKey, UploadsInFlight},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionsPageOutput {
    TallyChanged(SubmissionTally),
    UploadNoticeReady(String),
    StoredKeyChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionTally {
    TallyLoading,
    TallyCounted {
        submitted_count: usize,
        awaiting_count: usize,
        refused_count: usize,
    },
    TallyUnavailable,
}

#[derive(Debug)]
pub enum SubmissionListing {
    ListingLoading,
    ListingLoaded(Vec<SubmissionRecord>),
    ListingFailed(ActivityHistoryFailure),
}

impl SubmissionListing {
    pub fn listed_submissions(&self) -> &[SubmissionRecord] {
        match self {
            Self::ListingLoaded(listed_submissions) => listed_submissions,
            Self::ListingLoading | Self::ListingFailed(_) => &[],
        }
    }

    pub fn has_submissions(&self) -> bool {
        !self.listed_submissions().is_empty()
    }

    pub fn submission_tally(&self) -> SubmissionTally {
        match self {
            Self::ListingLoading => SubmissionTally::TallyLoading,
            Self::ListingFailed(_) => SubmissionTally::TallyUnavailable,
            Self::ListingLoaded(listed_submissions) => {
                let progress_count = |counted_progress: SubmissionProgress| {
                    listed_submissions
                        .iter()
                        .filter(|listed_submission| {
                            listed_submission.submission_state.submission_progress()
                                == counted_progress
                        })
                        .count()
                };
                SubmissionTally::TallyCounted {
                    submitted_count: listed_submissions.len(),
                    awaiting_count: progress_count(SubmissionProgress::AwaitingOutcome),
                    refused_count: progress_count(SubmissionProgress::RefusedByService),
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum CandidateListing {
    CandidatesLoading,
    CandidatesLoaded(Vec<QuarantineEntryRecord>),
    CandidatesFailed(QuarantineMoveFailure),
}

impl CandidateListing {
    pub fn listed_candidates(&self) -> &[QuarantineEntryRecord] {
        match self {
            Self::CandidatesLoaded(listed_candidates) => listed_candidates,
            Self::CandidatesLoading | Self::CandidatesFailed(_) => &[],
        }
    }

    pub fn candidate_with_id(&self, entry_id: i64) -> Option<&QuarantineEntryRecord> {
        self.listed_candidates()
            .iter()
            .find(|listed_candidate| listed_candidate.entry_id == entry_id)
    }

    pub fn newest_candidate_from(&self, original_path: &Path) -> Option<&QuarantineEntryRecord> {
        self.listed_candidates()
            .iter()
            .filter(|listed_candidate| listed_candidate.original_path == original_path)
            .max_by_key(|listed_candidate| match listed_candidate.detection_date {
                StoredDetectionDate::DetectedAt(detected_at) => detected_at.as_second(),
                StoredDetectionDate::UnreadableText(_) => i64::MIN,
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFilter {
    AllServices,
    OnlyService(SubmissionService),
}

pub const SERVICE_FILTER_CHOICES: [ServiceFilter; 4] = [
    ServiceFilter::AllServices,
    ServiceFilter::OnlyService(SubmissionService::ClamavProject),
    ServiceFilter::OnlyService(SubmissionService::MalwareBazaar),
    ServiceFilter::OnlyService(SubmissionService::VirusTotal),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressFilter {
    AllProgress,
    OnlyProgress(SubmissionProgress),
}

pub const PROGRESS_FILTER_CHOICES: [ProgressFilter; 4] = [
    ProgressFilter::AllProgress,
    ProgressFilter::OnlyProgress(SubmissionProgress::AwaitingOutcome),
    ProgressFilter::OnlyProgress(SubmissionProgress::OutcomeKnown),
    ProgressFilter::OnlyProgress(SubmissionProgress::RefusedByService),
];

pub fn choice_position<Choice: PartialEq>(
    offered_choices: &[Choice],
    chosen_choice: &Choice,
) -> u32 {
    offered_choices
        .iter()
        .position(|offered_choice| offered_choice == chosen_choice)
        .and_then(|choice_index| u32::try_from(choice_index).ok())
        .unwrap_or_default()
}

pub fn choice_at<Choice: Copy>(offered_choices: &[Choice], chosen_position: u32) -> Option<Choice> {
    usize::try_from(chosen_position)
        .ok()
        .and_then(|choice_index| offered_choices.get(choice_index))
        .copied()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmissionFilters {
    pub service_filter: ServiceFilter,
    pub progress_filter: ProgressFilter,
}

impl SubmissionFilters {
    pub const SHOW_EVERYTHING: Self = Self {
        service_filter: ServiceFilter::AllServices,
        progress_filter: ProgressFilter::AllProgress,
    };

    pub fn admits_submission(&self, submission_record: &SubmissionRecord) -> bool {
        let service_admitted = match self.service_filter {
            ServiceFilter::AllServices => true,
            ServiceFilter::OnlyService(submission_service) => {
                submission_record
                    .submission_state
                    .submission_target()
                    .submission_service()
                    == submission_service
            }
        };
        let progress_admitted = match self.progress_filter {
            ProgressFilter::AllProgress => true,
            ProgressFilter::OnlyProgress(submission_progress) => {
                submission_record.submission_state.submission_progress() == submission_progress
            }
        };
        service_admitted && progress_admitted
    }
}

pub fn offered_targets(entry_record: &QuarantineEntryRecord) -> Vec<SubmissionTarget> {
    if entry_record.payload_hash == RecordedPayloadHash::IntegrityUnknown {
        return Vec::new();
    }
    let false_positive_target = entry_record
        .threat_identity
        .matched_signature_name()
        .map(|_signature_name| SubmissionTarget::ClamavFalsePositive);
    let bazaar_target = match bazaar_eligibility(&entry_record.threat_identity) {
        BazaarEligibility::EligibleSignature { .. } => Some(SubmissionTarget::MalwareBazaarSample),
        BazaarEligibility::NotDetectedByClamav | BazaarEligibility::UnwantedProgramOnly => None,
    };
    false_positive_target
        .into_iter()
        .chain(bazaar_target)
        .chain([SubmissionTarget::VirusTotalSample])
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfferedTarget {
    pub submission_target: SubmissionTarget,
    pub upload_activity: UploadActivity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendAvailability {
    SendableNow,
    NothingToSend,
    EveryTargetUploading,
}

pub fn entry_upload_key(
    entry_record: &QuarantineEntryRecord,
    submission_target: SubmissionTarget,
) -> Option<UploadKey> {
    match &entry_record.payload_hash {
        RecordedPayloadHash::KnownSha256 { sha256_hex } => {
            Some(UploadKey::for_target(sha256_hex, submission_target))
        }
        RecordedPayloadHash::IntegrityUnknown => None,
    }
}

pub fn offered_target_activities(
    entry_record: &QuarantineEntryRecord,
    uploads_in_flight: &UploadsInFlight,
) -> Vec<OfferedTarget> {
    offered_targets(entry_record)
        .into_iter()
        .filter_map(|submission_target| {
            entry_upload_key(entry_record, submission_target).map(|upload_key| OfferedTarget {
                submission_target,
                upload_activity: uploads_in_flight.upload_activity(&upload_key),
            })
        })
        .collect()
}

pub fn send_availability(offered_activities: &[OfferedTarget]) -> SendAvailability {
    if offered_activities.is_empty() {
        SendAvailability::NothingToSend
    } else if offered_activities
        .iter()
        .any(|offered_target| offered_target.upload_activity == UploadActivity::UploadIdle)
    {
        SendAvailability::SendableNow
    } else {
        SendAvailability::EveryTargetUploading
    }
}

#[cfg(test)]
mod submissions_state_tests {
    use std::path::PathBuf;

    use bytesize::ByteSize;
    use jiff::Timestamp;

    use super::*;
    use crate::host_services::{
        activity_history::submission_history_store::{
            BazaarSampleStatus, FalsePositiveReview, SubmissionState, SubmittedFile,
            VirusTotalSampleStatus,
        },
        clamav_scanner::scanner_output_parser::ThreatIdentity,
    };

    fn submission_with(submission_state: SubmissionState) -> SubmissionRecord {
        SubmissionRecord {
            submitted_file: SubmittedFile {
                content_sha256: "a".repeat(64),
                file_name: "invoice.exe".to_owned(),
            },
            submitted_at: Timestamp::constant(100, 0),
            submission_state,
        }
    }

    fn quarantined_entry(
        threat_identity: ThreatIdentity,
        payload_hash: RecordedPayloadHash,
    ) -> QuarantineEntryRecord {
        QuarantineEntryRecord {
            entry_id: 3,
            original_path: PathBuf::from("/home/user/Downloads/invoice.exe"),
            quarantine_path: PathBuf::from("/vault/payload"),
            threat_identity,
            detection_date: StoredDetectionDate::from("2026-11-01T00:00:00Z".to_owned()),
            file_size: ByteSize::b(10),
            payload_hash,
            original_permissions: 0o644,
        }
    }

    fn known_hash() -> RecordedPayloadHash {
        RecordedPayloadHash::KnownSha256 {
            sha256_hex: "b".repeat(64),
        }
    }

    #[test]
    fn the_tally_counts_awaiting_and_refused_submissions() {
        let submission_listing = SubmissionListing::ListingLoaded(vec![
            submission_with(SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Trojan.Agent".to_owned(),
                review_status: FalsePositiveReview::AwaitingClamavReview,
            }),
            submission_with(SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            }),
            submission_with(SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::SubmissionRefused {
                    refusal_reason: "BadRequestError".to_owned(),
                },
            }),
        ]);
        assert_eq!(
            submission_listing.submission_tally(),
            SubmissionTally::TallyCounted {
                submitted_count: 3,
                awaiting_count: 1,
                refused_count: 1,
            }
        );
        assert_eq!(
            SubmissionListing::ListingLoading.submission_tally(),
            SubmissionTally::TallyLoading
        );
        assert_eq!(
            SubmissionListing::ListingFailed(ActivityHistoryFailure::StoredSubmissionUnreadable)
                .submission_tally(),
            SubmissionTally::TallyUnavailable
        );
    }

    #[test]
    fn filters_narrow_by_service_and_progress() {
        let bazaar_listed = submission_with(SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
        });
        assert!(SubmissionFilters::SHOW_EVERYTHING.admits_submission(&bazaar_listed));
        assert!(
            SubmissionFilters {
                service_filter: ServiceFilter::OnlyService(SubmissionService::MalwareBazaar),
                progress_filter: ProgressFilter::OnlyProgress(SubmissionProgress::OutcomeKnown),
            }
            .admits_submission(&bazaar_listed)
        );
        assert!(
            !SubmissionFilters {
                service_filter: ServiceFilter::OnlyService(SubmissionService::VirusTotal),
                progress_filter: ProgressFilter::AllProgress,
            }
            .admits_submission(&bazaar_listed)
        );
        assert!(
            !SubmissionFilters {
                service_filter: ServiceFilter::AllServices,
                progress_filter: ProgressFilter::OnlyProgress(SubmissionProgress::RefusedByService),
            }
            .admits_submission(&bazaar_listed)
        );
    }

    #[test]
    fn filter_choices_round_trip_through_their_positions() {
        SERVICE_FILTER_CHOICES.iter().for_each(|service_filter| {
            assert_eq!(
                choice_at(
                    &SERVICE_FILTER_CHOICES,
                    choice_position(&SERVICE_FILTER_CHOICES, service_filter)
                ),
                Some(*service_filter)
            );
        });
        assert_eq!(choice_at(&PROGRESS_FILTER_CHOICES, 9), None);
    }

    #[test]
    fn targets_follow_the_detection_and_the_recorded_hash() {
        assert_eq!(
            offered_targets(&quarantined_entry(
                ThreatIdentity::Signature {
                    signature_name: "Win.Trojan.Agent".to_owned(),
                },
                known_hash()
            )),
            vec![
                SubmissionTarget::ClamavFalsePositive,
                SubmissionTarget::MalwareBazaarSample,
                SubmissionTarget::VirusTotalSample,
            ]
        );
        assert_eq!(
            offered_targets(&quarantined_entry(
                ThreatIdentity::Signature {
                    signature_name: "PUA.Win.Packer.Upx".to_owned(),
                },
                known_hash()
            )),
            vec![
                SubmissionTarget::ClamavFalsePositive,
                SubmissionTarget::VirusTotalSample,
            ]
        );
        assert_eq!(
            offered_targets(&quarantined_entry(
                ThreatIdentity::BlockedByOnAccess,
                known_hash()
            )),
            vec![SubmissionTarget::VirusTotalSample]
        );
    }

    #[test]
    fn an_entry_without_a_usable_hash_offers_nothing_to_send() {
        assert!(
            offered_targets(&quarantined_entry(
                ThreatIdentity::Signature {
                    signature_name: "Win.Trojan.Agent".to_owned(),
                },
                RecordedPayloadHash::IntegrityUnknown
            ))
            .is_empty()
        );
    }

    #[test]
    fn targets_being_uploaded_are_offered_but_not_available() {
        let entry_record = quarantined_entry(
            ThreatIdentity::Signature {
                signature_name: "Win.Trojan.Agent".to_owned(),
            },
            known_hash(),
        );
        let mut uploads_in_flight = UploadsInFlight::default();
        uploads_in_flight
            .start_upload(UploadKey::for_target(
                &"b".repeat(64),
                SubmissionTarget::MalwareBazaarSample,
            ))
            .expect("first upload");
        let offered_activities = offered_target_activities(&entry_record, &uploads_in_flight);
        assert_eq!(
            offered_activities
                .iter()
                .map(|offered_target| offered_target.upload_activity)
                .collect::<Vec<_>>(),
            vec![
                UploadActivity::UploadIdle,
                UploadActivity::UploadRunning,
                UploadActivity::UploadIdle
            ]
        );
        assert_eq!(
            send_availability(&offered_activities),
            SendAvailability::SendableNow
        );
        [
            SubmissionTarget::ClamavFalsePositive,
            SubmissionTarget::VirusTotalSample,
        ]
        .into_iter()
        .for_each(|submission_target| {
            uploads_in_flight
                .start_upload(UploadKey::for_target(&"b".repeat(64), submission_target))
                .expect("other uploads");
        });
        assert_eq!(
            send_availability(&offered_target_activities(
                &entry_record,
                &uploads_in_flight
            )),
            SendAvailability::EveryTargetUploading
        );
        assert_eq!(
            send_availability(&offered_target_activities(
                &quarantined_entry(
                    ThreatIdentity::BlockedByOnAccess,
                    RecordedPayloadHash::IntegrityUnknown
                ),
                &uploads_in_flight
            )),
            SendAvailability::NothingToSend
        );
    }

    #[test]
    fn a_requested_file_finds_its_newest_quarantined_copy() {
        let older_entry = quarantined_entry(ThreatIdentity::BlockedByOnAccess, known_hash());
        let newer_entry = QuarantineEntryRecord {
            entry_id: 4,
            detection_date: StoredDetectionDate::from("2026-11-03T00:00:00Z".to_owned()),
            ..older_entry.clone()
        };
        let candidate_listing = CandidateListing::CandidatesLoaded(vec![older_entry, newer_entry]);
        assert_eq!(
            candidate_listing
                .newest_candidate_from(Path::new("/home/user/Downloads/invoice.exe"))
                .map(|newest_candidate| newest_candidate.entry_id),
            Some(4)
        );
        assert_eq!(
            candidate_listing.newest_candidate_from(Path::new("/elsewhere")),
            None
        );
    }
}
