use gettextrs::{gettext, ngettext};

use crate::{
    findings::sent_samples_page::{
        sent_samples_state::{
            CandidateListing, ProgressFilter, SendAvailability, ServiceFilter, SubmissionFilters,
            SubmissionListing, offered_target_activities, send_availability,
        },
        uploads_in_flight::UploadsInFlight,
    },
    host_services::{
        activity_history::submission_history_store::{
            BazaarSampleStatus, FalsePositiveReview, MissedMalwareReview, RemoteEntryLink,
            SignatureDatabaseVersion, SubmissionKind, SubmissionProgress, SubmissionRecord,
            SubmissionService, SubmissionState, SubmissionTarget, VirusTotalSampleStatus,
        },
        clamav_scanner::scanner_output_parser::{displayed_threat_name, sanitize_scanner_line},
        desktop::locale_formatting::MomentFormatters,
        quarantine_vault::{
            quarantine_entry_database::QuarantineEntryRecord,
            quarantine_file_moves::RecordedPayloadHash,
        },
        sample_submissions::{
            remote_status_refresh::{RemoteRefreshFailure, RemoteRefreshSummary},
            submission_samples::shown_file_name,
        },
        threat_intel::{
            file_reputation_check::{describe_bazaar_failure, describe_virustotal_failure},
            service_key_storage::describe_key_failure,
        },
    },
    shared_widgets::{
        quarantine_failure_text::describe_quarantine_failure,
        submission_outcome_text::history_failure_text,
    },
};

const SHORT_HASH_LENGTH: usize = 12;

pub const fn service_name(submission_service: SubmissionService) -> &'static str {
    match submission_service {
        SubmissionService::ClamavProject => "ClamAV",
        SubmissionService::MalwareBazaar => "MalwareBazaar",
        SubmissionService::VirusTotal => "VirusTotal",
    }
}

pub fn kind_text(submission_kind: SubmissionKind) -> String {
    match submission_kind {
        SubmissionKind::FalsePositive => gettext("False positive"),
        SubmissionKind::MissedMalware => gettext("Missed malware"),
        SubmissionKind::MalwareSample => gettext("Malware sample"),
    }
}

pub fn target_choice_label(submission_target: SubmissionTarget) -> String {
    match submission_target {
        SubmissionTarget::ClamavFalsePositive => gettext("Report False Positive to ClamAV"),
        SubmissionTarget::ClamavMissedMalware => gettext("Report Missed Malware to ClamAV"),
        SubmissionTarget::MalwareBazaarSample => gettext("Upload to MalwareBazaar"),
        SubmissionTarget::VirusTotalSample => gettext("Upload to VirusTotal"),
    }
}

pub fn short_hash(content_sha256: &str) -> String {
    content_sha256.chars().take(SHORT_HASH_LENGTH).collect()
}

fn settled_version_text(
    database_version: SignatureDatabaseVersion,
    versioned_text: String,
    unversioned_text: String,
) -> String {
    match database_version {
        SignatureDatabaseVersion::DailyVersion { version_number } => {
            versioned_text.replace("{version}", &version_number.to_string())
        }
        SignatureDatabaseVersion::VersionUnreadable => unversioned_text,
    }
}

fn awaiting_clamav_text() -> String {
    gettext(
        "Awaiting ClamAV review. Reviews take at least 48 hours; a later signature update shows \
         the outcome.",
    )
}

pub fn status_text(submission_state: &SubmissionState) -> String {
    match submission_state {
        SubmissionState::ClamavFalsePositive {
            review_status: FalsePositiveReview::AwaitingClamavReview,
            ..
        }
        | SubmissionState::ClamavMissedMalware {
            review_status: MissedMalwareReview::AwaitingClamavReview,
        } => awaiting_clamav_text(),
        SubmissionState::ClamavFalsePositive {
            review_status: FalsePositiveReview::FixedInDatabase { database_version },
            ..
        } => settled_version_text(
            *database_version,
            gettext("Fixed in database version {version}"),
            gettext("Fixed in the current signature database"),
        ),
        SubmissionState::ClamavMissedMalware {
            review_status: MissedMalwareReview::NowDetected { database_version },
        } => settled_version_text(
            *database_version,
            gettext("Detected since database version {version}"),
            gettext("Detected by the current signature database"),
        ),
        SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::UploadAccepted,
        } => gettext("Uploaded; waiting for MalwareBazaar to list it"),
        SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
        } => gettext("Listed on MalwareBazaar"),
        SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::SubmissionRefused { refusal_reason },
        } => gettext("MalwareBazaar refused it: {reason}")
            .replace("{reason}", &sanitize_scanner_line(refusal_reason)),
        SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued { .. },
        } => gettext("Queued for analysis on VirusTotal"),
        SubmissionState::VirusTotalSample {
            virustotal_status:
                VirusTotalSampleStatus::VirusTotalAnalysed {
                    malicious_count,
                    engine_count,
                    ..
                },
        } => ngettext(
            "{count} of {total} engine flags it as malicious",
            "{count} of {total} engines flag it as malicious",
            u32::try_from(*engine_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &malicious_count.to_string())
        .replace("{total}", &engine_count.to_string()),
        SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::SubmissionRefused { refusal_reason },
        } => gettext("VirusTotal refused it: {reason}")
            .replace("{reason}", &sanitize_scanner_line(refusal_reason)),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmittedRowView {
    pub row_title: String,
    pub row_subtitle: String,
    pub needs_attention: bool,
    pub entry_link: RemoteEntryLink,
}

pub fn submitted_row_view(
    submission_record: &SubmissionRecord,
    moment_formatters: &MomentFormatters,
) -> SubmittedRowView {
    let submission_target = submission_record.submission_state.submission_target();
    let summary_line = gettext("{service} · {kind} · {hash} · {date}")
        .replace(
            "{service}",
            service_name(submission_target.submission_service()),
        )
        .replace("{kind}", &kind_text(submission_target.submission_kind()))
        .replace(
            "{hash}",
            &short_hash(&submission_record.submitted_file.content_sha256),
        )
        .replace(
            "{date}",
            &moment_formatters.exact_moment_text(submission_record.submitted_at),
        );
    SubmittedRowView {
        row_title: sanitize_scanner_line(&submission_record.submitted_file.file_name),
        row_subtitle: format!(
            "{summary_line}\n{}",
            status_text(&submission_record.submission_state)
        ),
        needs_attention: submission_record.submission_state.submission_progress()
            == SubmissionProgress::RefusedByService,
        entry_link: submission_record
            .submission_state
            .remote_entry_link(&submission_record.submitted_file.content_sha256),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRowView {
    pub entry_id: i64,
    pub row_title: String,
    pub row_subtitle: String,
    pub send_availability: SendAvailability,
}

impl CandidateRowView {
    pub const fn allows_sending(&self) -> bool {
        matches!(self.send_availability, SendAvailability::SendableNow)
    }
}

pub fn candidate_row_view(
    entry_record: &QuarantineEntryRecord,
    uploads_in_flight: &UploadsInFlight,
) -> CandidateRowView {
    let detection_text = displayed_threat_name(&entry_record.threat_identity);
    CandidateRowView {
        entry_id: entry_record.entry_id,
        row_title: shown_file_name(&entry_record.original_path),
        row_subtitle: match &entry_record.payload_hash {
            RecordedPayloadHash::KnownSha256 { sha256_hex } => {
                format!("{detection_text} · {}", short_hash(sha256_hex))
            }
            RecordedPayloadHash::IntegrityUnknown => {
                gettext("{detection} · No usable hash, so Lazaret can't prove what it would send")
                    .replace("{detection}", &detection_text)
            }
        },
        send_availability: send_availability(&offered_target_activities(
            entry_record,
            uploads_in_flight,
        )),
    }
}

pub fn service_filter_label(service_filter: ServiceFilter) -> String {
    match service_filter {
        ServiceFilter::AllServices => gettext("All services"),
        ServiceFilter::OnlyService(submission_service) => {
            service_name(submission_service).to_owned()
        }
    }
}

pub fn progress_filter_label(progress_filter: ProgressFilter) -> String {
    match progress_filter {
        ProgressFilter::AllProgress => gettext("Any status"),
        ProgressFilter::OnlyProgress(SubmissionProgress::AwaitingOutcome) => gettext("Waiting"),
        ProgressFilter::OnlyProgress(SubmissionProgress::OutcomeKnown) => gettext("Settled"),
        ProgressFilter::OnlyProgress(SubmissionProgress::RefusedByService) => gettext("Refused"),
    }
}

pub fn filter_summary_text(submission_filters: &SubmissionFilters) -> String {
    match (
        submission_filters.service_filter,
        submission_filters.progress_filter,
    ) {
        (ServiceFilter::AllServices, ProgressFilter::AllProgress) => gettext("All submissions"),
        (ServiceFilter::AllServices, progress_filter) => progress_filter_label(progress_filter),
        (service_filter, ProgressFilter::AllProgress) => service_filter_label(service_filter),
        (service_filter, progress_filter) => format!(
            "{} · {}",
            service_filter_label(service_filter),
            progress_filter_label(progress_filter)
        ),
    }
}

pub fn empty_submissions_text(submission_listing: &SubmissionListing) -> String {
    match submission_listing {
        SubmissionListing::ListingLoading => gettext("Loading submissions…"),
        SubmissionListing::ListingLoaded(listed_submissions) if listed_submissions.is_empty() => {
            gettext("Nothing submitted")
        }
        SubmissionListing::ListingLoaded(_) => gettext("No submission matches the filters"),
        SubmissionListing::ListingFailed(history_failure) => history_failure_text(history_failure),
    }
}

pub fn empty_candidates_text(candidate_listing: &CandidateListing) -> String {
    match candidate_listing {
        CandidateListing::CandidatesLoading => gettext("Loading quarantine…"),
        CandidateListing::CandidatesLoaded(_) => gettext("Quarantine is empty"),
        CandidateListing::CandidatesFailed(quarantine_failure) => {
            describe_quarantine_failure(quarantine_failure)
        }
    }
}

fn refresh_failure_text(refresh_failure: &RemoteRefreshFailure) -> String {
    match refresh_failure {
        RemoteRefreshFailure::KeyMissing { submission_service } => {
            gettext("{service} needs a key to check uploads")
                .replace("{service}", service_name(*submission_service))
        }
        RemoteRefreshFailure::KeyUnreadable(key_failure) => describe_key_failure(key_failure),
        RemoteRefreshFailure::BazaarLookupFailed(bazaar_failure) => {
            describe_bazaar_failure(bazaar_failure)
        }
        RemoteRefreshFailure::VirusTotalLookupFailed(virustotal_failure) => {
            describe_virustotal_failure(virustotal_failure)
        }
        RemoteRefreshFailure::HistoryFailed(history_failure) => {
            history_failure_text(history_failure)
        }
    }
}

pub fn refresh_summary_text(refresh_summary: &RemoteRefreshSummary) -> String {
    let updated_text = match refresh_summary.updated_count {
        0 => gettext("No upload changed"),
        updated_count => ngettext(
            "{count} upload has a new status",
            "{count} uploads have a new status",
            u32::try_from(updated_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &updated_count.to_string()),
    };
    refresh_summary
        .refresh_failures
        .iter()
        .map(refresh_failure_text)
        .fold(updated_text, |summary_text, failure_text| {
            format!("{summary_text}. {failure_text}")
        })
}

#[cfg(test)]
mod submissions_presentation_tests {
    use std::path::PathBuf;

    use bytesize::ByteSize;
    use jiff::Timestamp;

    use super::*;
    use crate::host_services::{
        activity_history::submission_history_store::SubmittedFile,
        clamav_scanner::scanner_output_parser::ThreatIdentity,
        protection_evidence::protection_evidence_fixtures::english_formatters,
        quarantine_vault::quarantine_entry_database::StoredDetectionDate,
    };

    fn record_with(submission_state: SubmissionState) -> SubmissionRecord {
        SubmissionRecord {
            submitted_file: SubmittedFile {
                content_sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                    .to_owned(),
                file_name: "invoice.exe".to_owned(),
            },
            submitted_at: Timestamp::constant(1_793_869_222, 0),
            submission_state,
        }
    }

    #[test]
    fn a_submitted_row_shows_service_kind_hash_date_and_status() {
        let row_view = submitted_row_view(
            &record_with(SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Trojan.Agent".to_owned(),
                review_status: FalsePositiveReview::FixedInDatabase {
                    database_version: SignatureDatabaseVersion::DailyVersion {
                        version_number: 28_174,
                    },
                },
            }),
            english_formatters(),
        );
        assert_eq!(row_view.row_title, "invoice.exe");
        assert!(
            row_view
                .row_subtitle
                .starts_with("ClamAV · False positive · 275a021bbfb6 · ")
        );
        assert!(
            row_view
                .row_subtitle
                .ends_with("\nFixed in database version 28174")
        );
        assert!(!row_view.needs_attention);
        assert_eq!(row_view.entry_link, RemoteEntryLink::NoRemoteEntry);
    }

    #[test]
    fn waiting_clamav_reports_mention_the_review_time() {
        assert!(
            status_text(&SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            })
            .contains("at least 48 hours")
        );
    }

    #[test]
    fn refused_uploads_need_attention_and_link_nowhere() {
        let row_view = submitted_row_view(
            &record_with(SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused {
                    refusal_reason: "file_expected".to_owned(),
                },
            }),
            english_formatters(),
        );
        assert!(row_view.needs_attention);
        assert!(row_view.row_subtitle.contains("refused it: file_expected"));
        assert_eq!(row_view.entry_link, RemoteEntryLink::NoRemoteEntry);
    }

    #[test]
    fn analysed_uploads_show_the_engine_counts_and_link_to_the_report() {
        let row_view = submitted_row_view(
            &record_with(SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed {
                    analysis_id: "analysis-1".to_owned(),
                    malicious_count: 41,
                    engine_count: 68,
                },
            }),
            english_formatters(),
        );
        assert!(
            row_view
                .row_subtitle
                .contains("41 of 68 engines flag it as malicious")
        );
        assert!(matches!(
            row_view.entry_link,
            RemoteEntryLink::RemoteEntryAt { entry_url } if entry_url.starts_with("https://www.virustotal.com/gui/file/")
        ));
    }

    #[test]
    fn an_unhashed_candidate_cannot_be_sent() {
        let candidate_view = candidate_row_view(
            &QuarantineEntryRecord {
                entry_id: 5,
                original_path: PathBuf::from("/home/user/old.bin"),
                quarantine_path: PathBuf::from("/vault/old"),
                threat_identity: ThreatIdentity::Signature {
                    signature_name: "Legacy.Test".to_owned(),
                },
                detection_date: StoredDetectionDate::from("2020-01-01T00:00:00Z".to_owned()),
                file_size: ByteSize::b(3),
                payload_hash: RecordedPayloadHash::IntegrityUnknown,
                original_permissions: 0o644,
            },
            &UploadsInFlight::default(),
        );
        assert_eq!(candidate_view.row_title, "old.bin");
        assert_eq!(
            candidate_view.send_availability,
            SendAvailability::NothingToSend
        );
        assert!(candidate_view.row_subtitle.contains("No usable hash"));
    }

    #[test]
    fn a_refresh_summary_lists_what_changed_and_what_failed() {
        assert_eq!(
            refresh_summary_text(&RemoteRefreshSummary {
                updated_count: 2,
                refresh_failures: vec![RemoteRefreshFailure::KeyMissing {
                    submission_service: SubmissionService::VirusTotal,
                }],
            }),
            "2 uploads have a new status. VirusTotal needs a key to check uploads"
        );
    }
}
