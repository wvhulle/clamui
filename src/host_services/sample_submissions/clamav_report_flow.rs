use jiff::Timestamp;

use crate::host_services::{
    activity_history::{
        activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        submission_history_store::{
            EarlierSubmission, FalsePositiveReview, MissedMalwareReview, NewSubmission,
            SubmissionRecord, SubmissionRecording, SubmissionState, SubmissionTarget,
        },
    },
    clamav_programs::clamav_report_submission::{
        ClamavReport, ClamavReportKind, ClamavReportRequest, ClamsubmitFailure,
        submit_clamav_report,
    },
    quarantine_vault::quarantine_entry_database::QuarantineVault,
    sample_submissions::submission_samples::{
        SampleReadFailure, SubmissionSample, read_submitted_content,
    },
};

#[derive(Debug)]
pub enum ClamavReportAttempt {
    ReportRecorded(SubmissionRecord),
    AlreadyReported(SubmissionRecord),
    SampleUnreadable(SampleReadFailure),
    ReportNotSent(ClamsubmitFailure),
    HistoryUnavailable(ActivityHistoryFailure),
    ReportSentWithoutRecord(ActivityHistoryFailure),
}

pub const fn clamav_report_target(report_kind: &ClamavReportKind) -> SubmissionTarget {
    match report_kind {
        ClamavReportKind::FalsePositive { .. } => SubmissionTarget::ClamavFalsePositive,
        ClamavReportKind::MissedMalware => SubmissionTarget::ClamavMissedMalware,
    }
}

pub fn awaiting_review_state(report_kind: &ClamavReportKind) -> SubmissionState {
    match report_kind {
        ClamavReportKind::FalsePositive { detection_name } => {
            SubmissionState::ClamavFalsePositive {
                reported_signature: detection_name.clone(),
                review_status: FalsePositiveReview::AwaitingClamavReview,
            }
        }
        ClamavReportKind::MissedMalware => SubmissionState::ClamavMissedMalware {
            review_status: MissedMalwareReview::AwaitingClamavReview,
        },
    }
}

pub async fn read_clamav_report_sample(
    quarantine_vault: &QuarantineVault,
    report_request: &ClamavReportRequest,
) -> Result<SubmissionSample, SampleReadFailure> {
    read_submitted_content(quarantine_vault, &report_request.submitted_content).await
}

pub async fn send_read_clamav_report(
    activity_history: &ActivityHistory,
    clamav_report: &ClamavReport,
    submission_sample: SubmissionSample,
) -> ClamavReportAttempt {
    let report_kind = &clamav_report.report_kind;
    match activity_history
        .find_earlier_submission(
            &submission_sample.submitted_file.content_sha256,
            clamav_report_target(report_kind),
        )
        .await
    {
        Ok(EarlierSubmission::SubmittedBefore(earlier_submission)) => {
            return ClamavReportAttempt::AlreadyReported(earlier_submission);
        }
        Ok(EarlierSubmission::NotSubmittedBefore) => {}
        Err(history_failure) => return ClamavReportAttempt::HistoryUnavailable(history_failure),
    }
    if let Err(clamsubmit_failure) =
        submit_clamav_report(clamav_report, submission_sample.sample_bytes).await
    {
        return ClamavReportAttempt::ReportNotSent(clamsubmit_failure);
    }
    match activity_history
        .record_submission(NewSubmission {
            submitted_file: submission_sample.submitted_file,
            submitted_at: Timestamp::now(),
            submission_state: awaiting_review_state(report_kind),
        })
        .await
    {
        Ok(SubmissionRecording::SubmissionRecorded(recorded_submission)) => {
            ClamavReportAttempt::ReportRecorded(recorded_submission)
        }
        Ok(SubmissionRecording::AlreadySubmitted(earlier_submission)) => {
            ClamavReportAttempt::AlreadyReported(earlier_submission)
        }
        Err(history_failure) => ClamavReportAttempt::ReportSentWithoutRecord(history_failure),
    }
}

#[cfg(test)]
mod clamav_report_flow_tests {
    use super::*;
    use crate::host_services::{
        activity_history::submission_history_store::SubmittedFile,
        clamav_programs::clamav_report_submission::{ReporterContact, SubmittedContent},
        sample_submissions::submission_samples::content_sha256_text,
    };

    #[test]
    fn each_report_kind_starts_awaiting_review_with_its_own_target() {
        let false_positive = ClamavReportKind::FalsePositive {
            detection_name: "Win.Trojan.Agent".to_owned(),
        };
        assert_eq!(
            clamav_report_target(&false_positive),
            SubmissionTarget::ClamavFalsePositive
        );
        assert_eq!(
            awaiting_review_state(&false_positive),
            SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Trojan.Agent".to_owned(),
                review_status: FalsePositiveReview::AwaitingClamavReview,
            }
        );
        assert_eq!(
            clamav_report_target(&ClamavReportKind::MissedMalware),
            SubmissionTarget::ClamavMissedMalware
        );
        assert_eq!(
            awaiting_review_state(&ClamavReportKind::MissedMalware).submission_target(),
            SubmissionTarget::ClamavMissedMalware
        );
    }

    #[tokio::test]
    async fn a_file_already_reported_is_not_sent_again() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let activity_history =
            ActivityHistory::at_database_path(temporary_root.path().join("lazaret.db"));
        let quarantine_vault = QuarantineVault::open_vault(
            temporary_root.path().join("lazaret.db"),
            temporary_root.path().join("quarantine"),
        )
        .await
        .expect("vault");
        let picked_path = temporary_root.path().join("missed.bin");
        std::fs::write(&picked_path, b"missed sample").expect("picked file");
        activity_history
            .record_submission(NewSubmission {
                submitted_file: SubmittedFile {
                    content_sha256: content_sha256_text(b"missed sample"),
                    file_name: "missed.bin".to_owned(),
                },
                submitted_at: Timestamp::constant(100, 0),
                submission_state: awaiting_review_state(&ClamavReportKind::MissedMalware),
            })
            .await
            .expect("earlier report");
        let report_request = ClamavReportRequest {
            clamav_report: ClamavReport {
                reporter_contact: ReporterContact {
                    reporter_name: "Alex Doe".to_owned(),
                    reporter_email: "alex@example.org".to_owned(),
                },
                report_kind: ClamavReportKind::MissedMalware,
            },
            submitted_content: SubmittedContent::FileOnDisk {
                file_path: picked_path,
            },
        };
        let submission_sample = read_clamav_report_sample(&quarantine_vault, &report_request)
            .await
            .expect("picked sample");
        assert_eq!(
            submission_sample.submitted_file.content_sha256,
            content_sha256_text(b"missed sample")
        );
        let report_attempt = send_read_clamav_report(
            &activity_history,
            &report_request.clamav_report,
            submission_sample,
        )
        .await;
        assert!(matches!(
            report_attempt,
            ClamavReportAttempt::AlreadyReported(earlier_submission)
                if earlier_submission.submitted_at == Timestamp::constant(100, 0)
        ));
    }
}
