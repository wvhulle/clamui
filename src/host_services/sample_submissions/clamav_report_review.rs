use tokio::task::spawn_blocking;

use crate::host_services::{
    activity_history::{
        activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        submission_history_store::{
            FalsePositiveReview, MissedMalwareReview, SignatureDatabaseVersion, SubmissionState,
        },
    },
    clamav_scanner::content_verdict::ContentVerdict,
    protection_evidence::clamav_engine_evidence::newest_disk_signature_version,
};

#[derive(Clone, Debug)]
pub struct RecheckedContent {
    pub content_sha256: String,
    pub content_verdict: ContentVerdict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewChange {
    ReviewUnchanged,
    ReviewSettled(SubmissionState),
}

pub fn review_after_recheck(
    submission_state: &SubmissionState,
    content_verdict: &ContentVerdict,
    database_version: SignatureDatabaseVersion,
) -> ReviewChange {
    match (submission_state, content_verdict) {
        (
            SubmissionState::ClamavFalsePositive {
                reported_signature,
                review_status: FalsePositiveReview::AwaitingClamavReview,
            },
            ContentVerdict::NoLongerDetected,
        ) => ReviewChange::ReviewSettled(SubmissionState::ClamavFalsePositive {
            reported_signature: reported_signature.clone(),
            review_status: FalsePositiveReview::FixedInDatabase { database_version },
        }),
        (
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            },
            ContentVerdict::StillDetected { .. },
        ) => ReviewChange::ReviewSettled(SubmissionState::ClamavMissedMalware {
            review_status: MissedMalwareReview::NowDetected { database_version },
        }),
        (
            SubmissionState::ClamavFalsePositive { .. }
            | SubmissionState::ClamavMissedMalware { .. }
            | SubmissionState::MalwareBazaarSample { .. }
            | SubmissionState::VirusTotalSample { .. },
            ContentVerdict::NoLongerDetected
            | ContentVerdict::StillDetected { .. }
            | ContentVerdict::VerdictUnavailable(_),
        ) => ReviewChange::ReviewUnchanged,
    }
}

pub async fn current_database_version() -> SignatureDatabaseVersion {
    match spawn_blocking(newest_disk_signature_version).await {
        Ok(Some(version_number)) => SignatureDatabaseVersion::DailyVersion { version_number },
        Ok(None) | Err(_) => SignatureDatabaseVersion::VersionUnreadable,
    }
}

pub async fn settle_clamav_reviews(
    activity_history: &ActivityHistory,
    rechecked_contents: &[RecheckedContent],
    database_version: SignatureDatabaseVersion,
) -> Result<usize, ActivityHistoryFailure> {
    let mut settled_count = 0;
    for listed_submission in activity_history.list_submissions().await? {
        let review_changes = rechecked_contents
            .iter()
            .filter(|rechecked_content| {
                rechecked_content
                    .content_sha256
                    .eq_ignore_ascii_case(&listed_submission.submitted_file.content_sha256)
            })
            .map(|rechecked_content| {
                review_after_recheck(
                    &listed_submission.submission_state,
                    &rechecked_content.content_verdict,
                    database_version,
                )
            });
        if let Some(ReviewChange::ReviewSettled(settled_state)) = review_changes
            .into_iter()
            .find(|review_change| matches!(review_change, ReviewChange::ReviewSettled(_)))
        {
            activity_history
                .update_submission_state(
                    &listed_submission.submitted_file.content_sha256,
                    settled_state,
                )
                .await?;
            settled_count += 1;
        }
    }
    Ok(settled_count)
}

#[cfg(test)]
mod clamav_report_review_tests {
    use std::sync::Arc;

    use jiff::Timestamp;

    use super::*;
    use crate::host_services::{
        activity_history::submission_history_store::{
            BazaarSampleStatus, NewSubmission, SubmittedFile,
        },
        clamav_scanner::content_verdict::VerdictFailure,
    };

    const DAILY_VERSION: SignatureDatabaseVersion = SignatureDatabaseVersion::DailyVersion {
        version_number: 28_174,
    };

    fn awaiting_false_positive() -> SubmissionState {
        SubmissionState::ClamavFalsePositive {
            reported_signature: "Win.Trojan.Agent".to_owned(),
            review_status: FalsePositiveReview::AwaitingClamavReview,
        }
    }

    fn awaiting_missed_malware() -> SubmissionState {
        SubmissionState::ClamavMissedMalware {
            review_status: MissedMalwareReview::AwaitingClamavReview,
        }
    }

    fn still_detected() -> ContentVerdict {
        ContentVerdict::StillDetected {
            detection_name: "Win.Trojan.Agent".to_owned(),
        }
    }

    #[test]
    fn a_false_positive_is_fixed_once_the_file_is_no_longer_detected() {
        assert_eq!(
            review_after_recheck(
                &awaiting_false_positive(),
                &ContentVerdict::NoLongerDetected,
                DAILY_VERSION
            ),
            ReviewChange::ReviewSettled(SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Trojan.Agent".to_owned(),
                review_status: FalsePositiveReview::FixedInDatabase {
                    database_version: DAILY_VERSION
                },
            })
        );
        assert_eq!(
            review_after_recheck(&awaiting_false_positive(), &still_detected(), DAILY_VERSION),
            ReviewChange::ReviewUnchanged
        );
    }

    #[test]
    fn missed_malware_is_now_detected_once_a_signature_matches() {
        assert_eq!(
            review_after_recheck(&awaiting_missed_malware(), &still_detected(), DAILY_VERSION),
            ReviewChange::ReviewSettled(SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::NowDetected {
                    database_version: DAILY_VERSION
                },
            })
        );
        assert_eq!(
            review_after_recheck(
                &awaiting_missed_malware(),
                &ContentVerdict::NoLongerDetected,
                DAILY_VERSION
            ),
            ReviewChange::ReviewUnchanged
        );
    }

    #[test]
    fn a_failed_check_and_other_services_never_settle_a_review() {
        let failed_check =
            ContentVerdict::VerdictUnavailable(Arc::new(VerdictFailure::VerdictTimedOut));
        assert_eq!(
            review_after_recheck(&awaiting_false_positive(), &failed_check, DAILY_VERSION),
            ReviewChange::ReviewUnchanged
        );
        assert_eq!(
            review_after_recheck(
                &SubmissionState::MalwareBazaarSample {
                    bazaar_status: BazaarSampleStatus::UploadAccepted,
                },
                &ContentVerdict::NoLongerDetected,
                DAILY_VERSION
            ),
            ReviewChange::ReviewUnchanged
        );
    }

    #[tokio::test]
    async fn rechecked_quarantine_content_settles_matching_reports_only() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let activity_history =
            ActivityHistory::at_database_path(temporary_root.path().join("lazaret.db"));
        let reported_hash = "a".repeat(64);
        let other_hash = "b".repeat(64);
        for (content_sha256, submission_state) in [
            (&reported_hash, awaiting_false_positive()),
            (&other_hash, awaiting_false_positive()),
        ] {
            activity_history
                .record_submission(NewSubmission {
                    submitted_file: SubmittedFile {
                        content_sha256: content_sha256.clone(),
                        file_name: "report.exe".to_owned(),
                    },
                    submitted_at: Timestamp::constant(100, 0),
                    submission_state,
                })
                .await
                .expect("recorded");
        }
        let settled_count = settle_clamav_reviews(
            &activity_history,
            &[RecheckedContent {
                content_sha256: reported_hash.to_ascii_uppercase(),
                content_verdict: ContentVerdict::NoLongerDetected,
            }],
            DAILY_VERSION,
        )
        .await
        .expect("settled");
        assert_eq!(settled_count, 1);
        let listed_submissions = activity_history.list_submissions().await.expect("listed");
        let state_of = |content_sha256: &str| {
            listed_submissions
                .iter()
                .find(|listed_submission| {
                    listed_submission.submitted_file.content_sha256 == content_sha256
                })
                .map(|listed_submission| listed_submission.submission_state.clone())
        };
        assert_eq!(
            state_of(&reported_hash),
            Some(SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Trojan.Agent".to_owned(),
                review_status: FalsePositiveReview::FixedInDatabase {
                    database_version: DAILY_VERSION
                },
            })
        );
        assert_eq!(state_of(&other_hash), Some(awaiting_false_positive()));
    }
}
