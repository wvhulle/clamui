use crate::host_services::{
    activity_history::{
        activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        submission_history_store::{
            BazaarSampleStatus, SubmissionRecord, SubmissionService, SubmissionState,
            VirusTotalSampleStatus,
        },
    },
    sample_submissions::{
        bazaar_sample_upload::refreshed_bazaar_state,
        virustotal_sample_upload::refreshed_virustotal_state,
    },
    threat_intel::{
        malware_bazaar_client::MalwareBazaarFailure,
        service_key_storage::{
            KeyStorageFailure, ResolvedApiKey, ThreatIntelService, read_api_key,
        },
        virustotal_api_client::{VirusTotalClient, VirusTotalFailure},
    },
};

#[derive(Debug)]
pub enum RemoteRefreshFailure {
    KeyMissing {
        submission_service: SubmissionService,
    },
    KeyUnreadable(KeyStorageFailure),
    BazaarLookupFailed(MalwareBazaarFailure),
    VirusTotalLookupFailed(VirusTotalFailure),
    HistoryFailed(ActivityHistoryFailure),
}

#[derive(Debug)]
pub struct RemoteRefreshSummary {
    pub updated_count: usize,
    pub refresh_failures: Vec<RemoteRefreshFailure>,
}

pub const fn awaits_remote_service(submission_state: &SubmissionState) -> bool {
    matches!(
        submission_state,
        SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::UploadAccepted,
        } | SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued { .. },
        }
    )
}

async fn service_key(
    threat_intel_service: ThreatIntelService,
    submission_service: SubmissionService,
) -> Result<String, RemoteRefreshFailure> {
    match read_api_key(threat_intel_service).await {
        Ok(ResolvedApiKey::FromKeyFile(api_key) | ResolvedApiKey::FromKeyring(api_key)) => {
            Ok(api_key)
        }
        Ok(ResolvedApiKey::NotConfigured) => {
            Err(RemoteRefreshFailure::KeyMissing { submission_service })
        }
        Err(key_failure) => Err(RemoteRefreshFailure::KeyUnreadable(key_failure)),
    }
}

async fn refreshed_bazaar_records(
    awaiting_records: &[&SubmissionRecord],
) -> Result<Vec<SubmissionRecord>, RemoteRefreshFailure> {
    let auth_key = service_key(
        ThreatIntelService::AbuseChService,
        SubmissionService::MalwareBazaar,
    )
    .await?;
    let mut refreshed_records = Vec::new();
    for awaiting_record in awaiting_records {
        refreshed_records.push(SubmissionRecord {
            submission_state: refreshed_bazaar_state(&auth_key, awaiting_record)
                .await
                .map_err(RemoteRefreshFailure::BazaarLookupFailed)?,
            ..(*awaiting_record).clone()
        });
    }
    Ok(refreshed_records)
}

async fn refreshed_virustotal_records(
    awaiting_records: &[&SubmissionRecord],
) -> Result<Vec<SubmissionRecord>, RemoteRefreshFailure> {
    let virustotal_client = VirusTotalClient::with_api_key(
        service_key(
            ThreatIntelService::VirusTotalService,
            SubmissionService::VirusTotal,
        )
        .await?,
    )
    .map_err(RemoteRefreshFailure::VirusTotalLookupFailed)?;
    let mut refreshed_records = Vec::new();
    for awaiting_record in awaiting_records {
        refreshed_records.push(SubmissionRecord {
            submission_state: refreshed_virustotal_state(&virustotal_client, awaiting_record)
                .await
                .map_err(RemoteRefreshFailure::VirusTotalLookupFailed)?,
            ..(*awaiting_record).clone()
        });
    }
    Ok(refreshed_records)
}

fn awaiting_records_of(
    listed_submissions: &[SubmissionRecord],
    submission_service: SubmissionService,
) -> Vec<&SubmissionRecord> {
    listed_submissions
        .iter()
        .filter(|listed_submission| {
            awaits_remote_service(&listed_submission.submission_state)
                && listed_submission
                    .submission_state
                    .submission_target()
                    .submission_service()
                    == submission_service
        })
        .collect()
}

pub async fn refresh_remote_statuses(activity_history: &ActivityHistory) -> RemoteRefreshSummary {
    let listed_submissions = match activity_history.list_submissions().await {
        Ok(listed_submissions) => listed_submissions,
        Err(history_failure) => {
            return RemoteRefreshSummary {
                updated_count: 0,
                refresh_failures: vec![RemoteRefreshFailure::HistoryFailed(history_failure)],
            };
        }
    };
    let bazaar_records = awaiting_records_of(&listed_submissions, SubmissionService::MalwareBazaar);
    let virustotal_records =
        awaiting_records_of(&listed_submissions, SubmissionService::VirusTotal);
    let mut refresh_outcomes = Vec::new();
    if !bazaar_records.is_empty() {
        refresh_outcomes.push(refreshed_bazaar_records(&bazaar_records).await);
    }
    if !virustotal_records.is_empty() {
        refresh_outcomes.push(refreshed_virustotal_records(&virustotal_records).await);
    }
    let mut refresh_summary = RemoteRefreshSummary {
        updated_count: 0,
        refresh_failures: Vec::new(),
    };
    for refresh_outcome in refresh_outcomes {
        match refresh_outcome {
            Ok(refreshed_records) => {
                for refreshed_record in refreshed_records {
                    if awaits_remote_service(&refreshed_record.submission_state) {
                        continue;
                    }
                    match activity_history
                        .update_submission_state(
                            &refreshed_record.submitted_file.content_sha256,
                            refreshed_record.submission_state,
                        )
                        .await
                    {
                        Ok(()) => refresh_summary.updated_count += 1,
                        Err(history_failure) => refresh_summary
                            .refresh_failures
                            .push(RemoteRefreshFailure::HistoryFailed(history_failure)),
                    }
                }
            }
            Err(refresh_failure) => refresh_summary.refresh_failures.push(refresh_failure),
        }
    }
    refresh_summary
}

#[cfg(test)]
mod remote_status_refresh_tests {
    use super::*;
    use crate::host_services::activity_history::submission_history_store::{
        FalsePositiveReview, MissedMalwareReview,
    };

    #[test]
    fn only_uploads_waiting_on_their_service_are_refreshed() {
        assert!(awaits_remote_service(
            &SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::UploadAccepted,
            }
        ));
        assert!(awaits_remote_service(&SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                analysis_id: "analysis-1".to_owned(),
            },
        }));
        [
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            },
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed {
                    analysis_id: "analysis-1".to_owned(),
                    malicious_count: 1,
                    engine_count: 60,
                },
            },
            SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Trojan.Agent".to_owned(),
                review_status: FalsePositiveReview::AwaitingClamavReview,
            },
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            },
        ]
        .iter()
        .for_each(|settled_state| assert!(!awaits_remote_service(settled_state)));
    }

    #[tokio::test]
    async fn nothing_to_refresh_contacts_no_service() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let refresh_summary = refresh_remote_statuses(&ActivityHistory::at_database_path(
            temporary_root.path().join("lazaret.db"),
        ))
        .await;
        assert_eq!(refresh_summary.updated_count, 0);
        assert!(refresh_summary.refresh_failures.is_empty());
    }
}
