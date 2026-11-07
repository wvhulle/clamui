use jiff::Timestamp;
use turso::{Connection, Row, Value};

use crate::host_services::{
    activity_history::activity_history_database::{ActivityHistory, ActivityHistoryFailure},
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
};

const SUBMISSION_COLUMNS: &str = "content_sha256, submission_service, submission_kind, file_name, \
                                  submitted_at_unix, submission_status";
const SUBMISSION_KEY_FILTER: &str =
    "content_sha256 = ?1 AND submission_service = ?2 AND submission_kind = ?3";
const DETAIL_TABLES: [&str; 6] = [
    "settled_database_versions",
    "false_positive_signatures",
    "clamav_review_settlements",
    "virustotal_analyses",
    "virustotal_verdicts",
    "upload_refusals",
];
const MALWARE_BAZAAR_SAMPLE_URL: &str = "https://bazaar.abuse.ch/sample";
const VIRUSTOTAL_FILE_URL: &str = "https://www.virustotal.com/gui/file";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionService {
    ClamavProject,
    MalwareBazaar,
    VirusTotal,
}

pub const ALL_SUBMISSION_SERVICES: [SubmissionService; 3] = [
    SubmissionService::ClamavProject,
    SubmissionService::MalwareBazaar,
    SubmissionService::VirusTotal,
];

impl SubmissionService {
    const fn stored_service_text(self) -> &'static str {
        match self {
            Self::ClamavProject => "clamav",
            Self::MalwareBazaar => "malware_bazaar",
            Self::VirusTotal => "virustotal",
        }
    }

    fn from_stored_service_text(stored_text: &str) -> Result<Self, ActivityHistoryFailure> {
        ALL_SUBMISSION_SERVICES
            .into_iter()
            .find(|submission_service| submission_service.stored_service_text() == stored_text)
            .ok_or(ActivityHistoryFailure::StoredSubmissionUnreadable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionKind {
    FalsePositive,
    MissedMalware,
    MalwareSample,
}

impl SubmissionKind {
    const fn stored_kind_text(self) -> &'static str {
        match self {
            Self::FalsePositive => "false_positive",
            Self::MissedMalware => "missed_malware",
            Self::MalwareSample => "malware_sample",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionTarget {
    ClamavFalsePositive,
    ClamavMissedMalware,
    MalwareBazaarSample,
    VirusTotalSample,
}

pub const ALL_SUBMISSION_TARGETS: [SubmissionTarget; 4] = [
    SubmissionTarget::ClamavFalsePositive,
    SubmissionTarget::ClamavMissedMalware,
    SubmissionTarget::MalwareBazaarSample,
    SubmissionTarget::VirusTotalSample,
];

impl SubmissionTarget {
    pub const fn submission_service(self) -> SubmissionService {
        match self {
            Self::ClamavFalsePositive | Self::ClamavMissedMalware => {
                SubmissionService::ClamavProject
            }
            Self::MalwareBazaarSample => SubmissionService::MalwareBazaar,
            Self::VirusTotalSample => SubmissionService::VirusTotal,
        }
    }

    pub const fn submission_kind(self) -> SubmissionKind {
        match self {
            Self::ClamavFalsePositive => SubmissionKind::FalsePositive,
            Self::ClamavMissedMalware => SubmissionKind::MissedMalware,
            Self::MalwareBazaarSample | Self::VirusTotalSample => SubmissionKind::MalwareSample,
        }
    }

    fn from_stored_columns(
        stored_service: &str,
        stored_kind: &str,
    ) -> Result<Self, ActivityHistoryFailure> {
        let submission_service = SubmissionService::from_stored_service_text(stored_service)?;
        ALL_SUBMISSION_TARGETS
            .into_iter()
            .find(|submission_target| {
                submission_target.submission_service() == submission_service
                    && submission_target.submission_kind().stored_kind_text() == stored_kind
            })
            .ok_or(ActivityHistoryFailure::StoredSubmissionUnreadable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureDatabaseVersion {
    DailyVersion { version_number: u64 },
    VersionUnreadable,
}

impl SignatureDatabaseVersion {
    fn from_column_value(column_value: Value) -> Result<Self, ActivityHistoryFailure> {
        match column_value {
            Value::Null => Ok(Self::VersionUnreadable),
            Value::Integer(stored_version) => u64::try_from(stored_version)
                .map(|version_number| Self::DailyVersion { version_number })
                .map_err(|_negative_version| ActivityHistoryFailure::StoredSubmissionUnreadable),
            Value::Text(_) | Value::Real(_) | Value::Blob(_) => {
                Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FalsePositiveReview {
    AwaitingClamavReview,
    FixedInDatabase {
        database_version: SignatureDatabaseVersion,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MissedMalwareReview {
    AwaitingClamavReview,
    NowDetected {
        database_version: SignatureDatabaseVersion,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BazaarSampleStatus {
    UploadAccepted,
    ListedOnMalwareBazaar,
    SubmissionRefused { refusal_reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VirusTotalSampleStatus {
    VirusTotalAnalysisQueued {
        analysis_id: String,
    },
    VirusTotalAnalysed {
        analysis_id: String,
        malicious_count: u64,
        engine_count: u64,
    },
    SubmissionRefused {
        refusal_reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionState {
    ClamavFalsePositive {
        reported_signature: String,
        review_status: FalsePositiveReview,
    },
    ClamavMissedMalware {
        review_status: MissedMalwareReview,
    },
    MalwareBazaarSample {
        bazaar_status: BazaarSampleStatus,
    },
    VirusTotalSample {
        virustotal_status: VirusTotalSampleStatus,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionProgress {
    AwaitingOutcome,
    OutcomeKnown,
    RefusedByService,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteEntryLink {
    NoRemoteEntry,
    RemoteEntryAt { entry_url: String },
}

enum StatusDetail<'state> {
    ReportedSignature {
        reported_signature: &'state str,
    },
    ReviewSettlement {
        database_version: SignatureDatabaseVersion,
    },
    VirusTotalAnalysis {
        analysis_id: &'state str,
    },
    VirusTotalVerdict {
        malicious_count: u64,
        engine_count: u64,
    },
    UploadRefusal {
        refusal_reason: &'state str,
    },
}

impl SubmissionState {
    pub const fn submission_target(&self) -> SubmissionTarget {
        match self {
            Self::ClamavFalsePositive { .. } => SubmissionTarget::ClamavFalsePositive,
            Self::ClamavMissedMalware { .. } => SubmissionTarget::ClamavMissedMalware,
            Self::MalwareBazaarSample { .. } => SubmissionTarget::MalwareBazaarSample,
            Self::VirusTotalSample { .. } => SubmissionTarget::VirusTotalSample,
        }
    }

    pub const fn submission_progress(&self) -> SubmissionProgress {
        match self {
            Self::ClamavFalsePositive {
                review_status: FalsePositiveReview::AwaitingClamavReview,
                ..
            }
            | Self::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            }
            | Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::UploadAccepted,
            }
            | Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued { .. },
            } => SubmissionProgress::AwaitingOutcome,
            Self::ClamavFalsePositive {
                review_status: FalsePositiveReview::FixedInDatabase { .. },
                ..
            }
            | Self::ClamavMissedMalware {
                review_status: MissedMalwareReview::NowDetected { .. },
            }
            | Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            }
            | Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed { .. },
            } => SubmissionProgress::OutcomeKnown,
            Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused { .. },
            }
            | Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::SubmissionRefused { .. },
            } => SubmissionProgress::RefusedByService,
        }
    }

    pub fn remote_entry_link(&self, content_sha256: &str) -> RemoteEntryLink {
        match self {
            Self::ClamavFalsePositive { .. }
            | Self::ClamavMissedMalware { .. }
            | Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused { .. },
            }
            | Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::SubmissionRefused { .. },
            } => RemoteEntryLink::NoRemoteEntry,
            Self::MalwareBazaarSample {
                bazaar_status:
                    BazaarSampleStatus::UploadAccepted | BazaarSampleStatus::ListedOnMalwareBazaar,
            } => RemoteEntryLink::RemoteEntryAt {
                entry_url: format!("{MALWARE_BAZAAR_SAMPLE_URL}/{content_sha256}/"),
            },
            Self::VirusTotalSample {
                virustotal_status:
                    VirusTotalSampleStatus::VirusTotalAnalysisQueued { .. }
                    | VirusTotalSampleStatus::VirusTotalAnalysed { .. },
            } => RemoteEntryLink::RemoteEntryAt {
                entry_url: format!("{VIRUSTOTAL_FILE_URL}/{content_sha256}"),
            },
        }
    }

    const fn stored_status_name(&self) -> &'static str {
        match self {
            Self::ClamavFalsePositive {
                review_status: FalsePositiveReview::AwaitingClamavReview,
                ..
            }
            | Self::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            } => "awaiting_review",
            Self::ClamavFalsePositive {
                review_status: FalsePositiveReview::FixedInDatabase { .. },
                ..
            } => "fixed_in_database",
            Self::ClamavMissedMalware {
                review_status: MissedMalwareReview::NowDetected { .. },
            } => "now_detected",
            Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::UploadAccepted,
            } => "upload_accepted",
            Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            } => "listed",
            Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued { .. },
            } => "analysis_queued",
            Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed { .. },
            } => "analysed",
            Self::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused { .. },
            }
            | Self::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::SubmissionRefused { .. },
            } => "refused",
        }
    }

    fn status_details(&self) -> Vec<StatusDetail<'_>> {
        match self {
            Self::ClamavFalsePositive {
                reported_signature,
                review_status,
            } => [StatusDetail::ReportedSignature { reported_signature }]
                .into_iter()
                .chain(match review_status {
                    FalsePositiveReview::AwaitingClamavReview => None,
                    FalsePositiveReview::FixedInDatabase { database_version } => {
                        Some(StatusDetail::ReviewSettlement {
                            database_version: *database_version,
                        })
                    }
                })
                .collect(),
            Self::ClamavMissedMalware { review_status } => match review_status {
                MissedMalwareReview::AwaitingClamavReview => Vec::new(),
                MissedMalwareReview::NowDetected { database_version } => {
                    vec![StatusDetail::ReviewSettlement {
                        database_version: *database_version,
                    }]
                }
            },
            Self::MalwareBazaarSample { bazaar_status } => match bazaar_status {
                BazaarSampleStatus::UploadAccepted | BazaarSampleStatus::ListedOnMalwareBazaar => {
                    Vec::new()
                }
                BazaarSampleStatus::SubmissionRefused { refusal_reason } => {
                    vec![StatusDetail::UploadRefusal { refusal_reason }]
                }
            },
            Self::VirusTotalSample { virustotal_status } => match virustotal_status {
                VirusTotalSampleStatus::VirusTotalAnalysisQueued { analysis_id } => {
                    vec![StatusDetail::VirusTotalAnalysis { analysis_id }]
                }
                VirusTotalSampleStatus::VirusTotalAnalysed {
                    analysis_id,
                    malicious_count,
                    engine_count,
                } => vec![
                    StatusDetail::VirusTotalAnalysis { analysis_id },
                    StatusDetail::VirusTotalVerdict {
                        malicious_count: *malicious_count,
                        engine_count: *engine_count,
                    },
                ],
                VirusTotalSampleStatus::SubmissionRefused { refusal_reason } => {
                    vec![StatusDetail::UploadRefusal { refusal_reason }]
                }
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmittedFile {
    pub content_sha256: String,
    pub file_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSubmission {
    pub submitted_file: SubmittedFile,
    pub submitted_at: Timestamp,
    pub submission_state: SubmissionState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionRecord {
    pub submitted_file: SubmittedFile,
    pub submitted_at: Timestamp,
    pub submission_state: SubmissionState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionRecording {
    SubmissionRecorded(SubmissionRecord),
    AlreadySubmitted(SubmissionRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EarlierSubmission {
    NotSubmittedBefore,
    SubmittedBefore(SubmissionRecord),
}

fn key_values(content_sha256: &str, submission_target: SubmissionTarget) -> Vec<Value> {
    vec![
        Value::Text(content_sha256.to_ascii_lowercase()),
        Value::Text(
            submission_target
                .submission_service()
                .stored_service_text()
                .to_owned(),
        ),
        Value::Text(
            submission_target
                .submission_kind()
                .stored_kind_text()
                .to_owned(),
        ),
    ]
}

fn stored_count(count_value: u64) -> Value {
    Value::Integer(i64::try_from(count_value).unwrap_or(i64::MAX))
}

fn count_from_stored(stored_count: i64) -> Result<u64, ActivityHistoryFailure> {
    u64::try_from(stored_count)
        .map_err(|_negative_count| ActivityHistoryFailure::StoredSubmissionUnreadable)
}

async fn first_detail_row(
    database_connection: &Connection,
    detail_query: &str,
    content_sha256: &str,
    submission_target: SubmissionTarget,
) -> Result<Row, ActivityHistoryFailure> {
    database_connection
        .query(detail_query, key_values(content_sha256, submission_target))
        .await?
        .next()
        .await?
        .ok_or(ActivityHistoryFailure::StoredSubmissionUnreadable)
}

async fn stored_text_detail(
    database_connection: &Connection,
    detail_table: &str,
    detail_column: &str,
    content_sha256: &str,
    submission_target: SubmissionTarget,
) -> Result<String, ActivityHistoryFailure> {
    Ok(first_detail_row(
        database_connection,
        &format!("SELECT {detail_column} FROM {detail_table} WHERE {SUBMISSION_KEY_FILTER}"),
        content_sha256,
        submission_target,
    )
    .await?
    .get(0)?)
}

async fn stored_settlement_version(
    database_connection: &Connection,
    content_sha256: &str,
    submission_target: SubmissionTarget,
) -> Result<SignatureDatabaseVersion, ActivityHistoryFailure> {
    SignatureDatabaseVersion::from_column_value(
        first_detail_row(
            database_connection,
            "SELECT settled_database_versions.settled_database_version FROM \
             clamav_review_settlements LEFT JOIN settled_database_versions ON \
             settled_database_versions.content_sha256 = clamav_review_settlements.content_sha256 \
             AND settled_database_versions.submission_service = \
             clamav_review_settlements.submission_service AND \
             settled_database_versions.submission_kind = \
             clamav_review_settlements.submission_kind WHERE \
             clamav_review_settlements.content_sha256 = ?1 AND \
             clamav_review_settlements.submission_service = ?2 AND \
             clamav_review_settlements.submission_kind = ?3",
            content_sha256,
            submission_target,
        )
        .await?
        .get_value(0)?,
    )
}

async fn stored_submission_state(
    database_connection: &Connection,
    content_sha256: &str,
    submission_target: SubmissionTarget,
    stored_status: &str,
) -> Result<SubmissionState, ActivityHistoryFailure> {
    let unreadable_failure = ActivityHistoryFailure::StoredSubmissionUnreadable;
    let text_detail = |detail_table: &'static str, detail_column: &'static str| {
        stored_text_detail(
            database_connection,
            detail_table,
            detail_column,
            content_sha256,
            submission_target,
        )
    };
    let settlement_version =
        || stored_settlement_version(database_connection, content_sha256, submission_target);
    Ok(match (submission_target, stored_status) {
        (SubmissionTarget::ClamavFalsePositive, "awaiting_review" | "fixed_in_database") => {
            SubmissionState::ClamavFalsePositive {
                reported_signature: text_detail("false_positive_signatures", "reported_signature")
                    .await?,
                review_status: match stored_status {
                    "fixed_in_database" => FalsePositiveReview::FixedInDatabase {
                        database_version: settlement_version().await?,
                    },
                    _awaiting_review => FalsePositiveReview::AwaitingClamavReview,
                },
            }
        }
        (SubmissionTarget::ClamavMissedMalware, "awaiting_review") => {
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            }
        }
        (SubmissionTarget::ClamavMissedMalware, "now_detected") => {
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::NowDetected {
                    database_version: settlement_version().await?,
                },
            }
        }
        (SubmissionTarget::MalwareBazaarSample, "upload_accepted") => {
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::UploadAccepted,
            }
        }
        (SubmissionTarget::MalwareBazaarSample, "listed") => SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
        },
        (SubmissionTarget::MalwareBazaarSample, "refused") => {
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused {
                    refusal_reason: text_detail("upload_refusals", "refusal_reason").await?,
                },
            }
        }
        (SubmissionTarget::VirusTotalSample, "analysis_queued") => {
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                    analysis_id: text_detail("virustotal_analyses", "analysis_id").await?,
                },
            }
        }
        (SubmissionTarget::VirusTotalSample, "analysed") => {
            let verdict_row = first_detail_row(
                database_connection,
                &format!(
                    "SELECT malicious_count, engine_count FROM virustotal_verdicts WHERE \
                     {SUBMISSION_KEY_FILTER}"
                ),
                content_sha256,
                submission_target,
            )
            .await?;
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed {
                    analysis_id: text_detail("virustotal_analyses", "analysis_id").await?,
                    malicious_count: count_from_stored(verdict_row.get(0)?)?,
                    engine_count: count_from_stored(verdict_row.get(1)?)?,
                },
            }
        }
        (SubmissionTarget::VirusTotalSample, "refused") => SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::SubmissionRefused {
                refusal_reason: text_detail("upload_refusals", "refusal_reason").await?,
            },
        },
        (
            SubmissionTarget::ClamavFalsePositive
            | SubmissionTarget::ClamavMissedMalware
            | SubmissionTarget::MalwareBazaarSample
            | SubmissionTarget::VirusTotalSample,
            _unknown_status,
        ) => return Err(unreadable_failure),
    })
}

async fn submission_from_row(
    database_connection: &Connection,
    submission_row: &Row,
) -> Result<SubmissionRecord, ActivityHistoryFailure> {
    let content_sha256: String = submission_row.get(0)?;
    let stored_service: String = submission_row.get(1)?;
    let stored_kind: String = submission_row.get(2)?;
    let stored_status: String = submission_row.get(5)?;
    let submission_target = SubmissionTarget::from_stored_columns(&stored_service, &stored_kind)?;
    Ok(SubmissionRecord {
        submission_state: stored_submission_state(
            database_connection,
            &content_sha256,
            submission_target,
            &stored_status,
        )
        .await?,
        submitted_file: SubmittedFile {
            content_sha256,
            file_name: submission_row.get(3)?,
        },
        submitted_at: Timestamp::from_second(submission_row.get(4)?)?,
    })
}

async fn submissions_from_query(
    database_connection: &Connection,
    submission_query: &str,
    query_values: Vec<Value>,
) -> Result<Vec<SubmissionRecord>, ActivityHistoryFailure> {
    let mut submission_rows = database_connection
        .query(submission_query, query_values)
        .await?;
    let mut stored_rows = Vec::new();
    while let Some(submission_row) = submission_rows.next().await? {
        stored_rows.push(submission_row);
    }
    drop(submission_rows);
    let mut read_submissions = Vec::new();
    for stored_row in &stored_rows {
        read_submissions.push(submission_from_row(database_connection, stored_row).await?);
    }
    Ok(read_submissions)
}

async fn submission_with_key(
    database_connection: &Connection,
    content_sha256: &str,
    submission_target: SubmissionTarget,
) -> Result<EarlierSubmission, ActivityHistoryFailure> {
    Ok(submissions_from_query(
        database_connection,
        &format!("SELECT {SUBMISSION_COLUMNS} FROM submissions WHERE {SUBMISSION_KEY_FILTER}"),
        key_values(content_sha256, submission_target),
    )
    .await?
    .pop()
    .map_or(
        EarlierSubmission::NotSubmittedBefore,
        EarlierSubmission::SubmittedBefore,
    ))
}

async fn delete_status_details(
    database_connection: &Connection,
    content_sha256: &str,
    submission_target: SubmissionTarget,
) -> Result<(), ActivityHistoryFailure> {
    for detail_table in DETAIL_TABLES {
        database_connection
            .execute(
                &format!("DELETE FROM {detail_table} WHERE {SUBMISSION_KEY_FILTER}"),
                key_values(content_sha256, submission_target),
            )
            .await?;
    }
    Ok(())
}

async fn insert_status_details(
    database_connection: &Connection,
    content_sha256: &str,
    submission_state: &SubmissionState,
) -> Result<(), ActivityHistoryFailure> {
    let submission_target = submission_state.submission_target();
    let status_key_values = || {
        key_values(content_sha256, submission_target)
            .into_iter()
            .chain([Value::Text(
                submission_state.stored_status_name().to_owned(),
            )])
    };
    for status_detail in submission_state.status_details() {
        let (detail_insert, detail_values) = match status_detail {
            StatusDetail::ReportedSignature { reported_signature } => (
                "INSERT INTO false_positive_signatures (content_sha256, submission_service, \
                 submission_kind, submission_status, reported_signature) VALUES (?1, ?2, ?3, ?4, \
                 ?5)",
                vec![Value::Text(sanitize_scanner_line(reported_signature))],
            ),
            StatusDetail::ReviewSettlement { database_version } => {
                database_connection
                    .execute(
                        "INSERT INTO clamav_review_settlements (content_sha256, \
                         submission_service, submission_kind, submission_status) VALUES (?1, ?2, \
                         ?3, ?4)",
                        status_key_values().collect::<Vec<_>>(),
                    )
                    .await?;
                let SignatureDatabaseVersion::DailyVersion { version_number } = database_version
                else {
                    continue;
                };
                database_connection
                    .execute(
                        "INSERT INTO settled_database_versions (content_sha256, \
                         submission_service, submission_kind, settled_database_version) VALUES \
                         (?1, ?2, ?3, ?4)",
                        key_values(content_sha256, submission_target)
                            .into_iter()
                            .chain([stored_count(version_number)])
                            .collect::<Vec<_>>(),
                    )
                    .await?;
                continue;
            }
            StatusDetail::VirusTotalAnalysis { analysis_id } => (
                "INSERT INTO virustotal_analyses (content_sha256, submission_service, \
                 submission_kind, submission_status, analysis_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![Value::Text(sanitize_scanner_line(analysis_id))],
            ),
            StatusDetail::VirusTotalVerdict {
                malicious_count,
                engine_count,
            } => (
                "INSERT INTO virustotal_verdicts (content_sha256, submission_service, \
                 submission_kind, submission_status, malicious_count, engine_count) VALUES (?1, \
                 ?2, ?3, ?4, ?5, ?6)",
                vec![stored_count(malicious_count), stored_count(engine_count)],
            ),
            StatusDetail::UploadRefusal { refusal_reason } => (
                "INSERT INTO upload_refusals (content_sha256, submission_service, \
                 submission_kind, submission_status, refusal_reason) VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![Value::Text(sanitize_scanner_line(refusal_reason))],
            ),
        };
        database_connection
            .execute(
                detail_insert,
                status_key_values().chain(detail_values).collect::<Vec<_>>(),
            )
            .await?;
    }
    Ok(())
}

async fn in_transaction(
    database_connection: &Connection,
    transaction_writes: impl Future<Output = Result<(), ActivityHistoryFailure>>,
) -> Result<(), ActivityHistoryFailure> {
    database_connection.execute("BEGIN IMMEDIATE", ()).await?;
    match transaction_writes.await {
        Ok(()) => {
            database_connection.execute("COMMIT", ()).await?;
            Ok(())
        }
        Err(write_failure) => {
            let _rollback_outcome = database_connection.execute("ROLLBACK", ()).await;
            Err(write_failure)
        }
    }
}

impl ActivityHistory {
    pub async fn find_earlier_submission(
        &self,
        content_sha256: &str,
        submission_target: SubmissionTarget,
    ) -> Result<EarlierSubmission, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        Ok(
            match submission_with_key(&database_connection, content_sha256, submission_target)
                .await?
            {
                EarlierSubmission::SubmittedBefore(earlier_submission)
                    if earlier_submission.submission_state.submission_progress()
                        != SubmissionProgress::RefusedByService =>
                {
                    EarlierSubmission::SubmittedBefore(earlier_submission)
                }
                EarlierSubmission::SubmittedBefore(_) | EarlierSubmission::NotSubmittedBefore => {
                    EarlierSubmission::NotSubmittedBefore
                }
            },
        )
    }

    pub async fn record_submission(
        &self,
        new_submission: NewSubmission,
    ) -> Result<SubmissionRecording, ActivityHistoryFailure> {
        let submission_target = new_submission.submission_state.submission_target();
        let content_sha256 = new_submission
            .submitted_file
            .content_sha256
            .to_ascii_lowercase();
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        if let EarlierSubmission::SubmittedBefore(earlier_submission) =
            submission_with_key(&database_connection, &content_sha256, submission_target).await?
            && earlier_submission.submission_state.submission_progress()
                != SubmissionProgress::RefusedByService
        {
            return Ok(SubmissionRecording::AlreadySubmitted(earlier_submission));
        }
        in_transaction(&database_connection, async {
            database_connection
                .execute(
                    &format!("DELETE FROM submissions WHERE {SUBMISSION_KEY_FILTER}"),
                    key_values(&content_sha256, submission_target),
                )
                .await?;
            database_connection
                .execute(
                    "INSERT INTO submissions (content_sha256, submission_service, \
                     submission_kind, file_name, submitted_at_unix, submission_status) VALUES \
                     (?1, ?2, ?3, ?4, ?5, ?6)",
                    key_values(&content_sha256, submission_target)
                        .into_iter()
                        .chain([
                            Value::Text(sanitize_scanner_line(
                                &new_submission.submitted_file.file_name,
                            )),
                            Value::Integer(new_submission.submitted_at.as_second()),
                            Value::Text(
                                new_submission
                                    .submission_state
                                    .stored_status_name()
                                    .to_owned(),
                            ),
                        ])
                        .collect::<Vec<_>>(),
                )
                .await?;
            insert_status_details(
                &database_connection,
                &content_sha256,
                &new_submission.submission_state,
            )
            .await
        })
        .await?;
        match submission_with_key(&database_connection, &content_sha256, submission_target).await? {
            EarlierSubmission::SubmittedBefore(recorded_submission) => {
                Ok(SubmissionRecording::SubmissionRecorded(recorded_submission))
            }
            EarlierSubmission::NotSubmittedBefore => {
                Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
            }
        }
    }

    pub async fn list_submissions(&self) -> Result<Vec<SubmissionRecord>, ActivityHistoryFailure> {
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        submissions_from_query(
            &database_connection,
            &format!(
                "SELECT {SUBMISSION_COLUMNS} FROM submissions ORDER BY submitted_at_unix DESC, \
                 content_sha256, submission_service, submission_kind"
            ),
            Vec::new(),
        )
        .await
    }

    pub async fn update_submission_state(
        &self,
        content_sha256: &str,
        submission_state: SubmissionState,
    ) -> Result<(), ActivityHistoryFailure> {
        let submission_target = submission_state.submission_target();
        let _history_lock = self.lock_history().await?;
        let database_connection = self.open_connection().await?;
        in_transaction(&database_connection, async {
            delete_status_details(&database_connection, content_sha256, submission_target).await?;
            let updated_rows = database_connection
                .execute(
                    &format!(
                        "UPDATE submissions SET submission_status = ?4 WHERE \
                         {SUBMISSION_KEY_FILTER}"
                    ),
                    key_values(content_sha256, submission_target)
                        .into_iter()
                        .chain([Value::Text(
                            submission_state.stored_status_name().to_owned(),
                        )])
                        .collect::<Vec<_>>(),
                )
                .await?;
            if updated_rows == 0 {
                return Err(ActivityHistoryFailure::StoredSubmissionUnreadable);
            }
            insert_status_details(&database_connection, content_sha256, &submission_state).await
        })
        .await
    }
}

#[cfg(test)]
mod submission_history_store_tests {
    use super::*;

    const SAMPLE_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    fn every_submission_state() -> Vec<SubmissionState> {
        let daily_version = SignatureDatabaseVersion::DailyVersion {
            version_number: 28_173,
        };
        vec![
            SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Test.EICAR_HDB-1".to_owned(),
                review_status: FalsePositiveReview::AwaitingClamavReview,
            },
            SubmissionState::ClamavFalsePositive {
                reported_signature: "Win.Test.EICAR_HDB-1".to_owned(),
                review_status: FalsePositiveReview::FixedInDatabase {
                    database_version: daily_version,
                },
            },
            SubmissionState::ClamavFalsePositive {
                reported_signature: "Doc.Macro:Odd-1".to_owned(),
                review_status: FalsePositiveReview::FixedInDatabase {
                    database_version: SignatureDatabaseVersion::VersionUnreadable,
                },
            },
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            },
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::NowDetected {
                    database_version: daily_version,
                },
            },
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::UploadAccepted,
            },
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            },
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused {
                    refusal_reason: "illegal_tags: a:b".to_owned(),
                },
            },
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                    analysis_id: "OTFiMDcwMjVjZDIzZTI0NGU4ZDlmMjI2NjkzZDczNGE6MTY1MzY1NDM3Nw=="
                        .to_owned(),
                },
            },
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed {
                    analysis_id: "analysis-1".to_owned(),
                    malicious_count: 41,
                    engine_count: 70,
                },
            },
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::SubmissionRefused {
                    refusal_reason: "BadRequestError".to_owned(),
                },
            },
        ]
    }

    fn new_submission(content_sha256: &str, submission_state: SubmissionState) -> NewSubmission {
        NewSubmission {
            submitted_file: SubmittedFile {
                content_sha256: content_sha256.to_owned(),
                file_name: "invoice.exe".to_owned(),
            },
            submitted_at: Timestamp::constant(1_793_869_222, 0),
            submission_state,
        }
    }

    fn fixture_history(temporary_root: &tempfile::TempDir) -> ActivityHistory {
        ActivityHistory::at_database_path(temporary_root.path().join("history.db"))
    }

    fn detail_row_count(temporary_root: &tempfile::TempDir) -> i64 {
        let sqlite_connection =
            rusqlite::Connection::open(temporary_root.path().join("history.db")).expect("sqlite");
        DETAIL_TABLES
            .iter()
            .map(|detail_table| {
                sqlite_connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {detail_table}"),
                        [],
                        |count_row| count_row.get::<_, i64>(0),
                    )
                    .expect("detail count")
            })
            .sum()
    }

    #[tokio::test]
    async fn every_kind_and_status_round_trips_through_the_tables() {
        for submission_state in every_submission_state() {
            let temporary_root = tempfile::tempdir().expect("temporary root");
            let history = fixture_history(&temporary_root);
            let recording = history
                .record_submission(new_submission(SAMPLE_SHA256, submission_state.clone()))
                .await
                .expect("recorded");
            assert!(matches!(
                recording,
                SubmissionRecording::SubmissionRecorded(_)
            ));
            let listed_submissions = history.list_submissions().await.expect("listed");
            assert_eq!(listed_submissions.len(), 1);
            assert_eq!(listed_submissions[0].submission_state, submission_state);
            assert_eq!(
                listed_submissions[0].submitted_file.file_name,
                "invoice.exe"
            );
            assert_eq!(
                listed_submissions[0].submitted_at,
                Timestamp::constant(1_793_869_222, 0)
            );
        }
    }

    #[tokio::test]
    async fn a_second_submission_of_the_same_hash_to_the_same_target_is_refused() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        let first_state = SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::UploadAccepted,
        };
        history
            .record_submission(new_submission(SAMPLE_SHA256, first_state.clone()))
            .await
            .expect("first");
        let second_recording = history
            .record_submission(new_submission(
                &SAMPLE_SHA256.to_ascii_uppercase(),
                SubmissionState::MalwareBazaarSample {
                    bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
                },
            ))
            .await
            .expect("second");
        assert!(matches!(
            second_recording,
            SubmissionRecording::AlreadySubmitted(earlier_submission)
                if earlier_submission.submission_state == first_state
        ));
        assert_eq!(history.list_submissions().await.expect("listed").len(), 1);
    }

    #[tokio::test]
    async fn duplicates_are_per_hash_service_and_kind() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        let false_positive = SubmissionState::ClamavFalsePositive {
            reported_signature: "Win.Trojan.Agent".to_owned(),
            review_status: FalsePositiveReview::AwaitingClamavReview,
        };
        let missed_malware = SubmissionState::ClamavMissedMalware {
            review_status: MissedMalwareReview::AwaitingClamavReview,
        };
        let virustotal_sample = SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                analysis_id: "analysis-1".to_owned(),
            },
        };
        for submission_state in [&false_positive, &missed_malware, &virustotal_sample] {
            assert!(matches!(
                history
                    .record_submission(new_submission(SAMPLE_SHA256, submission_state.clone()))
                    .await
                    .expect("recorded"),
                SubmissionRecording::SubmissionRecorded(_)
            ));
        }
        assert!(matches!(
            history
                .record_submission(new_submission(&"a".repeat(64), false_positive.clone()))
                .await
                .expect("other hash"),
            SubmissionRecording::SubmissionRecorded(_)
        ));
        assert!(matches!(
            history
                .record_submission(new_submission(SAMPLE_SHA256, missed_malware))
                .await
                .expect("duplicate"),
            SubmissionRecording::AlreadySubmitted(_)
        ));
        assert!(matches!(
            history
                .find_earlier_submission(SAMPLE_SHA256, SubmissionTarget::ClamavFalsePositive)
                .await
                .expect("found"),
            EarlierSubmission::SubmittedBefore(_)
        ));
        assert_eq!(
            history
                .find_earlier_submission(SAMPLE_SHA256, SubmissionTarget::MalwareBazaarSample)
                .await
                .expect("searched"),
            EarlierSubmission::NotSubmittedBefore
        );
        assert_eq!(history.list_submissions().await.expect("listed").len(), 4);
    }

    #[tokio::test]
    async fn a_refused_submission_can_be_tried_again_and_is_replaced() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        history
            .record_submission(new_submission(
                SAMPLE_SHA256,
                SubmissionState::VirusTotalSample {
                    virustotal_status: VirusTotalSampleStatus::SubmissionRefused {
                        refusal_reason: "BadRequestError".to_owned(),
                    },
                },
            ))
            .await
            .expect("refused");
        assert_eq!(
            history
                .find_earlier_submission(SAMPLE_SHA256, SubmissionTarget::VirusTotalSample)
                .await
                .expect("searched"),
            EarlierSubmission::NotSubmittedBefore
        );
        let queued_state = SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                analysis_id: "analysis-2".to_owned(),
            },
        };
        assert!(matches!(
            history
                .record_submission(new_submission(SAMPLE_SHA256, queued_state.clone()))
                .await
                .expect("retried"),
            SubmissionRecording::SubmissionRecorded(_)
        ));
        let listed_submissions = history.list_submissions().await.expect("listed");
        assert_eq!(listed_submissions.len(), 1);
        assert_eq!(listed_submissions[0].submission_state, queued_state);
        assert_eq!(detail_row_count(&temporary_root), 1);
    }

    #[tokio::test]
    async fn a_status_update_replaces_its_details_under_the_same_key() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        history
            .record_submission(new_submission(
                SAMPLE_SHA256,
                SubmissionState::VirusTotalSample {
                    virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                        analysis_id: "analysis-3".to_owned(),
                    },
                },
            ))
            .await
            .expect("recorded");
        let analysed_state = SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed {
                analysis_id: "analysis-3".to_owned(),
                malicious_count: 12,
                engine_count: 68,
            },
        };
        history
            .update_submission_state(SAMPLE_SHA256, analysed_state.clone())
            .await
            .expect("updated");
        let listed_submissions = history.list_submissions().await.expect("listed");
        assert_eq!(listed_submissions.len(), 1);
        assert_eq!(listed_submissions[0].submission_state, analysed_state);
        assert_eq!(detail_row_count(&temporary_root), 2);
        assert!(matches!(
            history
                .update_submission_state(
                    &"c".repeat(64),
                    SubmissionState::MalwareBazaarSample {
                        bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
                    },
                )
                .await,
            Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
        ));
    }

    #[tokio::test]
    async fn the_schema_refuses_rows_that_cannot_exist() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        drop(history.list_submissions().await.expect("schema created"));
        let sqlite_connection =
            rusqlite::Connection::open(temporary_root.path().join("history.db")).expect("sqlite");
        sqlite_connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=ON;
                 INSERT INTO submissions VALUES ('{SAMPLE_SHA256}', 'clamav', 'missed_malware', \
                 'a', 1, 'awaiting_review');
                 INSERT INTO submissions VALUES ('{SAMPLE_SHA256}', 'virustotal', \
                 'malware_sample', 'a', 1, 'analysis_queued');
                 INSERT INTO virustotal_analyses VALUES ('{SAMPLE_SHA256}', 'virustotal', \
                 'malware_sample', 'analysis_queued', 'analysis-1');"
            ))
            .expect("valid rows");
        [
            format!(
                "INSERT INTO submissions VALUES ('{SAMPLE_SHA256}', 'virustotal', 'shredded', \
                 'a', 1, 'analysed')"
            ),
            "INSERT INTO submissions VALUES ('ab', 'malware_bazaar', 'malware_sample', 'a', 1, \
             'listed')"
                .to_owned(),
            format!(
                "INSERT INTO submissions VALUES ('{SAMPLE_SHA256}', 'malware_bazaar', \
                 'malware_sample', 'a', 1, 'analysed')"
            ),
            format!(
                "INSERT INTO submissions VALUES ('{SAMPLE_SHA256}', 'clamav', 'malware_sample', \
                 'a', 1, 'awaiting_review')"
            ),
            format!(
                "INSERT INTO false_positive_signatures VALUES ('{SAMPLE_SHA256}', 'clamav', \
                 'missed_malware', 'awaiting_review', 'Win.Trojan.Agent')"
            ),
            format!(
                "INSERT INTO clamav_review_settlements VALUES ('{SAMPLE_SHA256}', 'clamav', \
                 'missed_malware', 'now_detected')"
            ),
            format!(
                "INSERT INTO settled_database_versions VALUES ('{SAMPLE_SHA256}', 'clamav', \
                 'missed_malware', 28173)"
            ),
            format!(
                "INSERT INTO virustotal_verdicts VALUES ('{SAMPLE_SHA256}', 'virustotal', \
                 'malware_sample', 'analysed', 1, 70)"
            ),
            format!(
                "INSERT INTO upload_refusals VALUES ('{SAMPLE_SHA256}', 'virustotal', \
                 'malware_sample', 'refused', 'BadRequestError')"
            ),
        ]
        .into_iter()
        .for_each(|invalid_insert| {
            assert!(
                sqlite_connection.execute(&invalid_insert, []).is_err(),
                "accepted: {invalid_insert}"
            );
        });
        assert!(
            sqlite_connection
                .execute(
                    &format!(
                        "UPDATE submissions SET submission_status = 'refused' WHERE \
                         submission_service = 'virustotal' AND content_sha256 = '{SAMPLE_SHA256}'"
                    ),
                    [],
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_settlement_without_a_readable_version_stores_no_version_row() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        history
            .record_submission(new_submission(
                SAMPLE_SHA256,
                SubmissionState::ClamavMissedMalware {
                    review_status: MissedMalwareReview::NowDetected {
                        database_version: SignatureDatabaseVersion::VersionUnreadable,
                    },
                },
            ))
            .await
            .expect("recorded");
        let version_rows: i64 =
            rusqlite::Connection::open(temporary_root.path().join("history.db"))
                .expect("sqlite")
                .query_row(
                    "SELECT COUNT(*) FROM settled_database_versions",
                    [],
                    |count_row| count_row.get(0),
                )
                .expect("count");
        assert_eq!(version_rows, 0);
    }

    #[tokio::test]
    async fn a_status_without_its_detail_row_is_unreadable() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let history = fixture_history(&temporary_root);
        drop(history.list_submissions().await.expect("schema created"));
        rusqlite::Connection::open(temporary_root.path().join("history.db"))
            .expect("sqlite")
            .execute(
                &format!(
                    "INSERT INTO submissions VALUES ('{SAMPLE_SHA256}', 'virustotal', \
                     'malware_sample', 'a', 1, 'analysis_queued')"
                ),
                [],
            )
            .expect("orphaned status");
        assert!(matches!(
            history.list_submissions().await,
            Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
        ));
    }

    #[test]
    fn stored_combinations_that_cannot_exist_are_unreadable() {
        assert!(matches!(
            SubmissionTarget::from_stored_columns("virustotal", "false_positive"),
            Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
        ));
        assert!(matches!(
            SubmissionTarget::from_stored_columns("clamav", "malware_sample"),
            Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
        ));
        assert!(matches!(
            SignatureDatabaseVersion::from_column_value(Value::Integer(-1)),
            Err(ActivityHistoryFailure::StoredSubmissionUnreadable)
        ));
    }

    #[test]
    fn only_uploads_that_reached_a_service_link_to_its_entry() {
        assert_eq!(
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            }
            .remote_entry_link("ab12"),
            RemoteEntryLink::RemoteEntryAt {
                entry_url: "https://bazaar.abuse.ch/sample/ab12/".to_owned()
            }
        );
        assert_eq!(
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                    analysis_id: "analysis-1".to_owned(),
                },
            }
            .remote_entry_link("ab12"),
            RemoteEntryLink::RemoteEntryAt {
                entry_url: "https://www.virustotal.com/gui/file/ab12".to_owned()
            }
        );
        assert_eq!(
            SubmissionState::ClamavMissedMalware {
                review_status: MissedMalwareReview::AwaitingClamavReview,
            }
            .remote_entry_link("ab12"),
            RemoteEntryLink::NoRemoteEntry
        );
    }
}
