use std::sync::Arc;

use gettextrs::{gettext, ngettext};

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    threat_intel::{
        circl_hashlookup_client::{CirclLookupFailure, KnownFileLookup, look_up_known_file},
        malware_bazaar_client::{KnownSampleLookup, MalwareBazaarFailure, look_up_file_hash},
        service_key_storage::{
            KeyStorageFailure, ResolvedApiKey, ThreatIntelService, describe_key_failure,
            read_api_key,
        },
        virustotal_api_client::{FileReportLookup, VirusTotalClient, VirusTotalFailure},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ReputationLookupFailure {
    #[error(transparent)]
    KeyUnavailable(#[from] KeyStorageFailure),
    #[error(transparent)]
    CirclLookupFailed(#[from] CirclLookupFailure),
    #[error(transparent)]
    BazaarLookupFailed(#[from] MalwareBazaarFailure),
    #[error(transparent)]
    VirusTotalLookupFailed(#[from] VirusTotalFailure),
}

#[derive(Clone, Debug)]
pub enum SourceAnswer {
    NeedsKey,
    Answered {
        verdict_text: String,
    },
    AnsweredWithReport {
        verdict_text: String,
        report_url: String,
    },
    Failed(Arc<ReputationLookupFailure>),
}

impl From<ReputationLookupFailure> for SourceAnswer {
    fn from(lookup_failure: ReputationLookupFailure) -> Self {
        Self::Failed(Arc::new(lookup_failure))
    }
}

impl SourceAnswer {
    pub fn displayed_text(&self) -> String {
        match self {
            Self::NeedsKey => gettext("Needs a key"),
            Self::Answered { verdict_text } | Self::AnsweredWithReport { verdict_text, .. } => {
                verdict_text.clone()
            }
            Self::Failed(lookup_failure) => describe_lookup_failure(lookup_failure),
        }
    }

    pub const fn needs_key(&self) -> bool {
        matches!(self, Self::NeedsKey)
    }
}

#[derive(Clone, Debug)]
pub struct ReputationAnswers {
    pub circl_answer: SourceAnswer,
    pub bazaar_answer: SourceAnswer,
    pub virustotal_answer: SourceAnswer,
}

pub fn describe_known_file(known_file_lookup: &KnownFileLookup) -> SourceAnswer {
    let verdict_text = match known_file_lookup {
        KnownFileLookup::HashUnknown => gettext("Not in the known-files database"),
        KnownFileLookup::KnownMalicious {
            file_name,
            flagged_by,
        } => gettext("Listed as malicious by {source} (as {name})")
            .replace("{source}", &sanitize_scanner_line(flagged_by))
            .replace("{name}", &sanitize_scanner_line(file_name)),
        KnownFileLookup::KnownFile {
            file_name,
            source_name,
        } if file_name.is_empty() => gettext("Listed as a known file by {source}")
            .replace("{source}", &sanitize_scanner_line(source_name)),
        KnownFileLookup::KnownFile {
            file_name,
            source_name,
        } => gettext("Known file {name}, listed by {source}")
            .replace("{source}", &sanitize_scanner_line(source_name))
            .replace("{name}", &sanitize_scanner_line(file_name)),
    };
    SourceAnswer::Answered { verdict_text }
}

pub fn describe_known_samples(sample_lookup: &KnownSampleLookup) -> SourceAnswer {
    let verdict_text = match sample_lookup {
        KnownSampleLookup::NoKnownSamples => gettext("Not a known malware sample"),
        KnownSampleLookup::SamplesFound { known_samples } => known_samples.first().map_or_else(
            || gettext("Known malware sample"),
            |first_sample| {
                let family_name = if first_sample.malware_family.is_empty() {
                    gettext("unnamed family")
                } else {
                    sanitize_scanner_line(&first_sample.malware_family)
                };
                gettext("Known malware: {family}, first seen {date}")
                    .replace("{date}", &sanitize_scanner_line(&first_sample.first_seen))
                    .replace("{family}", &family_name)
            },
        ),
    };
    SourceAnswer::Answered { verdict_text }
}

pub fn describe_virustotal_report(report_lookup: &FileReportLookup) -> SourceAnswer {
    match report_lookup {
        FileReportLookup::FileUnknownToVirusTotal => SourceAnswer::Answered {
            verdict_text: gettext("Unknown to VirusTotal"),
        },
        FileReportLookup::ReportAvailable(file_report) => SourceAnswer::AnsweredWithReport {
            verdict_text: ngettext(
                "{count} of {total} engine detects it",
                "{count} of {total} engines detect it",
                u32::try_from(file_report.total_engine_count).unwrap_or(u32::MAX),
            )
            .replace("{count}", &file_report.detecting_engine_count.to_string())
            .replace("{total}", &file_report.total_engine_count.to_string()),
            report_url: file_report.report_url.clone(),
        },
    }
}

fn describe_virustotal_failure(virustotal_failure: &VirusTotalFailure) -> String {
    match virustotal_failure {
        VirusTotalFailure::ApiKeyRejected => gettext("VirusTotal rejected the API key."),
        VirusTotalFailure::RequestLimitReached => {
            gettext("The VirusTotal request limit was reached. Try again later.")
        }
        VirusTotalFailure::UnexpectedStatus { status_code } => {
            gettext("VirusTotal answered with status {status}")
                .replace("{status}", &status_code.to_string())
        }
        VirusTotalFailure::RequestFailed(request_failure) => {
            gettext("VirusTotal could not be reached: {error}")
                .replace("{error}", &request_failure.to_string())
        }
        VirusTotalFailure::AnswerUnreadable => {
            gettext("VirusTotal sent an answer Lazaret cannot read")
        }
    }
}

fn describe_circl_failure(circl_failure: &CirclLookupFailure) -> String {
    match circl_failure {
        CirclLookupFailure::RequestFailed(request_failure) => {
            gettext("CIRCL hashlookup could not be reached: {error}")
                .replace("{error}", &request_failure.to_string())
        }
        CirclLookupFailure::AnswerUnreadable => {
            gettext("CIRCL hashlookup sent an answer that could not be read")
        }
        CirclLookupFailure::UnexpectedStatus { status_code } => {
            gettext("CIRCL hashlookup answered with status {status}")
                .replace("{status}", &status_code.to_string())
        }
    }
}

fn describe_bazaar_failure(bazaar_failure: &MalwareBazaarFailure) -> String {
    match bazaar_failure {
        MalwareBazaarFailure::RequestFailed(request_failure) => {
            gettext("MalwareBazaar could not be reached: {error}")
                .replace("{error}", &request_failure.to_string())
        }
        MalwareBazaarFailure::AnswerUnreadable => {
            gettext("MalwareBazaar sent an answer that could not be read")
        }
        MalwareBazaarFailure::KeyRefused => gettext("MalwareBazaar refused the API key"),
        MalwareBazaarFailure::QueryRefused { query_status } => {
            gettext("MalwareBazaar answered: {status}")
                .replace("{status}", &sanitize_scanner_line(query_status))
        }
    }
}

fn describe_lookup_failure(lookup_failure: &ReputationLookupFailure) -> String {
    match lookup_failure {
        ReputationLookupFailure::KeyUnavailable(key_failure) => describe_key_failure(key_failure),
        ReputationLookupFailure::CirclLookupFailed(circl_failure) => {
            describe_circl_failure(circl_failure)
        }
        ReputationLookupFailure::BazaarLookupFailed(bazaar_failure) => {
            describe_bazaar_failure(bazaar_failure)
        }
        ReputationLookupFailure::VirusTotalLookupFailed(virustotal_failure) => {
            describe_virustotal_failure(virustotal_failure)
        }
    }
}

enum StoredServiceKey {
    KeyAvailable { api_key: String },
    KeyNotConfigured,
}

async fn stored_key_for(
    threat_intel_service: ThreatIntelService,
) -> Result<StoredServiceKey, ReputationLookupFailure> {
    Ok(match read_api_key(threat_intel_service).await? {
        ResolvedApiKey::FromKeyFile(api_key) | ResolvedApiKey::FromKeyring(api_key) => {
            StoredServiceKey::KeyAvailable { api_key }
        }
        ResolvedApiKey::NotConfigured => StoredServiceKey::KeyNotConfigured,
    })
}

async fn look_up_circl(content_hash: &str) -> Result<SourceAnswer, ReputationLookupFailure> {
    Ok(describe_known_file(
        &look_up_known_file(content_hash).await?,
    ))
}

async fn look_up_bazaar(content_hash: &str) -> Result<SourceAnswer, ReputationLookupFailure> {
    let StoredServiceKey::KeyAvailable { api_key } =
        stored_key_for(ThreatIntelService::AbuseChService).await?
    else {
        return Ok(SourceAnswer::NeedsKey);
    };
    Ok(describe_known_samples(
        &look_up_file_hash(&api_key, content_hash).await?,
    ))
}

async fn look_up_virustotal(content_hash: &str) -> Result<SourceAnswer, ReputationLookupFailure> {
    let StoredServiceKey::KeyAvailable { api_key } =
        stored_key_for(ThreatIntelService::VirusTotalService).await?
    else {
        return Ok(SourceAnswer::NeedsKey);
    };
    let lookup_client = VirusTotalClient::with_api_key(api_key)?;
    Ok(describe_virustotal_report(
        &lookup_client.look_up_file_report(content_hash).await?,
    ))
}

fn answer_or_failure(source_lookup: Result<SourceAnswer, ReputationLookupFailure>) -> SourceAnswer {
    source_lookup.unwrap_or_else(SourceAnswer::from)
}

pub async fn check_hash_reputation(content_hash: String) -> ReputationAnswers {
    let (circl_answer, bazaar_answer, virustotal_answer) = futures::join!(
        look_up_circl(&content_hash),
        look_up_bazaar(&content_hash),
        look_up_virustotal(&content_hash),
    );
    ReputationAnswers {
        circl_answer: answer_or_failure(circl_answer),
        bazaar_answer: answer_or_failure(bazaar_answer),
        virustotal_answer: answer_or_failure(virustotal_answer),
    }
}

#[cfg(test)]
mod file_reputation_check_tests {
    use super::*;
    use crate::host_services::threat_intel::{
        malware_bazaar_client::SampleSummary, virustotal_api_client::VirusTotalReport,
    };

    #[test]
    fn a_known_file_names_its_source() {
        assert_eq!(
            describe_known_file(&KnownFileLookup::KnownFile {
                file_name: "./usr/bin/ls".to_owned(),
                source_name: "NSRL".to_owned(),
            })
            .displayed_text(),
            "Known file ./usr/bin/ls, listed by NSRL"
        );
        assert_eq!(
            describe_known_file(&KnownFileLookup::KnownMalicious {
                file_name: "eicar.com".to_owned(),
                flagged_by: "malshare.com".to_owned(),
            })
            .displayed_text(),
            "Listed as malicious by malshare.com (as eicar.com)"
        );
        assert_eq!(
            describe_known_file(&KnownFileLookup::HashUnknown).displayed_text(),
            "Not in the known-files database"
        );
    }

    #[test]
    fn a_known_sample_names_its_family_and_date() {
        assert_eq!(
            describe_known_samples(&KnownSampleLookup::SamplesFound {
                known_samples: vec![SampleSummary {
                    malware_family: "AgentTesla".to_owned(),
                    first_seen: "2026-10-01".to_owned(),
                    file_type: "exe".to_owned(),
                    sample_tags: Vec::new(),
                }],
            })
            .displayed_text(),
            "Known malware: AgentTesla, first seen 2026-10-01"
        );
    }

    #[test]
    fn a_virustotal_report_counts_engines_and_links_the_report() {
        let SourceAnswer::AnsweredWithReport {
            verdict_text,
            report_url,
        } = describe_virustotal_report(&FileReportLookup::ReportAvailable(VirusTotalReport {
            content_hash: "abc".to_owned(),
            detecting_engine_count: 3,
            total_engine_count: 71,
            engine_detections: Vec::new(),
            report_url: "https://www.virustotal.com/gui/file/abc".to_owned(),
        }))
        else {
            panic!("a VirusTotal report links to its page");
        };
        assert_eq!(verdict_text, "3 of 71 engines detect it");
        assert_eq!(report_url, "https://www.virustotal.com/gui/file/abc");
    }

    #[test]
    fn lookup_failures_are_described_by_their_kind() {
        assert_eq!(
            SourceAnswer::from(ReputationLookupFailure::from(
                VirusTotalFailure::UnexpectedStatus { status_code: 503 }
            ))
            .displayed_text(),
            "VirusTotal answered with status 503"
        );
        assert_eq!(
            SourceAnswer::from(ReputationLookupFailure::from(
                MalwareBazaarFailure::QueryRefused {
                    query_status: "illegal_hash".to_owned(),
                }
            ))
            .displayed_text(),
            "MalwareBazaar answered: illegal_hash"
        );
    }
}
