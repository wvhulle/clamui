use gettextrs::{gettext, ngettext};

use crate::{
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    threat_intel_lookup::{
        circl_hashlookup_client::{KnownFileLookup, look_up_known_file},
        malware_bazaar_client::{KnownSampleLookup, look_up_file_hash},
        service_key_preferences_page::describe_key_failure,
        service_key_storage::{ThreatIntelService, read_stored_api_key},
        virustotal_api_client::{FileReportLookup, VirusTotalClient, VirusTotalFailure},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceAnswer {
    NotChecked,
    Checking,
    NeedsKey,
    Answered {
        verdict_text: String,
    },
    AnsweredWithReport {
        verdict_text: String,
        report_url: String,
    },
    Failed {
        failure_text: String,
    },
}

impl SourceAnswer {
    pub fn displayed_text(&self) -> String {
        match self {
            Self::NotChecked => gettext("Not checked yet"),
            Self::Checking => gettext("Checking…"),
            Self::NeedsKey => gettext("Add a key in Preferences to include this source"),
            Self::Answered { verdict_text } | Self::AnsweredWithReport { verdict_text, .. } => {
                verdict_text.clone()
            }
            Self::Failed { failure_text } => failure_text.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationAnswers {
    pub circl_answer: SourceAnswer,
    pub bazaar_answer: SourceAnswer,
    pub virustotal_answer: SourceAnswer,
}

impl ReputationAnswers {
    pub fn all_set_to(shared_answer: &SourceAnswer) -> Self {
        Self {
            circl_answer: shared_answer.clone(),
            bazaar_answer: shared_answer.clone(),
            virustotal_answer: shared_answer.clone(),
        }
    }
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
        other_failure => other_failure.to_string(),
    }
}

async fn stored_key_for(threat_intel_service: ThreatIntelService) -> Result<String, SourceAnswer> {
    match read_stored_api_key(threat_intel_service).await {
        Ok(Some(stored_key)) => Ok(stored_key),
        Ok(None) => Err(SourceAnswer::NeedsKey),
        Err(key_failure) => Err(SourceAnswer::Failed {
            failure_text: describe_key_failure(&key_failure),
        }),
    }
}

async fn circl_answer(content_hash: &str) -> SourceAnswer {
    look_up_known_file(content_hash).await.map_or_else(
        |lookup_failure| SourceAnswer::Failed {
            failure_text: lookup_failure.to_string(),
        },
        |known_file_lookup| describe_known_file(&known_file_lookup),
    )
}

async fn bazaar_answer(content_hash: &str) -> SourceAnswer {
    let auth_key = match stored_key_for(ThreatIntelService::AbuseChService).await {
        Ok(auth_key) => auth_key,
        Err(missing_key_answer) => return missing_key_answer,
    };
    look_up_file_hash(&auth_key, content_hash)
        .await
        .map_or_else(
            |lookup_failure| SourceAnswer::Failed {
                failure_text: lookup_failure.to_string(),
            },
            |sample_lookup| describe_known_samples(&sample_lookup),
        )
}

async fn virustotal_answer(content_hash: &str) -> SourceAnswer {
    let api_key = match stored_key_for(ThreatIntelService::VirusTotalService).await {
        Ok(api_key) => api_key,
        Err(missing_key_answer) => return missing_key_answer,
    };
    let report_lookup = match VirusTotalClient::with_api_key(api_key) {
        Ok(lookup_client) => lookup_client.look_up_file_report(content_hash).await,
        Err(client_failure) => Err(client_failure),
    };
    report_lookup.map_or_else(
        |lookup_failure| SourceAnswer::Failed {
            failure_text: describe_virustotal_failure(&lookup_failure),
        },
        |file_report_lookup| describe_virustotal_report(&file_report_lookup),
    )
}

pub async fn check_hash_reputation(content_hash: String) -> ReputationAnswers {
    let (circl_answer, bazaar_answer, virustotal_answer) = futures::join!(
        circl_answer(&content_hash),
        bazaar_answer(&content_hash),
        virustotal_answer(&content_hash),
    );
    ReputationAnswers {
        circl_answer,
        bazaar_answer,
        virustotal_answer,
    }
}

#[cfg(test)]
mod file_reputation_check_tests {
    use super::*;
    use crate::threat_intel_lookup::{
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
        assert_eq!(
            describe_virustotal_report(&FileReportLookup::ReportAvailable(VirusTotalReport {
                content_hash: "abc".to_owned(),
                detecting_engine_count: 3,
                total_engine_count: 71,
                engine_detections: Vec::new(),
                report_url: "https://www.virustotal.com/gui/file/abc".to_owned(),
            })),
            SourceAnswer::AnsweredWithReport {
                verdict_text: "3 of 71 engines detect it".to_owned(),
                report_url: "https://www.virustotal.com/gui/file/abc".to_owned(),
            }
        );
    }
}
