use std::time::Duration;

use reqwest::StatusCode;
use serde_json::Value;

const LOOKUP_BASE_URL: &str = "https://hashlookup.circl.lu/lookup/sha256";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum CirclLookupFailure {
    #[error("CIRCL hashlookup could not be reached: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("CIRCL hashlookup sent an answer that could not be read")]
    AnswerUnreadable,
    #[error("CIRCL hashlookup answered with status {status_code}")]
    UnexpectedStatus { status_code: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KnownName {
    NamedFile(String),
    UnnamedFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListingSource {
    NamedSource(String),
    UnnamedSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KnownFileLookup {
    KnownMalicious {
        file_name: KnownName,
        flagged_by: ListingSource,
    },
    KnownFile {
        file_name: KnownName,
        source_name: ListingSource,
    },
    HashUnknown,
}

fn present_text(parsed_answer: &Value, field_name: &str) -> Option<String> {
    parsed_answer
        .get(field_name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|field_text| !field_text.is_empty())
        .map(str::to_owned)
}

fn listing_source(parsed_answer: &Value, field_name: &str) -> ListingSource {
    present_text(parsed_answer, field_name)
        .map_or(ListingSource::UnnamedSource, ListingSource::NamedSource)
}

pub fn parse_known_file_answer(answer_bytes: &[u8]) -> Result<KnownFileLookup, CirclLookupFailure> {
    let parsed_answer: Value = serde_json::from_slice(answer_bytes)
        .map_err(|_invalid_json| CirclLookupFailure::AnswerUnreadable)?;
    if !parsed_answer.is_object() {
        return Err(CirclLookupFailure::AnswerUnreadable);
    }
    let file_name = present_text(&parsed_answer, "FileName")
        .map_or(KnownName::UnnamedFile, KnownName::NamedFile);
    Ok(match parsed_answer.get("KnownMalicious") {
        Some(_flagging_value) => KnownFileLookup::KnownMalicious {
            file_name,
            flagged_by: listing_source(&parsed_answer, "KnownMalicious"),
        },
        None => KnownFileLookup::KnownFile {
            file_name,
            source_name: listing_source(&parsed_answer, "source"),
        },
    })
}

pub async fn look_up_known_file(content_hash: &str) -> Result<KnownFileLookup, CirclLookupFailure> {
    let lookup_response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(format!("{LOOKUP_BASE_URL}/{content_hash}"))
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?;
    match lookup_response.status() {
        StatusCode::NOT_FOUND => Ok(KnownFileLookup::HashUnknown),
        status_code if status_code.is_success() => {
            parse_known_file_answer(&lookup_response.bytes().await?)
        }
        status_code => Err(CirclLookupFailure::UnexpectedStatus {
            status_code: status_code.as_u16(),
        }),
    }
}

#[cfg(test)]
mod circl_hashlookup_client_tests {
    use super::*;

    #[test]
    fn a_known_file_keeps_its_name_and_source() {
        assert_eq!(
            parse_known_file_answer(
                br#"{"FileName":"./usr/bin/ls","FileSize":"142312","source":"NSRL","hashlookup:trust":55}"#
            )
            .expect("parsed"),
            KnownFileLookup::KnownFile {
                file_name: KnownName::NamedFile("./usr/bin/ls".to_owned()),
                source_name: ListingSource::NamedSource("NSRL".to_owned()),
            }
        );
    }

    #[test]
    fn a_file_flagged_as_malicious_is_not_reported_as_known_good() {
        assert_eq!(
            parse_known_file_answer(
                br#"{"FileName":"eicar.com","KnownMalicious":"malshare.com","source":"RDS_2025.03.1_android.db","hashlookup:trust":100}"#
            )
            .expect("parsed"),
            KnownFileLookup::KnownMalicious {
                file_name: KnownName::NamedFile("eicar.com".to_owned()),
                flagged_by: ListingSource::NamedSource("malshare.com".to_owned()),
            }
        );
    }

    #[test]
    fn a_malicious_flag_without_a_readable_source_is_still_malicious() {
        ["null", "\"\"", "[\"malshare.com\"]", "true"]
            .into_iter()
            .for_each(|flag_value| {
                let answer_text = format!(r#"{{"KnownMalicious":{flag_value}}}"#);
                assert_eq!(
                    parse_known_file_answer(answer_text.as_bytes()).expect("parsed"),
                    KnownFileLookup::KnownMalicious {
                        file_name: KnownName::UnnamedFile,
                        flagged_by: ListingSource::UnnamedSource,
                    },
                    "{flag_value}"
                );
            });
    }

    #[test]
    fn missing_fields_do_not_fail_the_lookup() {
        assert_eq!(
            parse_known_file_answer(br#"{"SHA-256":"AB"}"#).expect("parsed"),
            KnownFileLookup::KnownFile {
                file_name: KnownName::UnnamedFile,
                source_name: ListingSource::UnnamedSource,
            }
        );
    }

    #[test]
    fn unreadable_answers_are_errors_rather_than_clean_results() {
        assert!(matches!(
            parse_known_file_answer(b"<html>"),
            Err(CirclLookupFailure::AnswerUnreadable)
        ));
        assert!(matches!(
            parse_known_file_answer(b"[]"),
            Err(CirclLookupFailure::AnswerUnreadable)
        ));
    }
}
