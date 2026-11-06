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
pub enum KnownFileLookup {
    KnownMalicious {
        file_name: String,
        flagged_by: String,
    },
    KnownFile {
        file_name: String,
        source_name: String,
    },
    HashUnknown,
}

fn text_field(parsed_answer: &Value, field_name: &str) -> String {
    parsed_answer
        .get(field_name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub fn parse_known_file_answer(answer_bytes: &[u8]) -> Result<KnownFileLookup, CirclLookupFailure> {
    let parsed_answer: Value = serde_json::from_slice(answer_bytes)
        .map_err(|_invalid_json| CirclLookupFailure::AnswerUnreadable)?;
    if !parsed_answer.is_object() {
        return Err(CirclLookupFailure::AnswerUnreadable);
    }
    let file_name = text_field(&parsed_answer, "FileName");
    let flagged_by = text_field(&parsed_answer, "KnownMalicious");
    Ok(if flagged_by.is_empty() {
        KnownFileLookup::KnownFile {
            file_name,
            source_name: text_field(&parsed_answer, "source"),
        }
    } else {
        KnownFileLookup::KnownMalicious {
            file_name,
            flagged_by,
        }
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
                file_name: "./usr/bin/ls".to_owned(),
                source_name: "NSRL".to_owned(),
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
                file_name: "eicar.com".to_owned(),
                flagged_by: "malshare.com".to_owned(),
            }
        );
    }

    #[test]
    fn missing_fields_do_not_fail_the_lookup() {
        assert_eq!(
            parse_known_file_answer(br#"{"SHA-256":"AB"}"#).expect("parsed"),
            KnownFileLookup::KnownFile {
                file_name: String::new(),
                source_name: String::new(),
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
