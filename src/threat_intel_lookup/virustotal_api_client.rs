use std::{collections::BTreeMap, time::Duration};

use reqwest::StatusCode;
use serde::Deserialize;

const API_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const REPORT_BASE_URL: &str = "https://www.virustotal.com/gui/file";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum VirusTotalFailure {
    #[error("VirusTotal rejected the API key")]
    ApiKeyRejected,
    #[error("the VirusTotal request limit was reached")]
    RequestLimitReached,
    #[error("VirusTotal answered with status {status_code}")]
    UnexpectedStatus { status_code: u16 },
    #[error("VirusTotal could not be reached: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("VirusTotal sent an answer ClamUI cannot read")]
    AnswerUnreadable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionCategory {
    Malicious,
    Suspicious,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineDetection {
    pub engine_name: String,
    pub detection_category: DetectionCategory,
    pub detection_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirusTotalReport {
    pub content_hash: String,
    pub detecting_engine_count: u64,
    pub total_engine_count: u64,
    pub engine_detections: Vec<EngineDetection>,
    pub report_url: String,
}

#[derive(Debug)]
pub enum FileReportLookup {
    ReportAvailable(VirusTotalReport),
    FileUnknownToVirusTotal,
}

#[derive(Deserialize)]
struct ApiEnvelope<ApiData> {
    data: ApiData,
}

#[derive(Deserialize)]
struct FileObject {
    attributes: FileAttributes,
}

#[derive(Deserialize)]
struct FileAttributes {
    sha256: String,
    #[serde(default)]
    last_analysis_stats: BTreeMap<String, u64>,
    #[serde(default)]
    last_analysis_results: BTreeMap<String, EngineResult>,
}

#[derive(Deserialize)]
struct EngineResult {
    category: String,
    #[serde(default)]
    result: Option<String>,
}

fn detection_category_named(category_text: &str) -> Option<DetectionCategory> {
    match category_text {
        "malicious" => Some(DetectionCategory::Malicious),
        "suspicious" => Some(DetectionCategory::Suspicious),
        _undetected => None,
    }
}

pub fn parse_file_report(answer_bytes: &[u8]) -> Result<VirusTotalReport, VirusTotalFailure> {
    let file_object = serde_json::from_slice::<ApiEnvelope<FileObject>>(answer_bytes)
        .map_err(|_unreadable_answer| VirusTotalFailure::AnswerUnreadable)?
        .data;
    let statistic = |statistic_name: &str| {
        file_object
            .attributes
            .last_analysis_stats
            .get(statistic_name)
            .copied()
            .unwrap_or(0)
    };
    let detecting_engine_count = statistic("malicious") + statistic("suspicious");
    let total_engine_count = file_object.attributes.last_analysis_stats.values().sum();
    let engine_detections = file_object
        .attributes
        .last_analysis_results
        .iter()
        .filter_map(|engine_entry| {
            Some(EngineDetection {
                engine_name: engine_entry.0.clone(),
                detection_category: detection_category_named(&engine_entry.1.category)?,
                detection_name: engine_entry.1.result.clone().unwrap_or_default(),
            })
        })
        .collect();
    Ok(VirusTotalReport {
        report_url: format!("{REPORT_BASE_URL}/{}", file_object.attributes.sha256),
        content_hash: file_object.attributes.sha256,
        detecting_engine_count,
        total_engine_count,
        engine_detections,
    })
}

fn failure_for_status(status_code: StatusCode) -> VirusTotalFailure {
    match status_code {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => VirusTotalFailure::ApiKeyRejected,
        StatusCode::TOO_MANY_REQUESTS => VirusTotalFailure::RequestLimitReached,
        other_status => VirusTotalFailure::UnexpectedStatus {
            status_code: other_status.as_u16(),
        },
    }
}

#[derive(Clone)]
pub struct VirusTotalClient {
    http_client: reqwest::Client,
    api_key: String,
}

impl VirusTotalClient {
    pub fn with_api_key(api_key: String) -> Result<Self, VirusTotalFailure> {
        Ok(Self {
            http_client: reqwest::Client::builder().no_proxy().build()?,
            api_key,
        })
    }

    async fn get_bytes(&self, request_url: &str) -> Result<reqwest::Response, VirusTotalFailure> {
        Ok(self
            .http_client
            .get(request_url)
            .header("x-apikey", &self.api_key)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await?)
    }

    pub async fn look_up_file_report(
        &self,
        content_hash: &str,
    ) -> Result<FileReportLookup, VirusTotalFailure> {
        let lookup_response = self
            .get_bytes(&format!("{API_BASE_URL}/files/{content_hash}"))
            .await?;
        match lookup_response.status() {
            StatusCode::NOT_FOUND => Ok(FileReportLookup::FileUnknownToVirusTotal),
            status_code if status_code.is_success() => Ok(FileReportLookup::ReportAvailable(
                parse_file_report(&lookup_response.bytes().await?)?,
            )),
            status_code => Err(failure_for_status(status_code)),
        }
    }
}

#[cfg(test)]
mod virustotal_api_client_tests {
    use super::*;

    const REPORT_ANSWER: &[u8] = br#"{
      "data": { "attributes": {
        "sha256": "abc123",
        "last_analysis_stats": {"malicious": 2, "suspicious": 1, "undetected": 60, "harmless": 0},
        "last_analysis_results": {
          "EngineA": {"category": "malicious", "result": "Trojan.X"},
          "EngineB": {"category": "suspicious"},
          "EngineC": {"category": "undetected", "result": null}
        }
      } }
    }"#;

    #[test]
    fn reports_count_detecting_engines_and_keep_only_detections() {
        let file_report = parse_file_report(REPORT_ANSWER).expect("report");
        assert_eq!(file_report.detecting_engine_count, 3);
        assert_eq!(file_report.total_engine_count, 63);
        assert_eq!(file_report.engine_detections.len(), 2);
        assert_eq!(file_report.engine_detections[0].detection_name, "Trojan.X");
        assert_eq!(
            file_report.engine_detections[1].detection_category,
            DetectionCategory::Suspicious
        );
        assert_eq!(
            file_report.report_url,
            "https://www.virustotal.com/gui/file/abc123"
        );
    }

    #[test]
    fn unreadable_answers_are_reported() {
        assert!(matches!(
            parse_file_report(b"{\"data\":{}}"),
            Err(VirusTotalFailure::AnswerUnreadable)
        ));
    }

    #[test]
    fn statuses_map_to_specific_failures() {
        assert!(matches!(
            failure_for_status(StatusCode::UNAUTHORIZED),
            VirusTotalFailure::ApiKeyRejected
        ));
        assert!(matches!(
            failure_for_status(StatusCode::TOO_MANY_REQUESTS),
            VirusTotalFailure::RequestLimitReached
        ));
        assert!(matches!(
            failure_for_status(StatusCode::BAD_GATEWAY),
            VirusTotalFailure::UnexpectedStatus { status_code: 502 }
        ));
    }
}
