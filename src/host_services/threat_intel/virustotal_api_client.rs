use std::{collections::BTreeMap, time::Duration};

use bytesize::ByteSize;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::host_services::threat_intel::malware_bazaar_client::percent_encoded_form_value;

const API_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const REPORT_BASE_URL: &str = "https://www.virustotal.com/gui/file";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";
pub const MAXIMUM_DIRECT_UPLOAD_SIZE: ByteSize = ByteSize::mb(32);

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
    #[error("VirusTotal sent an answer Lazaret cannot read")]
    AnswerUnreadable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionCategory {
    Malicious,
    Suspicious,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineVerdictName {
    NamedDetection(String),
    UnnamedDetection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineDetection {
    pub engine_name: String,
    pub detection_category: DetectionCategory,
    pub detection_name: EngineVerdictName,
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
            .ok_or(VirusTotalFailure::AnswerUnreadable)
    };
    let detecting_engine_count = statistic("malicious")? + statistic("suspicious")?;
    let total_engine_count = file_object.attributes.last_analysis_stats.values().sum();
    let engine_detections = file_object
        .attributes
        .last_analysis_results
        .iter()
        .filter_map(|(engine_name, engine_result)| {
            Some(EngineDetection {
                engine_name: engine_name.clone(),
                detection_category: detection_category_named(&engine_result.category)?,
                detection_name: engine_result
                    .result
                    .clone()
                    .filter(|detection_name| !detection_name.is_empty())
                    .map_or(
                        EngineVerdictName::UnnamedDetection,
                        EngineVerdictName::NamedDetection,
                    ),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VirusTotalUploadAnswer {
    AnalysisQueued { analysis_id: String },
    UploadRefused { error_code: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisProgress {
    AnalysisPending,
    AnalysisCompleted {
        malicious_count: u64,
        engine_count: u64,
    },
}

#[derive(Deserialize)]
struct AnalysisReference {
    id: String,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorObject,
}

#[derive(Deserialize)]
struct ErrorObject {
    code: String,
}

#[derive(Deserialize)]
struct AnalysisObject {
    attributes: AnalysisAttributes,
}

#[derive(Deserialize)]
struct AnalysisAttributes {
    status: String,
    stats: BTreeMap<String, u64>,
}

const VERDICT_STATISTICS: [&str; 4] = ["malicious", "suspicious", "undetected", "harmless"];

pub fn parse_upload_answer(
    answer_bytes: &[u8],
) -> Result<VirusTotalUploadAnswer, VirusTotalFailure> {
    let analysis_reference = serde_json::from_slice::<ApiEnvelope<AnalysisReference>>(answer_bytes)
        .map_err(|_unreadable_answer| VirusTotalFailure::AnswerUnreadable)?
        .data;
    if analysis_reference.id.trim().is_empty() {
        return Err(VirusTotalFailure::AnswerUnreadable);
    }
    Ok(VirusTotalUploadAnswer::AnalysisQueued {
        analysis_id: analysis_reference.id,
    })
}

pub fn parse_refusal_answer(answer_bytes: &[u8]) -> VirusTotalUploadAnswer {
    VirusTotalUploadAnswer::UploadRefused {
        error_code: serde_json::from_slice::<ErrorEnvelope>(answer_bytes).map_or_else(
            |_unreadable_error| "BadRequestError".to_owned(),
            |error_envelope| error_envelope.error.code,
        ),
    }
}

pub fn parse_analysis_answer(answer_bytes: &[u8]) -> Result<AnalysisProgress, VirusTotalFailure> {
    let analysis_attributes = serde_json::from_slice::<ApiEnvelope<AnalysisObject>>(answer_bytes)
        .map_err(|_unreadable_answer| VirusTotalFailure::AnswerUnreadable)?
        .data
        .attributes;
    match analysis_attributes.status.as_str() {
        "queued" | "in-progress" => Ok(AnalysisProgress::AnalysisPending),
        "completed" => {
            let statistic = |statistic_name: &str| {
                analysis_attributes
                    .stats
                    .get(statistic_name)
                    .copied()
                    .ok_or(VirusTotalFailure::AnswerUnreadable)
            };
            Ok(AnalysisProgress::AnalysisCompleted {
                malicious_count: statistic("malicious")?,
                engine_count: VERDICT_STATISTICS
                    .iter()
                    .map(|statistic_name| statistic(statistic_name))
                    .sum::<Result<u64, VirusTotalFailure>>()?,
            })
        }
        _unknown_status => Err(VirusTotalFailure::AnswerUnreadable),
    }
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
    api_base_url: String,
}

impl VirusTotalClient {
    pub fn with_api_key(api_key: String) -> Result<Self, VirusTotalFailure> {
        Self::at_base_url(api_key, API_BASE_URL.to_owned())
    }

    fn at_base_url(api_key: String, api_base_url: String) -> Result<Self, VirusTotalFailure> {
        Ok(Self {
            http_client: reqwest::Client::builder().no_proxy().build()?,
            api_key,
            api_base_url,
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
            .get_bytes(&format!("{}/files/{content_hash}", self.api_base_url))
            .await?;
        match lookup_response.status() {
            StatusCode::NOT_FOUND => Ok(FileReportLookup::FileUnknownToVirusTotal),
            status_code if status_code.is_success() => Ok(FileReportLookup::ReportAvailable(
                parse_file_report(&lookup_response.bytes().await?)?,
            )),
            status_code => Err(failure_for_status(status_code)),
        }
    }

    pub async fn upload_file(
        &self,
        upload_name: String,
        sample_bytes: Vec<u8>,
    ) -> Result<VirusTotalUploadAnswer, VirusTotalFailure> {
        let upload_form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(sample_bytes)
                .file_name(upload_name)
                .mime_str(UPLOAD_CONTENT_TYPE)?,
        );
        let upload_response = self
            .http_client
            .post(format!("{}/files", self.api_base_url))
            .header("x-apikey", &self.api_key)
            .multipart(upload_form)
            .timeout(UPLOAD_TIMEOUT)
            .send()
            .await?;
        match upload_response.status() {
            status_code if status_code.is_success() => {
                parse_upload_answer(&upload_response.bytes().await?)
            }
            StatusCode::BAD_REQUEST => Ok(parse_refusal_answer(&upload_response.bytes().await?)),
            status_code => Err(failure_for_status(status_code)),
        }
    }

    pub async fn fetch_analysis(
        &self,
        analysis_id: &str,
    ) -> Result<AnalysisProgress, VirusTotalFailure> {
        let analysis_response = self
            .get_bytes(&format!(
                "{}/analyses/{}",
                self.api_base_url,
                percent_encoded_form_value(analysis_id)
            ))
            .await?;
        match analysis_response.status() {
            status_code if status_code.is_success() => {
                parse_analysis_answer(&analysis_response.bytes().await?)
            }
            status_code => Err(failure_for_status(status_code)),
        }
    }
}

#[cfg(test)]
mod virustotal_api_client_tests {
    use super::*;
    use crate::host_services::threat_intel::recorded_answer_stub::serve_recorded_answer;

    const UPLOAD_ANSWER: &[u8] = br#"{
      "data": {
        "type": "analysis",
        "id": "OTFiMDcwMjVjZDIzZTI0NGU4ZDlmMjI2NjkzZDczNGE6MTY1MzY1NDM3Nw=="
      }
    }"#;
    const REFUSED_UPLOAD_ANSWER: &[u8] = br#"{
      "error": {"code": "BadRequestError", "message": "The file is corrupt"}
    }"#;
    const WRONG_KEY_ANSWER: &[u8] = br#"{
      "error": {"code": "WrongCredentialsError", "message": "Wrong API key"}
    }"#;
    const QUEUED_ANALYSIS_ANSWER: &[u8] = br#"{
      "data": {"type": "analysis", "id": "abc", "attributes": {
        "status": "queued", "date": 1793869222, "stats": {}, "results": {}
      }}
    }"#;
    const COMPLETED_ANALYSIS_ANSWER: &[u8] = br#"{
      "data": {"type": "analysis", "id": "abc", "attributes": {
        "status": "completed", "date": 1793869222,
        "stats": {"confirmed-timeout": 0, "failure": 1, "harmless": 0, "malicious": 41,
                  "suspicious": 2, "timeout": 0, "type-unsupported": 4, "undetected": 25},
        "results": {}
      }},
      "meta": {"file_info": {"sha256": "ab12"}}
    }"#;

    fn stub_client(endpoint_url: &str) -> VirusTotalClient {
        VirusTotalClient::at_base_url(
            "fixture-key".to_owned(),
            endpoint_url.trim_end_matches('/').to_owned(),
        )
        .expect("client")
    }

    #[test]
    fn analyses_report_their_progress_and_verdict_counts() {
        assert_eq!(
            parse_analysis_answer(QUEUED_ANALYSIS_ANSWER).expect("queued"),
            AnalysisProgress::AnalysisPending
        );
        assert_eq!(
            parse_analysis_answer(COMPLETED_ANALYSIS_ANSWER).expect("completed"),
            AnalysisProgress::AnalysisCompleted {
                malicious_count: 41,
                engine_count: 68,
            }
        );
        assert!(matches!(
            parse_analysis_answer(br#"{"data":{"attributes":{"status":"completed","stats":{}}}}"#),
            Err(VirusTotalFailure::AnswerUnreadable)
        ));
    }

    #[tokio::test]
    async fn an_upload_posts_the_file_with_the_key_and_returns_the_analysis() {
        let answer_stub = serve_recorded_answer("200 OK", UPLOAD_ANSWER);
        let upload_answer = stub_client(&answer_stub.endpoint_url)
            .upload_file("ab12".to_owned(), b"sample bytes".to_vec())
            .await
            .expect("uploaded");
        assert_eq!(
            upload_answer,
            VirusTotalUploadAnswer::AnalysisQueued {
                analysis_id: "OTFiMDcwMjVjZDIzZTI0NGU4ZDlmMjI2NjkzZDczNGE6MTY1MzY1NDM3Nw=="
                    .to_owned()
            }
        );
        let captured_request = answer_stub.captured_request();
        assert!(captured_request.starts_with("POST /files HTTP/1.1"));
        assert!(
            captured_request
                .to_ascii_lowercase()
                .contains("x-apikey: fixture-key")
        );
        assert!(captured_request.contains("name=\"file\"; filename=\"ab12\""));
        assert!(captured_request.contains("sample bytes"));
    }

    #[tokio::test]
    async fn a_refused_upload_and_a_wrong_key_are_told_apart() {
        let refused_stub = serve_recorded_answer("400 Bad Request", REFUSED_UPLOAD_ANSWER);
        assert_eq!(
            stub_client(&refused_stub.endpoint_url)
                .upload_file("ab12".to_owned(), b"sample".to_vec())
                .await
                .expect("refused answer"),
            VirusTotalUploadAnswer::UploadRefused {
                error_code: "BadRequestError".to_owned()
            }
        );
        drop(refused_stub.captured_request());
        let wrong_key_stub = serve_recorded_answer("401 Unauthorized", WRONG_KEY_ANSWER);
        assert!(matches!(
            stub_client(&wrong_key_stub.endpoint_url)
                .upload_file("ab12".to_owned(), b"sample".to_vec())
                .await,
            Err(VirusTotalFailure::ApiKeyRejected)
        ));
        drop(wrong_key_stub.captured_request());
    }

    #[tokio::test]
    async fn an_analysis_is_fetched_by_its_encoded_identifier() {
        let answer_stub = serve_recorded_answer("200 OK", COMPLETED_ANALYSIS_ANSWER);
        assert_eq!(
            stub_client(&answer_stub.endpoint_url)
                .fetch_analysis("YWJj/ZGVm==")
                .await
                .expect("analysis"),
            AnalysisProgress::AnalysisCompleted {
                malicious_count: 41,
                engine_count: 68,
            }
        );
        assert!(
            answer_stub
                .captured_request()
                .starts_with("GET /analyses/YWJj%2FZGVm%3D%3D HTTP/1.1")
        );
    }

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
        assert_eq!(
            file_report.engine_detections[0].detection_name,
            EngineVerdictName::NamedDetection("Trojan.X".to_owned())
        );
        assert_eq!(
            file_report.engine_detections[1].detection_name,
            EngineVerdictName::UnnamedDetection
        );
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
    fn missing_detection_counts_are_unreadable_rather_than_clean() {
        [
            br#"{"data":{"attributes":{"sha256":"abc123"}}}"#.as_slice(),
            br#"{"data":{"attributes":{"sha256":"abc123","last_analysis_stats":{"undetected":60}}}}"#
                .as_slice(),
        ]
        .into_iter()
        .for_each(|answer_bytes| {
            assert!(matches!(
                parse_file_report(answer_bytes),
                Err(VirusTotalFailure::AnswerUnreadable)
            ));
        });
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
