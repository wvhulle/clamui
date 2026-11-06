use std::{fs::File, io, os::unix::fs::OpenOptionsExt, path::Path};

use gettextrs::gettext;
use sha2::{Digest, Sha256};
use zbus::{Connection, proxy};

use crate::host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line;

const ENGINE_HEURISTIC_PREFIXES: [&str; 2] = ["Heuristics.", "Heuristic."];
const UNOFFICIAL_SUFFIX: &str = ".UNOFFICIAL";
const APPLIED_ANSWER: &str = "applied";
const RELOAD_PENDING_ANSWER: &str = "applied-reload-pending";
const SERVICE_UNKNOWN_ERROR: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const ACCESS_DENIED_ERROR: &str = "org.freedesktop.DBus.Error.AccessDenied";

#[proxy(
    interface = "page.codeberg.wvhulle.Lazaret.SettingsHelper",
    default_service = "page.codeberg.wvhulle.Lazaret.SettingsHelper",
    default_path = "/page/codeberg/wvhulle/Lazaret/SettingsHelper"
)]
trait DetectionTrustHelper {
    fn trust_file(&self, sha256_hex: &str, file_size: u64) -> zbus::Result<String>;

    fn ignore_signature(&self, signature_name: &str) -> zbus::Result<String>;

    fn forget_trusted_file(&self, sha256_hex: &str) -> zbus::Result<String>;

    fn stop_ignoring_signature(&self, signature_name: &str) -> zbus::Result<String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileFingerprint {
    pub sha256_hex: String,
    pub file_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustChoice {
    TrustFile {
        file_fingerprint: FileFingerprint,
        shown_path: String,
    },
    IgnoreSignature {
        signature_name: String,
    },
    ForgetTrustedFile {
        sha256_hex: String,
    },
    StopIgnoringSignature {
        signature_name: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustOutcome {
    TrustApplied,
    AppliedReloadPending,
    AuthorizationRefused,
    HelperMissing,
    TrustFailed { failure_text: String },
}

pub fn fingerprint_file(file_path: &Path) -> io::Result<FileFingerprint> {
    let mut opened_file = File::options()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(file_path)?;
    let mut content_hash = Sha256::new();
    let file_size = io::copy(&mut opened_file, &mut content_hash)?;
    Ok(FileFingerprint {
        sha256_hex: hex::encode(content_hash.finalize()),
        file_size,
    })
}

pub fn signature_of_detection(threat_name: &str) -> String {
    threat_name
        .trim()
        .strip_suffix(UNOFFICIAL_SUFFIX)
        .unwrap_or(threat_name.trim())
        .to_owned()
}

pub fn signature_can_be_ignored(threat_name: &str) -> bool {
    let signature_name = signature_of_detection(threat_name);
    !signature_name.is_empty()
        && !ENGINE_HEURISTIC_PREFIXES
            .iter()
            .any(|heuristic_prefix| signature_name.starts_with(heuristic_prefix))
}

fn outcome_of_answer(helper_answer: zbus::Result<String>) -> TrustOutcome {
    match helper_answer {
        Ok(answer_text) if answer_text == APPLIED_ANSWER => TrustOutcome::TrustApplied,
        Ok(answer_text) if answer_text == RELOAD_PENDING_ANSWER => {
            TrustOutcome::AppliedReloadPending
        }
        Ok(other_answer) => TrustOutcome::TrustFailed {
            failure_text: other_answer,
        },
        Err(zbus::Error::MethodError(error_name, _error_text, _reply))
            if error_name.as_str() == SERVICE_UNKNOWN_ERROR =>
        {
            TrustOutcome::HelperMissing
        }
        Err(zbus::Error::MethodError(error_name, _error_text, _reply))
            if error_name.as_str() == ACCESS_DENIED_ERROR =>
        {
            TrustOutcome::AuthorizationRefused
        }
        Err(zbus::Error::MethodError(_error_name, Some(error_text), _reply)) => {
            TrustOutcome::TrustFailed {
                failure_text: error_text,
            }
        }
        Err(call_failure) => TrustOutcome::TrustFailed {
            failure_text: call_failure.to_string(),
        },
    }
}

pub async fn request_trust_change(trust_choice: TrustChoice) -> TrustOutcome {
    let helper_answer = async {
        let trust_helper = DetectionTrustHelperProxy::new(&Connection::system().await?).await?;
        match &trust_choice {
            TrustChoice::TrustFile {
                file_fingerprint, ..
            } => {
                trust_helper
                    .trust_file(&file_fingerprint.sha256_hex, file_fingerprint.file_size)
                    .await
            }
            TrustChoice::IgnoreSignature { signature_name } => {
                trust_helper.ignore_signature(signature_name).await
            }
            TrustChoice::ForgetTrustedFile { sha256_hex } => {
                trust_helper.forget_trusted_file(sha256_hex).await
            }
            TrustChoice::StopIgnoringSignature { signature_name } => {
                trust_helper.stop_ignoring_signature(signature_name).await
            }
        }
    };
    outcome_of_answer(helper_answer.await)
}

pub fn trust_outcome_text(trust_outcome: &TrustOutcome) -> String {
    match trust_outcome {
        TrustOutcome::TrustApplied => gettext("ClamAV loaded the change"),
        TrustOutcome::AppliedReloadPending => gettext(
            "Saved. clamd didn't answer, so it picks up the change when it next reloads its \
             signatures",
        ),
        TrustOutcome::AuthorizationRefused => gettext("Nothing changed without your password"),
        TrustOutcome::HelperMissing => gettext(
            "This installation has no settings helper, so ClamAV's trust list can't be changed \
             from Lazaret",
        ),
        TrustOutcome::TrustFailed { failure_text } => gettext("Nothing changed: {error}")
            .replace("{error}", &sanitize_scanner_line(failure_text)),
    }
}

#[cfg(test)]
mod trust_requests_tests {
    use super::*;

    #[test]
    fn fingerprint_matches_the_known_hash_of_the_content() {
        let fingerprinted_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(fingerprinted_file.path(), b"abc").unwrap();
        assert_eq!(
            fingerprint_file(fingerprinted_file.path()).unwrap(),
            FileFingerprint {
                sha256_hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_owned(),
                file_size: 3,
            }
        );
    }

    #[test]
    fn fingerprinting_never_follows_a_symbolic_link() {
        let link_directory = tempfile::tempdir().unwrap();
        let target_file = link_directory.path().join("target");
        std::fs::write(&target_file, b"abc").unwrap();
        let link_path = link_directory.path().join("link");
        std::os::unix::fs::symlink(&target_file, &link_path).unwrap();
        assert!(fingerprint_file(&link_path).is_err());
    }

    #[test]
    fn heuristics_can_only_be_trusted_by_hash() {
        assert!(!signature_can_be_ignored("Heuristics.Encrypted.Zip"));
        assert!(signature_can_be_ignored("Win.Test.EICAR_HDB-1"));
        assert_eq!(
            signature_of_detection("Sanesecurity.Foo.UNOFFICIAL"),
            "Sanesecurity.Foo"
        );
    }
}
