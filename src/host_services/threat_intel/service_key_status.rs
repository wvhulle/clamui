use gettextrs::gettext;

use crate::host_services::threat_intel::service_key_storage::{
    KeyStorageFailure, ResolvedApiKey, ThreatIntelService, describe_key_failure, read_api_key,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceKeyStatus {
    KeyConfigured,
    KeyMissing,
    KeyUnreadable { failure_text: String },
}

impl ServiceKeyStatus {
    pub fn from_key_reading(key_reading: &Result<ResolvedApiKey, KeyStorageFailure>) -> Self {
        match key_reading {
            Ok(ResolvedApiKey::FromKeyFile(_) | ResolvedApiKey::FromKeyring(_)) => {
                Self::KeyConfigured
            }
            Ok(ResolvedApiKey::NotConfigured) => Self::KeyMissing,
            Err(key_failure) => Self::KeyUnreadable {
                failure_text: describe_key_failure(key_failure),
            },
        }
    }

    pub fn status_text(&self) -> String {
        match self {
            Self::KeyConfigured => gettext("API key configured"),
            Self::KeyMissing => gettext("No API key, so this service is off"),
            Self::KeyUnreadable { failure_text } => {
                gettext("The API key can't be read: {reason}").replace("{reason}", failure_text)
            }
        }
    }

    pub const fn needs_attention(&self) -> bool {
        match self {
            Self::KeyConfigured | Self::KeyMissing => false,
            Self::KeyUnreadable { .. } => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupKeyStatuses {
    pub abuse_ch_key: ServiceKeyStatus,
    pub virustotal_key: ServiceKeyStatus,
}

pub async fn read_lookup_key_statuses() -> LookupKeyStatuses {
    LookupKeyStatuses {
        abuse_ch_key: ServiceKeyStatus::from_key_reading(
            &read_api_key(ThreatIntelService::AbuseChService).await,
        ),
        virustotal_key: ServiceKeyStatus::from_key_reading(
            &read_api_key(ThreatIntelService::VirusTotalService).await,
        ),
    }
}

#[cfg(test)]
mod service_key_status_tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn key_readings_tell_configured_missing_and_unreadable_apart() {
        let configured_status = ServiceKeyStatus::from_key_reading(&Ok(
            ResolvedApiKey::FromKeyring("0123456789abcdef".to_owned()),
        ));
        assert_eq!(configured_status, ServiceKeyStatus::KeyConfigured);
        assert!(!configured_status.needs_attention());
        let missing_status = ServiceKeyStatus::from_key_reading(&Ok(ResolvedApiKey::NotConfigured));
        assert_eq!(missing_status, ServiceKeyStatus::KeyMissing);
        assert!(!missing_status.needs_attention());
        let unreadable_status =
            ServiceKeyStatus::from_key_reading(&Err(KeyStorageFailure::KeyFilePermissionDenied {
                key_file_path: PathBuf::from("/run/agenix/abuse-ch"),
            }));
        assert!(unreadable_status.needs_attention());
        assert!(
            unreadable_status
                .status_text()
                .starts_with("The API key can't be read: ")
        );
    }
}
