use std::{
    collections::HashMap,
    io::{self, Read},
    path::{Path, PathBuf},
};

use gettextrs::gettext;
use relm4::gtk::gio::prelude::SettingsExt;

use crate::host_services::desktop::stored_settings::application_settings;

const VIRUSTOTAL_KEY_LENGTH: usize = 64;
const ABUSE_CH_MINIMUM_KEY_LENGTH: usize = 16;
const KEY_FILE_SIZE_LIMIT: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreatIntelService {
    VirusTotalService,
    AbuseChService,
}

impl ThreatIntelService {
    const fn keyring_account(self) -> &'static str {
        match self {
            Self::VirusTotalService => "virustotal",
            Self::AbuseChService => "abuse-ch",
        }
    }

    const fn keyring_label(self) -> &'static str {
        match self {
            Self::VirusTotalService => "Lazaret VirusTotal API key",
            Self::AbuseChService => "Lazaret abuse.ch Auth-Key",
        }
    }

    const fn key_file_setting(self) -> &'static str {
        match self {
            Self::VirusTotalService => "virustotal-key-file",
            Self::AbuseChService => "abuse-ch-key-file",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeySource {
    SystemKeyFile { key_file_path: PathBuf },
    UserKeyring,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedApiKey {
    FromKeyFile(String),
    FromKeyring(String),
    NotConfigured,
}

pub fn key_source_for_setting(configured_path: &str) -> KeySource {
    let trimmed_path = configured_path.trim();
    if trimmed_path.is_empty() {
        KeySource::UserKeyring
    } else {
        KeySource::SystemKeyFile {
            key_file_path: PathBuf::from(trimmed_path),
        }
    }
}

pub fn key_source(threat_intel_service: ThreatIntelService) -> KeySource {
    key_source_for_setting(&application_settings().string(threat_intel_service.key_file_setting()))
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStorageFailure {
    #[error("the system keyring is unavailable: {0}")]
    KeyringUnavailable(Box<oo7::Error>),
    #[error("the stored API key is not valid text")]
    StoredKeyUnreadable,
    #[error("this does not look like a valid API key")]
    KeyFormatInvalid,
    #[error("the key file {key_file_path} could not be read: {read_failure}")]
    KeyFileUnreadable {
        key_file_path: PathBuf,
        read_failure: io::Error,
    },
    #[error("the key file {key_file_path} does not hold a valid API key")]
    KeyFileContentInvalid { key_file_path: PathBuf },
}

impl From<oo7::Error> for KeyStorageFailure {
    fn from(keyring_failure: oo7::Error) -> Self {
        Self::KeyringUnavailable(Box::new(keyring_failure))
    }
}

fn key_attributes(threat_intel_service: ThreatIntelService) -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("application", "lazaret"),
        ("account", threat_intel_service.keyring_account()),
    ])
}

pub fn api_key_format_is_valid(
    threat_intel_service: ThreatIntelService,
    candidate_key: &str,
) -> bool {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => {
            candidate_key.len() == VIRUSTOTAL_KEY_LENGTH
                && candidate_key
                    .chars()
                    .all(|key_character| key_character.is_ascii_hexdigit())
        }
        ThreatIntelService::AbuseChService => {
            candidate_key.len() >= ABUSE_CH_MINIMUM_KEY_LENGTH
                && candidate_key
                    .chars()
                    .all(|key_character| key_character.is_ascii_alphanumeric())
        }
    }
}

pub fn masked_api_key(stored_key: &str) -> String {
    let visible_ending = stored_key
        .get(stored_key.len().saturating_sub(4)..)
        .unwrap_or_default();
    format!("••••{visible_ending}")
}

pub fn read_key_file(
    threat_intel_service: ThreatIntelService,
    key_file_path: &Path,
) -> Result<String, KeyStorageFailure> {
    let unreadable = |read_failure: io::Error| KeyStorageFailure::KeyFileUnreadable {
        key_file_path: key_file_path.to_path_buf(),
        read_failure,
    };
    let key_file = std::fs::File::open(key_file_path).map_err(unreadable)?;
    if !key_file.metadata().map_err(unreadable)?.is_file() {
        return Err(unreadable(io::Error::from(io::ErrorKind::InvalidInput)));
    }
    let mut key_text = String::new();
    key_file
        .take(KEY_FILE_SIZE_LIMIT)
        .read_to_string(&mut key_text)
        .map_err(unreadable)?;
    let trimmed_key = key_text.trim();
    if api_key_format_is_valid(threat_intel_service, trimmed_key) {
        Ok(trimmed_key.to_owned())
    } else {
        Err(KeyStorageFailure::KeyFileContentInvalid {
            key_file_path: key_file_path.to_path_buf(),
        })
    }
}

pub async fn read_api_key(
    threat_intel_service: ThreatIntelService,
) -> Result<ResolvedApiKey, KeyStorageFailure> {
    match key_source(threat_intel_service) {
        KeySource::SystemKeyFile { key_file_path } => {
            read_key_file(threat_intel_service, &key_file_path).map(ResolvedApiKey::FromKeyFile)
        }
        KeySource::UserKeyring => Ok(read_stored_api_key(threat_intel_service)
            .await?
            .map_or(ResolvedApiKey::NotConfigured, ResolvedApiKey::FromKeyring)),
    }
}

pub async fn read_stored_api_key(
    threat_intel_service: ThreatIntelService,
) -> Result<Option<String>, KeyStorageFailure> {
    let system_keyring = oo7::Keyring::new().await?;
    let stored_items = system_keyring
        .search_items(&key_attributes(threat_intel_service))
        .await?;
    let Some(stored_item) = stored_items.first() else {
        return Ok(None);
    };
    let stored_secret = stored_item.secret().await?;
    let stored_key = std::str::from_utf8(stored_secret.as_bytes())
        .map_err(|_invalid_text| KeyStorageFailure::StoredKeyUnreadable)?;
    Ok(Some(stored_key.to_owned()))
}

pub async fn save_api_key(
    threat_intel_service: ThreatIntelService,
    entered_key: String,
) -> Result<(), KeyStorageFailure> {
    if !api_key_format_is_valid(threat_intel_service, &entered_key) {
        return Err(KeyStorageFailure::KeyFormatInvalid);
    }
    oo7::Keyring::new()
        .await?
        .create_item(
            threat_intel_service.keyring_label(),
            &key_attributes(threat_intel_service),
            entered_key.as_str(),
            true,
        )
        .await?;
    Ok(())
}

pub async fn delete_stored_api_key(
    threat_intel_service: ThreatIntelService,
) -> Result<(), KeyStorageFailure> {
    oo7::Keyring::new()
        .await?
        .delete(&key_attributes(threat_intel_service))
        .await?;
    Ok(())
}

pub fn describe_key_failure(key_failure: &KeyStorageFailure) -> String {
    match key_failure {
        KeyStorageFailure::KeyFormatInvalid => gettext("This doesn't look like a valid API key"),
        KeyStorageFailure::StoredKeyUnreadable => gettext("Unable to read the stored API key"),
        KeyStorageFailure::KeyringUnavailable(_keyring_failure) => gettext("Keyring unavailable"),
        KeyStorageFailure::KeyFileUnreadable { read_failure, .. } => gettext(
            "Lazaret can't read this file: {error}. If it is an agenix or sops-nix secret, set \
             its owner to your user.",
        )
        .replace("{error}", &read_failure.to_string()),
        KeyStorageFailure::KeyFileContentInvalid { .. } => {
            gettext("The file doesn't hold a valid key for this service")
        }
    }
}

#[cfg(test)]
mod virustotal_key_storage_tests {
    use super::*;

    #[test]
    fn keys_must_be_sixty_four_hexadecimal_characters() {
        let is_valid = |candidate_key: &str| {
            api_key_format_is_valid(ThreatIntelService::VirusTotalService, candidate_key)
        };
        assert!(is_valid(
            &"aF0".repeat(21).chars().chain(['1']).collect::<String>()
        ));
        assert!(!is_valid("abc"));
        assert!(!is_valid(&"g".repeat(64)));
    }

    #[test]
    fn abuse_ch_keys_are_long_and_cannot_inject_into_a_header() {
        let is_valid = |candidate_key: &str| {
            api_key_format_is_valid(ThreatIntelService::AbuseChService, candidate_key)
        };
        assert!(is_valid(&"aB3".repeat(16)));
        assert!(!is_valid("short"));
        assert!(!is_valid(&format!("{}\r\nInjected: yes", "a".repeat(20))));
    }

    #[test]
    fn masking_only_shows_the_ending() {
        assert_eq!(
            masked_api_key(&format!("{}cafe", "0".repeat(60))),
            "••••cafe"
        );
    }

    #[test]
    fn an_empty_key_file_setting_means_the_keyring() {
        assert_eq!(key_source_for_setting("  "), KeySource::UserKeyring);
        assert_eq!(
            key_source_for_setting("/run/agenix/abuse-ch"),
            KeySource::SystemKeyFile {
                key_file_path: PathBuf::from("/run/agenix/abuse-ch")
            }
        );
    }

    #[test]
    fn a_key_file_is_trimmed_and_checked() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let key_file_path = temporary_root.path().join("abuse-ch");
        std::fs::write(&key_file_path, format!("{}\n", "aB3".repeat(16))).expect("written");
        assert_eq!(
            read_key_file(ThreatIntelService::AbuseChService, &key_file_path).expect("read"),
            "aB3".repeat(16)
        );
        std::fs::write(&key_file_path, "short").expect("written");
        assert!(matches!(
            read_key_file(ThreatIntelService::AbuseChService, &key_file_path),
            Err(KeyStorageFailure::KeyFileContentInvalid { .. })
        ));
    }

    #[test]
    fn a_symlinked_secret_is_followed_like_agenix_provides_it() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let secret_path = temporary_root.path().join("generation-secret");
        let link_path = temporary_root.path().join("abuse-ch");
        std::fs::write(&secret_path, "aB3".repeat(16)).expect("written");
        std::os::unix::fs::symlink(&secret_path, &link_path).expect("linked");
        assert!(read_key_file(ThreatIntelService::AbuseChService, &link_path).is_ok());
    }

    #[test]
    fn a_missing_or_directory_key_file_is_unreadable() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        assert!(matches!(
            read_key_file(
                ThreatIntelService::AbuseChService,
                &temporary_root.path().join("missing")
            ),
            Err(KeyStorageFailure::KeyFileUnreadable { .. })
        ));
        assert!(matches!(
            read_key_file(ThreatIntelService::AbuseChService, temporary_root.path()),
            Err(KeyStorageFailure::KeyFileUnreadable { .. })
        ));
    }
}
