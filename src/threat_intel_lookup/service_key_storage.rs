use std::collections::HashMap;

const VIRUSTOTAL_KEY_LENGTH: usize = 64;
const ABUSE_CH_MINIMUM_KEY_LENGTH: usize = 16;

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
            Self::VirusTotalService => "ClamUI VirusTotal API key",
            Self::AbuseChService => "ClamUI abuse.ch Auth-Key",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStorageFailure {
    #[error("the system keyring is unavailable: {0}")]
    KeyringUnavailable(Box<oo7::Error>),
    #[error("the stored API key is not valid text")]
    StoredKeyUnreadable,
    #[error("this does not look like a valid API key")]
    KeyFormatInvalid,
}

impl From<oo7::Error> for KeyStorageFailure {
    fn from(keyring_failure: oo7::Error) -> Self {
        Self::KeyringUnavailable(Box::new(keyring_failure))
    }
}

fn key_attributes(threat_intel_service: ThreatIntelService) -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("application", "clamui"),
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
}
