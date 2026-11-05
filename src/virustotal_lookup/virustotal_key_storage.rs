use std::collections::HashMap;

const KEY_LABEL: &str = "ClamUI VirusTotal API key";
const API_KEY_LENGTH: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum KeyStorageFailure {
    #[error("the system keyring is unavailable: {0}")]
    KeyringUnavailable(Box<oo7::Error>),
    #[error("the stored API key is not valid text")]
    StoredKeyUnreadable,
    #[error("VirusTotal API keys must be exactly 64 hexadecimal characters")]
    KeyFormatInvalid,
}

impl From<oo7::Error> for KeyStorageFailure {
    fn from(keyring_failure: oo7::Error) -> Self {
        Self::KeyringUnavailable(Box::new(keyring_failure))
    }
}

fn key_attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([("application", "clamui"), ("account", "virustotal")])
}

pub fn api_key_format_is_valid(candidate_key: &str) -> bool {
    candidate_key.len() == API_KEY_LENGTH
        && candidate_key
            .chars()
            .all(|key_character| key_character.is_ascii_hexdigit())
}

pub fn masked_api_key(stored_key: &str) -> String {
    let visible_ending = stored_key
        .get(stored_key.len().saturating_sub(4)..)
        .unwrap_or_default();
    format!("••••{visible_ending}")
}

pub async fn read_stored_api_key() -> Result<Option<String>, KeyStorageFailure> {
    let system_keyring = oo7::Keyring::new().await?;
    let stored_items = system_keyring.search_items(&key_attributes()).await?;
    let Some(stored_item) = stored_items.first() else {
        return Ok(None);
    };
    let stored_secret = stored_item.secret().await?;
    let stored_key = std::str::from_utf8(stored_secret.as_bytes())
        .map_err(|_invalid_text| KeyStorageFailure::StoredKeyUnreadable)?;
    Ok(Some(stored_key.to_owned()))
}

pub async fn save_api_key(entered_key: String) -> Result<(), KeyStorageFailure> {
    if !api_key_format_is_valid(&entered_key) {
        return Err(KeyStorageFailure::KeyFormatInvalid);
    }
    oo7::Keyring::new()
        .await?
        .create_item(KEY_LABEL, &key_attributes(), entered_key.as_str(), true)
        .await?;
    Ok(())
}

pub async fn delete_stored_api_key() -> Result<(), KeyStorageFailure> {
    oo7::Keyring::new().await?.delete(&key_attributes()).await?;
    Ok(())
}

#[cfg(test)]
mod virustotal_key_storage_tests {
    use super::*;

    #[test]
    fn keys_must_be_sixty_four_hexadecimal_characters() {
        assert!(api_key_format_is_valid(
            &"aF0".repeat(21).chars().chain(['1']).collect::<String>()
        ));
        assert!(!api_key_format_is_valid("abc"));
        assert!(!api_key_format_is_valid(&"g".repeat(64)));
    }

    #[test]
    fn masking_only_shows_the_ending() {
        assert_eq!(
            masked_api_key(&format!("{}cafe", "0".repeat(60))),
            "••••cafe"
        );
    }
}
