use gettextrs::gettext;
use regex::Regex;

const HIDDEN_ADDRESS_TEXT: &str = "[address hidden]";
pub const NIXOS_URLHAUS_SNIPPET: &str =
    "services.clamav.fangfrisch.urlhaus.authKeyFile = /run/secrets/urlhaus-auth-key;";
pub const NIXOS_SANESECURITY_SNIPPET: &str =
    "services.clamav.fangfrisch.sanesecurity.enable = true;";
pub const NIXOS_INTERSERVER_SNIPPET: &str =
    "services.clamav.fangfrisch.settings.interserver.enabled = \"yes\";";
pub const FANGFRISCH_SANESECURITY_LINES: &str = "[sanesecurity]\nenabled = yes";
pub const FANGFRISCH_INTERSERVER_LINES: &str = "[interserver]\nenabled = yes";
pub const FANGFRISCH_URLHAUS_LINES: &str =
    "[urlhaus]\nenabled = yes\nauth_key = YOUR-ABUSE-CH-AUTH-KEY";

pub const FANGFRISCH_MALWAREPATROL_LINES: &str =
    "[malwarepatrol]\nenabled = yes\nreceipt = YOUR-RECEIPT-NUMBER";
pub const FANGFRISCH_SECURITEINFO_LINES: &str =
    "[securiteinfo]\nenabled = yes\ncustomer_id = YOUR-CUSTOMER-ID";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsOnlyCredential {
    pub credential_label: CredentialLabel,
    pub signup_url: &'static str,
    pub fangfrisch_credential_lines: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialLabel {
    PurchaseReceipt,
    CustomerIdentifier,
}

impl CredentialLabel {
    pub fn described(self) -> String {
        match self {
            Self::PurchaseReceipt => gettext("purchase receipt number"),
            Self::CustomerIdentifier => gettext("customer ID"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnablingSnippets {
    pub nixos_snippet: &'static str,
    pub fangfrisch_lines: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredential {
    NoCredential(EnablingSnippets),
    KeyFileSupported(EnablingSnippets),
    CredentialInSettingsOnly(SettingsOnlyCredential),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThirdPartyProvider {
    AbuseChUrlhaus,
    Sanesecurity,
    InterServer,
    Malwarepatrol,
    SecuriteInfo,
}

impl ThirdPartyProvider {
    pub const fn provider_name(self) -> &'static str {
        match self {
            Self::AbuseChUrlhaus => "abuse.ch URLhaus",
            Self::Sanesecurity => "Sanesecurity",
            Self::InterServer => "InterServer",
            Self::Malwarepatrol => "Malwarepatrol",
            Self::SecuriteInfo => "SecuriteInfo",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureSource {
    ClamavProject,
    ThirdPartySignatures(ThirdPartyProvider),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureFileSource {
    ThirdPartyFile(ThirdPartyProvider),
    UnrecognizedSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProvider {
    pub third_party_provider: ThirdPartyProvider,
    signature_prefixes: &'static [&'static str],
    file_name_markers: &'static [&'static str],
    pub credential: ProviderCredential,
}

pub const SIGNATURE_PROVIDERS: [SignatureProvider; 5] = [
    SignatureProvider {
        third_party_provider: ThirdPartyProvider::AbuseChUrlhaus,
        signature_prefixes: &["URLhaus."],
        file_name_markers: &["urlhaus"],
        credential: ProviderCredential::KeyFileSupported(EnablingSnippets {
            nixos_snippet: NIXOS_URLHAUS_SNIPPET,
            fangfrisch_lines: FANGFRISCH_URLHAUS_LINES,
        }),
    },
    SignatureProvider {
        third_party_provider: ThirdPartyProvider::Sanesecurity,
        signature_prefixes: &["Sanesecurity."],
        file_name_markers: &["sanesecurity", "junk.ndb", "phish.ndb"],
        credential: ProviderCredential::NoCredential(EnablingSnippets {
            nixos_snippet: NIXOS_SANESECURITY_SNIPPET,
            fangfrisch_lines: FANGFRISCH_SANESECURITY_LINES,
        }),
    },
    SignatureProvider {
        third_party_provider: ThirdPartyProvider::InterServer,
        signature_prefixes: &["InterServer", "winnow"],
        file_name_markers: &["interserver", "winnow"],
        credential: ProviderCredential::NoCredential(EnablingSnippets {
            nixos_snippet: NIXOS_INTERSERVER_SNIPPET,
            fangfrisch_lines: FANGFRISCH_INTERSERVER_LINES,
        }),
    },
    SignatureProvider {
        third_party_provider: ThirdPartyProvider::Malwarepatrol,
        signature_prefixes: &["MalwarePatrol", "Malwarepatrol"],
        file_name_markers: &["malwarepatrol", "malware.patrol"],
        credential: ProviderCredential::CredentialInSettingsOnly(SettingsOnlyCredential {
            credential_label: CredentialLabel::PurchaseReceipt,
            signup_url: "https://www.malwarepatrol.net/",
            fangfrisch_credential_lines: FANGFRISCH_MALWAREPATROL_LINES,
        }),
    },
    SignatureProvider {
        third_party_provider: ThirdPartyProvider::SecuriteInfo,
        signature_prefixes: &["SecuriteInfo"],
        file_name_markers: &["securiteinfo"],
        credential: ProviderCredential::CredentialInSettingsOnly(SettingsOnlyCredential {
            credential_label: CredentialLabel::CustomerIdentifier,
            signup_url: "https://www.securiteinfo.com/",
            fangfrisch_credential_lines: FANGFRISCH_SECURITEINFO_LINES,
        }),
    },
];

pub fn provider_of_signature(signature_name: &str) -> SignatureSource {
    SIGNATURE_PROVIDERS
        .iter()
        .find(|signature_provider| {
            signature_provider
                .signature_prefixes
                .iter()
                .any(|signature_prefix| signature_name.starts_with(signature_prefix))
        })
        .map_or(SignatureSource::ClamavProject, |signature_provider| {
            SignatureSource::ThirdPartySignatures(signature_provider.third_party_provider)
        })
}

pub fn provider_of_signature_file(file_name: &str) -> SignatureFileSource {
    let lowercase_name = file_name.to_ascii_lowercase();
    SIGNATURE_PROVIDERS
        .iter()
        .find(|signature_provider| {
            signature_provider
                .file_name_markers
                .iter()
                .any(|file_name_marker| lowercase_name.contains(file_name_marker))
        })
        .map_or(
            SignatureFileSource::UnrecognizedSource,
            |signature_provider| {
                SignatureFileSource::ThirdPartyFile(signature_provider.third_party_provider)
            },
        )
}

pub fn signature_source_name(signature_source: SignatureSource) -> String {
    match signature_source {
        SignatureSource::ClamavProject => "ClamAV".to_owned(),
        SignatureSource::ThirdPartySignatures(third_party_provider) => {
            third_party_provider.provider_name().to_owned()
        }
    }
}

pub fn signature_file_source_name(file_source: SignatureFileSource) -> String {
    match file_source {
        SignatureFileSource::ThirdPartyFile(third_party_provider) => {
            third_party_provider.provider_name().to_owned()
        }
        SignatureFileSource::UnrecognizedSource => gettext("Other source"),
    }
}

pub fn hide_addresses_in_text(log_text: &str) -> String {
    Regex::new(
        r"(?i)[a-z][a-z0-9+.-]*://\S+|\burl\s*[:=]\s*\S+|\b(?:GET|HEAD|POST)\s+/\S+|\S*/files/exports/\S*",
    )
    .map_or_else(
        |_invalid_pattern| HIDDEN_ADDRESS_TEXT.to_owned(),
        |address_pattern| {
            address_pattern
                .replace_all(log_text, HIDDEN_ADDRESS_TEXT)
                .into_owned()
        },
    )
}

#[cfg(test)]
mod signature_provider_catalogue_tests {
    use super::*;

    #[test]
    fn signatures_name_their_source() {
        assert_eq!(
            provider_of_signature("URLhaus.15711"),
            SignatureSource::ThirdPartySignatures(ThirdPartyProvider::AbuseChUrlhaus)
        );
        assert_eq!(
            provider_of_signature("Win.Trojan.Agent-1"),
            SignatureSource::ClamavProject
        );
        assert_eq!(
            signature_source_name(provider_of_signature("Sanesecurity.Foxhole.Zip")),
            "Sanesecurity"
        );
    }

    #[test]
    fn signature_files_name_their_source() {
        assert_eq!(
            provider_of_signature_file("urlhaus_clamav.ndb"),
            SignatureFileSource::ThirdPartyFile(ThirdPartyProvider::AbuseChUrlhaus)
        );
        assert_eq!(
            signature_file_source_name(provider_of_signature_file("custom.ndb")),
            "Other source"
        );
    }

    #[test]
    fn addresses_are_hidden_because_they_can_contain_keys() {
        assert_eq!(
            hide_addresses_in_text(
                "ERROR: https://urlhaus-api.abuse.ch/v2/files/exports/SECRETKEY/urlhaus_clamav.\
                 ndb failed"
            ),
            "ERROR: [address hidden] failed"
        );
        assert_eq!(hide_addresses_in_text("nothing to hide"), "nothing to hide");
    }

    #[test]
    fn addresses_without_a_scheme_are_hidden_too() {
        assert_eq!(
            hide_addresses_in_text(
                "HTTPSConnectionPool(host='urlhaus-api.abuse.ch', port=443): Max retries exceeded \
                 with url: /v2/files/exports/SECRETKEY/urlhaus_clamav.ndb.sha256 (Caused by \
                 NameResolutionError)"
            ),
            "HTTPSConnectionPool(host='urlhaus-api.abuse.ch', port=443): Max retries exceeded \
             with [address hidden] (Caused by NameResolutionError)"
        );
        assert_eq!(
            hide_addresses_in_text("\"GET /v2/SECRETKEY/urlhaus_clamav.ndb HTTP/1.1\" 403"),
            "\"[address hidden] HTTP/1.1\" 403"
        );
        assert_eq!(
            hide_addresses_in_text("fetch /v2/files/exports/SECRETKEY/urlhaus_clamav.ndb done"),
            "fetch [address hidden] done"
        );
    }

    #[test]
    fn traceback_source_lines_stay_readable() {
        let traceback_line = "raise MaxRetryError(_pool, url, reason) from reason";
        assert_eq!(hide_addresses_in_text(traceback_line), traceback_line);
    }
}
