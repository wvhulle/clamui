use gettextrs::gettext;
use regex::Regex;

use crate::{
    clamav_components::distribution_install_guides::DistributionFamily,
    system_audit::audit_report_model::{AuditCheck, AuditStatus},
};

const HIDDEN_ADDRESS_TEXT: &str = "[address hidden]";
const NIXOS_URLHAUS_SNIPPET: &str =
    "services.clamav.fangfrisch.urlhaus.authKeyFile = /run/secrets/urlhaus-auth-key;";
const NIXOS_SANESECURITY_SNIPPET: &str = "services.clamav.fangfrisch.sanesecurity.enable = true;";
const NIXOS_INTERSERVER_SNIPPET: &str =
    "services.clamav.fangfrisch.settings.interserver.enabled = \"yes\";";
const FANGFRISCH_SANESECURITY_LINES: &str = "[sanesecurity]\nenabled = yes";
const FANGFRISCH_INTERSERVER_LINES: &str = "[interserver]\nenabled = yes";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredential {
    NoCredential,
    KeyFileSupported,
    CredentialInSettingsOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProvider {
    pub provider_name: &'static str,
    signature_prefixes: &'static [&'static str],
    file_name_markers: &'static [&'static str],
    credential: ProviderCredential,
    nixos_snippet: &'static str,
    fangfrisch_lines: &'static str,
}

pub const SIGNATURE_PROVIDERS: [SignatureProvider; 5] = [
    SignatureProvider {
        provider_name: "abuse.ch URLhaus",
        signature_prefixes: &["URLhaus."],
        file_name_markers: &["urlhaus"],
        credential: ProviderCredential::KeyFileSupported,
        nixos_snippet: NIXOS_URLHAUS_SNIPPET,
        fangfrisch_lines: "",
    },
    SignatureProvider {
        provider_name: "Sanesecurity",
        signature_prefixes: &["Sanesecurity."],
        file_name_markers: &["sanesecurity", "junk.ndb", "phish.ndb"],
        credential: ProviderCredential::NoCredential,
        nixos_snippet: NIXOS_SANESECURITY_SNIPPET,
        fangfrisch_lines: FANGFRISCH_SANESECURITY_LINES,
    },
    SignatureProvider {
        provider_name: "InterServer",
        signature_prefixes: &["InterServer", "winnow"],
        file_name_markers: &["interserver", "winnow"],
        credential: ProviderCredential::NoCredential,
        nixos_snippet: NIXOS_INTERSERVER_SNIPPET,
        fangfrisch_lines: FANGFRISCH_INTERSERVER_LINES,
    },
    SignatureProvider {
        provider_name: "Malwarepatrol",
        signature_prefixes: &["MalwarePatrol", "Malwarepatrol"],
        file_name_markers: &["malwarepatrol", "malware.patrol"],
        credential: ProviderCredential::CredentialInSettingsOnly,
        nixos_snippet: "",
        fangfrisch_lines: "",
    },
    SignatureProvider {
        provider_name: "SecuriteInfo",
        signature_prefixes: &["SecuriteInfo"],
        file_name_markers: &["securiteinfo"],
        credential: ProviderCredential::CredentialInSettingsOnly,
        nixos_snippet: "",
        fangfrisch_lines: "",
    },
];

pub fn provider_of_signature(signature_name: &str) -> &'static str {
    SIGNATURE_PROVIDERS
        .iter()
        .find(|signature_provider| {
            signature_provider
                .signature_prefixes
                .iter()
                .any(|signature_prefix| signature_name.starts_with(signature_prefix))
        })
        .map_or("ClamAV", |signature_provider| {
            signature_provider.provider_name
        })
}

pub fn provider_of_signature_file(file_name: &str) -> &'static str {
    let lowercase_name = file_name.to_ascii_lowercase();
    SIGNATURE_PROVIDERS
        .iter()
        .find(|signature_provider| {
            signature_provider
                .file_name_markers
                .iter()
                .any(|file_name_marker| lowercase_name.contains(file_name_marker))
        })
        .map_or("Other source", |signature_provider| {
            signature_provider.provider_name
        })
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

fn inactive_provider_check(
    signature_provider: &SignatureProvider,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let inactive_check = AuditCheck::new(
        signature_provider.provider_name.to_owned(),
        AuditStatus::CheckSkipped,
        gettext("Not in use"),
    )
    .starting_collapsed();
    match signature_provider.credential {
        ProviderCredential::CredentialInSettingsOnly => {
            inactive_check.with_recommendation(gettext(
                "This source needs a credential, and fangfrisch reads it from its settings. On \
                 NixOS those settings end up in the world-readable Nix store, so don't put the \
                 credential there.",
            ))
        }
        ProviderCredential::KeyFileSupported | ProviderCredential::NoCredential => {
            let enabling_lines = if distribution_family == DistributionFamily::NixosFamily
                || signature_provider.fangfrisch_lines.is_empty()
            {
                signature_provider.nixos_snippet
            } else {
                signature_provider.fangfrisch_lines
            };
            inactive_check.with_suggested_commands([enabling_lines])
        }
    }
}

pub fn signature_source_checks(
    signature_file_names: &[String],
    distribution_family: DistributionFamily,
) -> Vec<AuditCheck> {
    SIGNATURE_PROVIDERS
        .iter()
        .map(|signature_provider| {
            let provider_in_use = signature_file_names.iter().any(|file_name| {
                provider_of_signature_file(file_name) == signature_provider.provider_name
            });
            if provider_in_use {
                AuditCheck::new(
                    signature_provider.provider_name.to_owned(),
                    AuditStatus::CheckPassed,
                    gettext("In use"),
                )
            } else {
                inactive_provider_check(signature_provider, distribution_family)
            }
        })
        .collect()
}

#[cfg(test)]
mod signature_provider_catalogue_tests {
    use super::*;
    use crate::system_audit::audit_report_model::CheckGuidance;

    fn commands_of(audit_check: &AuditCheck) -> Vec<&'static str> {
        audit_check
            .check_guidance
            .iter()
            .filter_map(|check_guidance| match check_guidance {
                CheckGuidance::SuggestedCommand(suggested_command) => Some(*suggested_command),
                CheckGuidance::RecommendationText(_) | CheckGuidance::DocumentationLink(_) => None,
            })
            .collect()
    }

    #[test]
    fn signatures_name_their_source() {
        assert_eq!(provider_of_signature("URLhaus.15711"), "abuse.ch URLhaus");
        assert_eq!(provider_of_signature("Win.Trojan.Agent-1"), "ClamAV");
        assert_eq!(
            provider_of_signature("Sanesecurity.Foxhole.Zip"),
            "Sanesecurity"
        );
    }

    #[test]
    fn signature_files_name_their_source() {
        assert_eq!(
            provider_of_signature_file("urlhaus_clamav.ndb"),
            "abuse.ch URLhaus"
        );
        assert_eq!(provider_of_signature_file("custom.ndb"), "Other source");
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

    #[test]
    fn sources_in_use_are_recognized_and_offer_no_snippet() {
        let source_checks = signature_source_checks(
            &["urlhaus_clamav.ndb".to_owned()],
            DistributionFamily::NixosFamily,
        );
        assert_eq!(source_checks[0].check_status, AuditStatus::CheckPassed);
        assert!(commands_of(&source_checks[0]).is_empty());
        assert_eq!(source_checks[1].check_status, AuditStatus::CheckSkipped);
    }

    #[test]
    fn no_snippet_ever_contains_a_credential() {
        signature_source_checks(&[], DistributionFamily::NixosFamily)
            .iter()
            .flat_map(commands_of)
            .for_each(|enabling_snippet| {
                ["auth_key", "receipt", "customer_id"]
                    .into_iter()
                    .for_each(|credential_setting| {
                        assert!(
                            !enabling_snippet.contains(credential_setting),
                            "{enabling_snippet}"
                        );
                    });
            });
    }

    #[test]
    fn sources_needing_a_store_visible_credential_warn_instead_of_suggesting() {
        let source_checks = signature_source_checks(&[], DistributionFamily::NixosFamily);
        let malwarepatrol_check = source_checks
            .iter()
            .find(|source_check| source_check.check_name == "Malwarepatrol")
            .expect("catalogue entry");
        assert!(commands_of(malwarepatrol_check).is_empty());
        assert!(malwarepatrol_check.check_guidance.iter().any(|check_guidance| {
            matches!(check_guidance, CheckGuidance::RecommendationText(warning_text) if warning_text.contains("world-readable"))
        }));
    }
}
