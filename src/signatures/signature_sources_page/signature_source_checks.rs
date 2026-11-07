use std::{io, path::Path};

use gettextrs::gettext;
use tokio::task::spawn_blocking;

use crate::{
    host_services::clamav_programs::{
        database_directory_status::{DatabaseFolderReadFailure, configured_database_directory},
        distribution_install_guides::DistributionFamily,
        signature_provider_catalogue::{
            ProviderCredential, SIGNATURE_PROVIDERS, SettingsOnlyCredential, SignatureFileSource,
            SignatureProvider, provider_of_signature_file,
        },
    },
    shared_widgets::{
        audit_sections::audit_check_results::{AuditCheck, AuditStatus},
        host_read_failure_text::database_folder_failure_text,
    },
};

const FANGFRISCH_CONFIG_PATH: &str = "/etc/fangfrisch/fangfrisch.conf";
const FANGFRISCH_CONFIG_PROTECTION_COMMAND: &str = "sudo chmod 600 /etc/fangfrisch/fangfrisch.conf";

fn settings_credential_check(
    inactive_check: AuditCheck,
    provider_name: &str,
    settings_credential: SettingsOnlyCredential,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let credential_text = settings_credential.credential_label.described();
    if distribution_family == DistributionFamily::NixosFamily {
        return inactive_check
            .with_recommendation(
                gettext(
                    "{provider} needs a {credential}, and fangfrisch only reads it from its \
                     settings. On NixOS, services.clamav.fangfrisch.settings is copied into the \
                     Nix store, which every user of this computer can read, so the {credential} \
                     would be exposed. Leave {provider} off, or run fangfrisch with a settings \
                     file kept outside the Nix store, such as an agenix or sops-nix secret.",
                )
                .replace("{credential}", &credential_text)
                .replace("{provider}", provider_name),
            )
            .with_documentation(settings_credential.signup_url);
    }
    inactive_check
        .with_recommendation(
            gettext(
                "{provider} needs a {credential} from its website. fangfrisch reads it from its \
                 settings file, usually {path}. Add these lines there, replace the placeholder \
                 with your {credential}, and make the file readable by root only, so other users \
                 can't see it.",
            )
            .replace("{path}", FANGFRISCH_CONFIG_PATH)
            .replace("{credential}", &credential_text)
            .replace("{provider}", provider_name),
        )
        .with_suggested_commands([
            settings_credential.fangfrisch_credential_lines,
            FANGFRISCH_CONFIG_PROTECTION_COMMAND,
        ])
        .with_documentation(settings_credential.signup_url)
}

fn inactive_provider_check(
    signature_provider: &SignatureProvider,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let provider_name = signature_provider.third_party_provider.provider_name();
    let inactive_check = AuditCheck::new(
        provider_name.to_owned(),
        AuditStatus::CheckSkipped,
        gettext("Not in use"),
    )
    .starting_collapsed();
    match signature_provider.credential {
        ProviderCredential::CredentialInSettingsOnly(settings_credential) => {
            settings_credential_check(
                inactive_check,
                provider_name,
                settings_credential,
                distribution_family,
            )
        }
        ProviderCredential::KeyFileSupported(enabling_snippets)
        | ProviderCredential::NoCredential(enabling_snippets)
            if distribution_family == DistributionFamily::NixosFamily =>
        {
            inactive_check.with_suggested_commands([enabling_snippets.nixos_snippet])
        }
        ProviderCredential::NoCredential(enabling_snippets) => inactive_check
            .with_recommendation(
                gettext("Add these lines to fangfrisch's settings file, usually {path}.")
                    .replace("{path}", FANGFRISCH_CONFIG_PATH),
            )
            .with_suggested_commands([enabling_snippets.fangfrisch_lines]),
        ProviderCredential::KeyFileSupported(enabling_snippets) => inactive_check
            .with_recommendation(
                gettext(
                    "{provider} needs a free abuse.ch Auth-Key. Add these lines to fangfrisch's \
                     settings file, usually {path}, replace the placeholder with your key, and \
                     make the file readable by root only, so other users can't see it.",
                )
                .replace("{path}", FANGFRISCH_CONFIG_PATH)
                .replace("{provider}", provider_name),
            )
            .with_suggested_commands([
                enabling_snippets.fangfrisch_lines,
                FANGFRISCH_CONFIG_PROTECTION_COMMAND,
            ])
            .with_documentation("https://auth.abuse.ch/"),
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
                provider_of_signature_file(file_name)
                    == SignatureFileSource::ThirdPartyFile(signature_provider.third_party_provider)
            });
            if provider_in_use {
                AuditCheck::new(
                    signature_provider
                        .third_party_provider
                        .provider_name()
                        .to_owned(),
                    AuditStatus::CheckPassed,
                    gettext("In use"),
                )
            } else {
                inactive_provider_check(signature_provider, distribution_family)
            }
        })
        .collect()
}

pub fn unreadable_source_checks(read_failure: DatabaseFolderReadFailure) -> Vec<AuditCheck> {
    SIGNATURE_PROVIDERS
        .iter()
        .map(|signature_provider| {
            AuditCheck::new(
                signature_provider
                    .third_party_provider
                    .provider_name()
                    .to_owned(),
                AuditStatus::StatusUnknown,
                gettext("Unknown. {reason}")
                    .replace("{reason}", &database_folder_failure_text(read_failure)),
            )
        })
        .collect()
}

fn signature_file_names(
    database_directory: &Path,
) -> Result<Vec<String>, DatabaseFolderReadFailure> {
    match std::fs::read_dir(database_directory) {
        Ok(directory_entries) => Ok(directory_entries
            .filter_map(Result::ok)
            .map(|directory_entry| directory_entry.file_name().to_string_lossy().into_owned())
            .collect()),
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(read_failure) => Err(read_failure.into()),
    }
}

pub async fn gather_signature_source_checks(
    distribution_family: DistributionFamily,
) -> Vec<AuditCheck> {
    match spawn_blocking(|| signature_file_names(&configured_database_directory()))
        .await
        .map_err(DatabaseFolderReadFailure::from)
        .flatten()
    {
        Ok(signature_files) => signature_source_checks(&signature_files, distribution_family),
        Err(read_failure) => unreadable_source_checks(read_failure),
    }
}

#[cfg(test)]
mod signature_source_checks_tests {
    use super::*;
    use crate::{
        host_services::clamav_programs::signature_provider_catalogue::{
            EnablingSnippets, FANGFRISCH_SANESECURITY_LINES, FANGFRISCH_SECURITEINFO_LINES,
            NIXOS_SANESECURITY_SNIPPET, ThirdPartyProvider,
        },
        shared_widgets::audit_sections::audit_check_results::CheckGuidance,
    };

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
    fn an_unreadable_signature_folder_leaves_every_source_unknown() {
        let source_checks =
            unreadable_source_checks(DatabaseFolderReadFailure::ReadingTaskInterrupted);
        assert_eq!(source_checks.len(), SIGNATURE_PROVIDERS.len());
        source_checks.iter().for_each(|source_check| {
            assert_eq!(source_check.check_status, AuditStatus::StatusUnknown);
            assert!(source_check.status_detail.starts_with("Unknown."));
        });
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
            matches!(check_guidance, CheckGuidance::RecommendationText(warning_text) if warning_text.contains("Nix store") && warning_text.contains("purchase receipt number"))
        }));
    }

    #[test]
    fn other_systems_get_placeholder_lines_and_a_permission_command() {
        let source_checks = signature_source_checks(&[], DistributionFamily::DebianFamily);
        let securiteinfo_check = source_checks
            .iter()
            .find(|source_check| source_check.check_name == "SecuriteInfo")
            .expect("catalogue entry");
        assert_eq!(
            commands_of(securiteinfo_check),
            vec![
                FANGFRISCH_SECURITEINFO_LINES,
                FANGFRISCH_CONFIG_PROTECTION_COMMAND
            ]
        );
        assert!(securiteinfo_check.check_guidance.iter().all(|check_guidance| {
            !matches!(check_guidance, CheckGuidance::RecommendationText(advice_text) if advice_text.contains("NixOS"))
        }));
    }

    #[test]
    fn providers_without_a_settings_credential_carry_their_snippets() {
        let sanesecurity_provider = SIGNATURE_PROVIDERS
            .iter()
            .find(|signature_provider| {
                signature_provider.third_party_provider == ThirdPartyProvider::Sanesecurity
            })
            .expect("catalogue entry");
        assert_eq!(
            sanesecurity_provider.credential,
            ProviderCredential::NoCredential(EnablingSnippets {
                nixos_snippet: NIXOS_SANESECURITY_SNIPPET,
                fangfrisch_lines: FANGFRISCH_SANESECURITY_LINES,
            })
        );
        let nixos_checks = signature_source_checks(&[], DistributionFamily::NixosFamily);
        let sanesecurity_check = nixos_checks
            .iter()
            .find(|source_check| source_check.check_name == "Sanesecurity")
            .expect("catalogue entry");
        assert_eq!(
            commands_of(sanesecurity_check),
            vec![NIXOS_SANESECURITY_SNIPPET]
        );
    }

    #[test]
    fn every_suggested_snippet_is_filled_in() {
        [
            DistributionFamily::NixosFamily,
            DistributionFamily::DebianFamily,
        ]
        .into_iter()
        .flat_map(|distribution_family| signature_source_checks(&[], distribution_family))
        .for_each(|source_check| {
            commands_of(&source_check)
                .into_iter()
                .for_each(|suggested_command| assert!(!suggested_command.is_empty()));
        });
    }
}
